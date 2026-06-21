"""Unit tests for nvd_mcp.server — tool functions and helpers."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nvd_mcp.models import NvdCve, SeverityCounts
from nvd_mcp.server import (
    _recommended_action,
    lookup_cve,
    search_cves,
    summarize_risk,
)

from .conftest import make_cve


def _wire_client(mock_cls: MagicMock, mock_client: AsyncMock) -> None:
    """Attach mock_client as the async context manager value on mock_cls."""
    mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)


# ---------------------------------------------------------------------------
# _recommended_action
# ---------------------------------------------------------------------------


class TestRecommendedAction:
    def test_critical_singular(self) -> None:
        result = _recommended_action(SeverityCounts(critical=1))
        assert "IMMEDIATE" in result
        assert "vulnerability" in result

    def test_critical_plural(self) -> None:
        result = _recommended_action(SeverityCounts(critical=3))
        assert "vulnerabilities" in result

    def test_high_priority(self) -> None:
        result = _recommended_action(SeverityCounts(high=2))
        assert "HIGH PRIORITY" in result

    def test_medium_priority(self) -> None:
        result = _recommended_action(SeverityCounts(medium=4))
        assert "MEDIUM PRIORITY" in result

    def test_low_risk(self) -> None:
        result = _recommended_action(SeverityCounts(low=1))
        assert "LOW RISK" in result

    def test_minimal_risk(self) -> None:
        result = _recommended_action(SeverityCounts())
        assert "MINIMAL RISK" in result

    def test_critical_takes_precedence_over_high(self) -> None:
        result = _recommended_action(SeverityCounts(critical=1, high=5))
        assert "IMMEDIATE" in result


# ---------------------------------------------------------------------------
# lookup_cve tool
# ---------------------------------------------------------------------------


class TestLookupCve:
    async def test_returns_cve_detail(self, log4shell_cve: NvdCve) -> None:
        with patch("nvd_mcp.server.NvdClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.fetch_cve = AsyncMock(return_value=log4shell_cve)
            _wire_client(mock_cls, mock_client)

            result = await lookup_cve("CVE-2021-44228")

        assert result["cve_id"] == "CVE-2021-44228"
        assert result["cvss_score"] == 10.0
        assert result["cvss_severity"] == "CRITICAL"

    async def test_returns_error_when_not_found(self) -> None:
        with patch("nvd_mcp.server.NvdClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.fetch_cve = AsyncMock(return_value=None)
            _wire_client(mock_cls, mock_client)

            result = await lookup_cve("CVE-9999-99999")

        assert "error" in result
        assert "CVE-9999-99999" in result["error"]


# ---------------------------------------------------------------------------
# search_cves tool
# ---------------------------------------------------------------------------


class TestSearchCves:
    async def test_returns_sorted_by_score_descending(
        self, log4shell_cve: NvdCve, medium_cve: NvdCve
    ) -> None:
        with patch("nvd_mcp.server.NvdClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.search = AsyncMock(return_value=[medium_cve, log4shell_cve])
            _wire_client(mock_cls, mock_client)

            results = await search_cves("log4j")

        assert results[0]["cvss_score"] == 10.0
        assert results[1]["cvss_score"] == 5.0

    async def test_clamps_max_results(self, log4shell_cve: NvdCve) -> None:
        with patch("nvd_mcp.server.NvdClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.search = AsyncMock(return_value=[log4shell_cve])
            _wire_client(mock_cls, mock_client)

            await search_cves("log4j", max_results=999)

        mock_client.search.assert_called_once_with("log4j", 20)

    async def test_returns_empty_list_on_no_results(self) -> None:
        with patch("nvd_mcp.server.NvdClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.search = AsyncMock(return_value=[])
            _wire_client(mock_cls, mock_client)

            results = await search_cves("unknownxyz")

        assert results == []


# ---------------------------------------------------------------------------
# summarize_risk tool
# ---------------------------------------------------------------------------


class TestSummarizeRisk:
    async def test_raises_on_empty_list(self) -> None:
        with pytest.raises(ValueError, match="at least one"):
            await summarize_risk([])

    async def test_raises_when_exceeds_ten(self) -> None:
        ids = [f"CVE-2021-{i:05d}" for i in range(11)]
        with pytest.raises(ValueError, match="Maximum 10"):
            await summarize_risk(ids)

    async def test_raises_on_invalid_id_format(self) -> None:
        with pytest.raises(ValueError, match="Invalid CVE ID format"):
            await summarize_risk(["NOT-A-CVE"])

    async def test_risk_score_all_critical(self, log4shell_cve: NvdCve) -> None:
        with patch("nvd_mcp.server.NvdClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.fetch_cve = AsyncMock(return_value=log4shell_cve)
            _wire_client(mock_cls, mock_client)

            with patch("nvd_mcp.server.asyncio.sleep", new_callable=AsyncMock):
                result = await summarize_risk(["CVE-2021-44228"])

        assert result["risk_score"] == 10.0
        assert result["severity_counts"]["critical"] == 1
        assert result["found"] == 1

    async def test_not_found_ids_recorded(self) -> None:
        with patch("nvd_mcp.server.NvdClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.fetch_cve = AsyncMock(return_value=None)
            _wire_client(mock_cls, mock_client)

            result = await summarize_risk(["CVE-9999-99999"])

        assert "CVE-9999-99999" in result["not_found"]
        assert result["found"] == 0
        assert result["risk_score"] == 0.0

    async def test_mixed_severities_compute_weighted_score(
        self, log4shell_cve: NvdCve, medium_cve: NvdCve
    ) -> None:
        cves = {"CVE-2021-44228": log4shell_cve, "CVE-2023-00001": medium_cve}

        with patch("nvd_mcp.server.NvdClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.fetch_cve = AsyncMock(side_effect=lambda cid: cves.get(cid))
            _wire_client(mock_cls, mock_client)

            with patch("nvd_mcp.server.asyncio.sleep", new_callable=AsyncMock):
                result = await summarize_risk(["CVE-2021-44228", "CVE-2023-00001"])

        # (CRITICAL=10 + MEDIUM=2) / 2 = 6.0
        assert result["risk_score"] == 6.0
        assert result["severity_counts"]["critical"] == 1
        assert result["severity_counts"]["medium"] == 1

    async def test_top_critical_limited_to_three(self) -> None:
        critical_cves = [
            make_cve(cve_id=f"CVE-2021-{i:05d}", score=10.0, severity="CRITICAL")
            for i in range(5)
        ]

        with patch("nvd_mcp.server.NvdClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.fetch_cve = AsyncMock(
                side_effect=lambda cid: next(
                    (c for c in critical_cves if c.id == cid), None
                )
            )
            _wire_client(mock_cls, mock_client)

            with patch("nvd_mcp.server.asyncio.sleep", new_callable=AsyncMock):
                result = await summarize_risk([f"CVE-2021-{i:05d}" for i in range(5)])

        assert len(result["top_critical"]) == 3

    async def test_recommended_action_present(self, log4shell_cve: NvdCve) -> None:
        with patch("nvd_mcp.server.NvdClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.fetch_cve = AsyncMock(return_value=log4shell_cve)
            _wire_client(mock_cls, mock_client)

            with patch("nvd_mcp.server.asyncio.sleep", new_callable=AsyncMock):
                result = await summarize_risk(["CVE-2021-44228"])

        assert "IMMEDIATE" in result["recommended_action"]
