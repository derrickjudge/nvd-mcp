"""Unit tests for nvd_mcp.client — HTTP client and converter functions."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import orjson
import pytest

from nvd_mcp.client import (
    NvdClient,
    _english_description,
    _extract_cvss,
    to_detail,
    to_summary,
)
from nvd_mcp.models import NvdCve, NvdDescription, NvdMetrics, Severity

from .conftest import make_cve, make_cvss_metric, make_nvd_response

# ---------------------------------------------------------------------------
# _extract_cvss
# ---------------------------------------------------------------------------


class TestExtractCvss:
    def test_returns_v31_score(self, log4shell_cve: NvdCve) -> None:
        score, severity, vector = _extract_cvss(log4shell_cve)
        assert score == 10.0
        assert severity is Severity.CRITICAL
        assert vector is not None

    def test_prefers_v31_over_v30(self) -> None:
        cve = make_cve()
        cve.metrics.cvss_metric_v31 = [make_cvss_metric(9.0, "CRITICAL")]
        cve.metrics.cvss_metric_v30 = [make_cvss_metric(5.0, "MEDIUM")]
        score, severity, _ = _extract_cvss(cve)
        assert score == 9.0
        assert severity is Severity.CRITICAL

    def test_falls_back_to_v30_when_no_v31(self) -> None:
        cve = make_cve()
        cve.metrics.cvss_metric_v31 = []
        cve.metrics.cvss_metric_v30 = [make_cvss_metric(7.5, "HIGH")]
        score, severity, _ = _extract_cvss(cve)
        assert score == 7.5
        assert severity is Severity.HIGH

    def test_falls_back_to_v2_when_no_v3(self) -> None:
        cve = make_cve()
        cve.metrics.cvss_metric_v31 = []
        cve.metrics.cvss_metric_v30 = []
        cve.metrics.cvss_metric_v2 = [make_cvss_metric(6.8, "MEDIUM", version="2.0")]
        score, severity, _ = _extract_cvss(cve)
        assert score == 6.8
        assert severity is Severity.MEDIUM

    def test_returns_unknown_when_no_metrics(self) -> None:
        cve = make_cve()
        cve.metrics = NvdMetrics()
        score, severity, vector = _extract_cvss(cve)
        assert score is None
        assert severity is Severity.UNKNOWN
        assert vector is None

    def test_prefers_primary_scorer(self) -> None:
        cve = make_cve()
        cve.metrics.cvss_metric_v31 = [
            make_cvss_metric(5.0, "MEDIUM", metric_type="Secondary"),
            make_cvss_metric(9.8, "CRITICAL", metric_type="Primary"),
        ]
        score, severity, _ = _extract_cvss(cve)
        assert score == 9.8
        assert severity is Severity.CRITICAL

    def test_unknown_severity_string_falls_back(self) -> None:
        cve = make_cve()
        cve.metrics.cvss_metric_v31 = [make_cvss_metric(8.0, "SUPER_HIGH")]
        _, severity, _ = _extract_cvss(cve)
        assert severity is Severity.UNKNOWN


# ---------------------------------------------------------------------------
# _english_description
# ---------------------------------------------------------------------------


class TestEnglishDescription:
    def test_returns_english(self, log4shell_cve: NvdCve) -> None:
        desc = _english_description(log4shell_cve)
        assert "Log4j2" in desc

    def test_falls_back_to_first_when_no_english(self) -> None:
        cve = make_cve()
        cve.descriptions = [NvdDescription(lang="fr", value="Description française")]
        assert _english_description(cve) == "Description française"

    def test_returns_fallback_when_empty(self) -> None:
        cve = make_cve()
        cve.descriptions = []
        assert _english_description(cve) == "No description available."


# ---------------------------------------------------------------------------
# to_detail / to_summary
# ---------------------------------------------------------------------------


class TestToDetail:
    def test_maps_fields_correctly(self, log4shell_cve: NvdCve) -> None:
        detail = to_detail(log4shell_cve)
        assert detail.cve_id == "CVE-2021-44228"
        assert detail.cvss_score == 10.0
        assert detail.cvss_severity is Severity.CRITICAL
        assert detail.vuln_status == "Analyzed"

    def test_references_capped_at_five(self) -> None:
        urls = [f"https://example.com/{i}" for i in range(10)]
        cve = make_cve(references=urls)
        detail = to_detail(cve)
        assert len(detail.references) == 5

    def test_vuln_status_defaults_to_unknown(self) -> None:
        cve = make_cve()
        cve.vuln_status = None
        detail = to_detail(cve)
        assert detail.vuln_status == "Unknown"


class TestToSummary:
    def test_truncates_long_description(self) -> None:
        cve = make_cve(description="x" * 300)
        summary = to_summary(cve)
        assert len(summary.description) == 200
        assert summary.description.endswith("...")

    def test_preserves_short_description(self, log4shell_cve: NvdCve) -> None:
        summary = to_summary(log4shell_cve)
        assert "Log4j2" in summary.description
        assert not summary.description.endswith("...")


# ---------------------------------------------------------------------------
# NvdClient
# ---------------------------------------------------------------------------


def _make_http_response(data: dict, status_code: int = 200) -> MagicMock:
    """Build a mock httpx.Response returning the given JSON data."""
    response = MagicMock(spec=httpx.Response)
    response.status_code = status_code
    response.content = orjson.dumps(data)
    response.headers = {}
    response.raise_for_status = MagicMock()
    return response


class TestNvdClientFetchCve:
    async def test_returns_cve_when_found(self, log4shell_cve: NvdCve) -> None:
        payload = make_nvd_response([log4shell_cve]).model_dump(by_alias=True)
        mock_response = _make_http_response(payload)

        with patch("nvd_mcp.client.httpx.AsyncClient") as mock_client_cls:
            mock_http = AsyncMock()
            mock_http.get = AsyncMock(return_value=mock_response)
            mock_http.aclose = AsyncMock()
            mock_client_cls.return_value = mock_http

            async with NvdClient() as client:
                cve = await client.fetch_cve("CVE-2021-44228")

        assert cve is not None
        assert cve.id == "CVE-2021-44228"

    async def test_returns_none_when_not_found(self) -> None:
        payload = make_nvd_response([]).model_dump(by_alias=True)
        mock_response = _make_http_response(payload)

        with patch("nvd_mcp.client.httpx.AsyncClient") as mock_client_cls:
            mock_http = AsyncMock()
            mock_http.get = AsyncMock(return_value=mock_response)
            mock_http.aclose = AsyncMock()
            mock_client_cls.return_value = mock_http

            async with NvdClient() as client:
                cve = await client.fetch_cve("CVE-9999-99999")

        assert cve is None

    async def test_raises_on_invalid_cve_id(self) -> None:
        async with NvdClient() as client:
            with pytest.raises(ValueError, match="Invalid CVE ID format"):
                await client.fetch_cve("not-a-cve")

    async def test_raises_after_max_retries_on_429(self) -> None:
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "0"}
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "429 Too Many Requests",
            request=MagicMock(),
            response=mock_response,
        )

        with patch("nvd_mcp.client.httpx.AsyncClient") as mock_client_cls:
            mock_http = AsyncMock()
            mock_http.get = AsyncMock(return_value=mock_response)
            mock_http.aclose = AsyncMock()
            mock_client_cls.return_value = mock_http

            with patch("nvd_mcp.client.asyncio.sleep", new_callable=AsyncMock):
                async with NvdClient() as client:
                    with pytest.raises(httpx.HTTPStatusError):
                        await client.fetch_cve("CVE-2021-44228")


class TestNvdClientSearch:
    async def test_returns_list_of_cves(self, log4shell_cve: NvdCve) -> None:
        payload = make_nvd_response([log4shell_cve]).model_dump(by_alias=True)
        mock_response = _make_http_response(payload)

        with patch("nvd_mcp.client.httpx.AsyncClient") as mock_client_cls:
            mock_http = AsyncMock()
            mock_http.get = AsyncMock(return_value=mock_response)
            mock_http.aclose = AsyncMock()
            mock_client_cls.return_value = mock_http

            async with NvdClient() as client:
                results = await client.search("log4j", max_results=10)

        assert len(results) == 1
        assert results[0].id == "CVE-2021-44228"

    async def test_returns_empty_list_on_no_results(self) -> None:
        payload = make_nvd_response([]).model_dump(by_alias=True)
        mock_response = _make_http_response(payload)

        with patch("nvd_mcp.client.httpx.AsyncClient") as mock_client_cls:
            mock_http = AsyncMock()
            mock_http.get = AsyncMock(return_value=mock_response)
            mock_http.aclose = AsyncMock()
            mock_client_cls.return_value = mock_http

            async with NvdClient() as client:
                results = await client.search("unknownxyz123", max_results=5)

        assert results == []
