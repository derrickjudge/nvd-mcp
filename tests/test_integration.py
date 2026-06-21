"""Integration tests against the live NVD API.

These tests make real HTTP calls and are skipped by default.
Run them explicitly to verify end-to-end behaviour:

    pytest -m integration
"""

import pytest

from nvd_mcp.client import NvdClient, to_detail, to_summary
from nvd_mcp.models import Severity

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def anyio_backend() -> str:
    """Use asyncio backend for module-scoped async fixtures."""
    return "asyncio"


class TestLiveLookupCve:
    async def test_log4shell_resolves(self) -> None:
        """CVE-2021-44228 is a well-known CRITICAL CVE — must always exist in NVD."""
        async with NvdClient() as client:
            cve = await client.fetch_cve("CVE-2021-44228")

        assert cve is not None, "Log4Shell CVE not found — NVD may be unavailable"
        detail = to_detail(cve)
        assert detail.cve_id == "CVE-2021-44228"
        assert detail.cvss_score is not None
        assert detail.cvss_score >= 9.0, (
            f"Expected critical score, got {detail.cvss_score}"
        )
        assert detail.cvss_severity == Severity.CRITICAL

    async def test_unknown_cve_returns_none(self) -> None:
        async with NvdClient() as client:
            cve = await client.fetch_cve("CVE-9999-99999")

        assert cve is None

    async def test_invalid_id_raises_value_error(self) -> None:
        async with NvdClient() as client:
            with pytest.raises(ValueError, match="Invalid CVE ID format"):
                await client.fetch_cve("NOT-A-CVE")


class TestLiveSearch:
    async def test_log4j_keyword_returns_results(self) -> None:
        async with NvdClient() as client:
            cves = await client.search("log4j", max_results=5)

        assert len(cves) > 0, "Expected results for 'log4j' — NVD may be unavailable"
        summaries = [to_summary(c) for c in cves]
        ids = [s.cve_id for s in summaries]
        assert "CVE-2021-44228" in ids, f"Log4Shell missing from results: {ids}"

    async def test_search_returns_at_most_requested(self) -> None:
        async with NvdClient() as client:
            cves = await client.search("apache", max_results=3)

        assert len(cves) <= 3
