from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from .models import (
    CVE_ID_PATTERN,
    CveDetail,
    CveSummary,
    NvdCve,
    NvdResponse,
    Severity,
)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_USER_AGENT = "nvd-mcp/0.1.0"
_TIMEOUT = httpx.Timeout(10.0)
_MAX_RETRIES = 3
# Sleep durations (seconds) between retry attempts — index = attempt number
_RETRY_BACKOFF = [1.0, 2.0, 4.0]


# ---------------------------------------------------------------------------
# Helpers: extract data from raw NvdCve objects
# ---------------------------------------------------------------------------


def _extract_cvss(
    cve: NvdCve,
) -> tuple[Optional[float], Severity, Optional[str]]:
    """Return (score, severity, vector) from the best available CVSS version.

    Priority: CVSSv3.1 > CVSSv3.0 > CVSSv2. Within a version, prefer the
    "Primary" source entry over any secondary scorer.
    """
    for metric_list in (cve.metrics.cvss_metric_v31, cve.metrics.cvss_metric_v30):
        if not metric_list:
            continue
        primary = next((m for m in metric_list if m.type == "Primary"), None)
        entry = primary or metric_list[0]
        try:
            severity = Severity(entry.cvss_data.base_severity.upper())
        except ValueError:
            severity = Severity.UNKNOWN
        return entry.cvss_data.base_score, severity, entry.cvss_data.vector_string

    if cve.metrics.cvss_metric_v2:
        entry = cve.metrics.cvss_metric_v2[0]
        try:
            severity = Severity(entry.cvss_data.base_severity.upper())
        except ValueError:
            severity = Severity.UNKNOWN
        return entry.cvss_data.base_score, severity, entry.cvss_data.vector_string

    return None, Severity.UNKNOWN, None


def _english_description(cve: NvdCve) -> str:
    for desc in cve.descriptions:
        if desc.lang == "en":
            return desc.value
    return cve.descriptions[0].value if cve.descriptions else "No description available."


def to_detail(cve: NvdCve) -> CveDetail:
    score, severity, vector = _extract_cvss(cve)
    return CveDetail(
        cve_id=cve.id,
        description=_english_description(cve),
        published=cve.published,
        last_modified=cve.last_modified,
        vuln_status=cve.vuln_status or "Unknown",
        cvss_score=score,
        cvss_severity=severity,
        cvss_vector=vector,
        references=[ref.url for ref in cve.references[:5]],
    )


def to_summary(cve: NvdCve) -> CveSummary:
    score, severity, _ = _extract_cvss(cve)
    desc = _english_description(cve)
    if len(desc) > 200:
        desc = desc[:197] + "..."
    return CveSummary(
        cve_id=cve.id,
        description=desc,
        cvss_score=score,
        cvss_severity=severity,
        published=cve.published,
    )


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


class NvdClient:
    """Async HTTP client for the NVD REST API v2.

    Use as an async context manager so the underlying httpx session is closed
    cleanly after use.

        async with NvdClient() as client:
            cve = await client.fetch_cve("CVE-2021-44228")
    """

    def __init__(self) -> None:
        self._http = httpx.AsyncClient(
            timeout=_TIMEOUT,
            headers={"User-Agent": _USER_AGENT},
        )

    async def __aenter__(self) -> NvdClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self._http.aclose()

    async def _get(self, params: dict[str, str | int]) -> httpx.Response:
        """GET the NVD endpoint with automatic 429 retry and backoff."""
        for attempt in range(_MAX_RETRIES):
            response = await self._http.get(NVD_BASE_URL, params=params)
            if response.status_code != 429:
                response.raise_for_status()
                return response
            if attempt < _MAX_RETRIES - 1:
                wait = float(
                    response.headers.get("Retry-After", _RETRY_BACKOFF[attempt])
                )
                await asyncio.sleep(wait)
        raise RuntimeError(
            f"NVD API rate limit exceeded after {_MAX_RETRIES} attempts"
        )

    async def fetch_cve(self, cve_id: str) -> Optional[NvdCve]:
        """Fetch a single CVE by ID. Returns None if NVD has no record."""
        if not CVE_ID_PATTERN.match(cve_id):
            raise ValueError(f"Invalid CVE ID format: {cve_id!r}")
        response = await self._get({"cveId": cve_id.upper()})
        parsed = NvdResponse.model_validate(response.json())
        if not parsed.vulnerabilities:
            return None
        return parsed.vulnerabilities[0].cve

    async def search(self, keyword: str, max_results: int) -> list[NvdCve]:
        """Search CVEs by keyword. Returns up to max_results entries."""
        response = await self._get(
            {"keywordSearch": keyword, "resultsPerPage": max_results}
        )
        parsed = NvdResponse.model_validate(response.json())
        return [v.cve for v in parsed.vulnerabilities]
