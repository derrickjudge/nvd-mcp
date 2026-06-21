import asyncio
import logging

import httpx
import orjson

from .models import (
    CVE_ID_PATTERN,
    CveDetail,
    CveSummary,
    NvdCve,
    NvdResponse,
    Severity,
)

logger = logging.getLogger(__name__)

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
) -> tuple[float | None, Severity, str | None]:
    """Return the best available CVSS score, severity, and vector string.

    Checks metric versions in priority order: CVSSv3.1 > CVSSv3.0 > CVSSv2.
    Within a version, the ``Primary`` scorer is preferred over any secondary.

    Args:
        cve: Parsed NVD CVE record.

    Returns:
        A tuple of (base_score, severity, vector_string). Any value may be
        None if no CVSS data is present; severity defaults to UNKNOWN.
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
    """Return the English description for a CVE, or the first available.

    Args:
        cve: Parsed NVD CVE record.

    Returns:
        Description string, or a fallback message if none is present.
    """
    for desc in cve.descriptions:
        if desc.lang == "en":
            return desc.value
    if cve.descriptions:
        return cve.descriptions[0].value
    return "No description available."


def to_detail(cve: NvdCve) -> CveDetail:
    """Convert a raw NvdCve to a CveDetail output model.

    Args:
        cve: Parsed NVD CVE record.

    Returns:
        Fully populated CveDetail instance.
    """
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
    """Convert a raw NvdCve to a lightweight CveSummary output model.

    Descriptions are truncated to 200 characters for readability in list views.

    Args:
        cve: Parsed NVD CVE record.

    Returns:
        Populated CveSummary instance.
    """
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
    cleanly after use::

        async with NvdClient() as client:
            cve = await client.fetch_cve("CVE-2021-44228")
    """

    def __init__(self) -> None:
        self._http = httpx.AsyncClient(
            timeout=_TIMEOUT,
            headers={"User-Agent": _USER_AGENT},
        )

    async def __aenter__(self) -> "NvdClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self._http.aclose()

    async def _get(self, params: dict[str, str | int]) -> httpx.Response:
        """GET the NVD endpoint with automatic 429 retry and exponential backoff.

        Args:
            params: Query parameters to pass to the NVD API.

        Returns:
            Successful HTTP response.

        Raises:
            httpx.HTTPStatusError: On non-429 HTTP error responses.
            RuntimeError: If the rate limit persists after all retries.
        """
        for attempt in range(_MAX_RETRIES):
            response = await self._http.get(NVD_BASE_URL, params=params)
            if response.status_code != 429:
                response.raise_for_status()
                return response
            if attempt < _MAX_RETRIES - 1:
                wait = float(
                    response.headers.get("Retry-After", _RETRY_BACKOFF[attempt])
                )
                logger.warning(
                    "NVD rate limit hit (attempt %d/%d) — retrying in %.1fs",
                    attempt + 1,
                    _MAX_RETRIES,
                    wait,
                )
                await asyncio.sleep(wait)
        raise RuntimeError(f"NVD API rate limit exceeded after {_MAX_RETRIES} attempts")

    async def fetch_cve(self, cve_id: str) -> NvdCve | None:
        """Fetch a single CVE by ID.

        Args:
            cve_id: CVE identifier, e.g. ``"CVE-2021-44228"``.

        Returns:
            Parsed NvdCve record, or None if NVD has no record for this ID.

        Raises:
            ValueError: If ``cve_id`` does not match the expected format.
            httpx.HTTPStatusError: On unexpected HTTP error responses.
            RuntimeError: If rate limiting persists after all retries.
        """
        if not CVE_ID_PATTERN.match(cve_id):
            raise ValueError(f"Invalid CVE ID format: {cve_id!r}")
        response = await self._get({"cveId": cve_id.upper()})
        parsed = NvdResponse.model_validate(orjson.loads(response.content))
        if not parsed.vulnerabilities:
            return None
        return parsed.vulnerabilities[0].cve

    async def search(self, keyword: str, max_results: int) -> list[NvdCve]:
        """Search CVEs by keyword.

        Args:
            keyword: Product name or search term.
            max_results: Maximum number of results to return.

        Returns:
            List of matching NvdCve records (may be empty).

        Raises:
            httpx.HTTPStatusError: On unexpected HTTP error responses.
            RuntimeError: If rate limiting persists after all retries.
        """
        response = await self._get(
            {"keywordSearch": keyword, "resultsPerPage": max_results}
        )
        parsed = NvdResponse.model_validate(orjson.loads(response.content))
        return [v.cve for v in parsed.vulnerabilities]
