import asyncio
import logging
from typing import Any

import httpx
from fastmcp import FastMCP

from .client import NvdClient, to_detail, to_summary
from .models import (
    CVE_ID_PATTERN,
    CveSummary,
    RiskReport,
    Severity,
    SeverityCounts,
    TopCve,
)

logger = logging.getLogger(__name__)

mcp = FastMCP(
    name="NVD CVE Intelligence",
    instructions=(
        "Tools for querying and analyzing CVE vulnerability data from the "
        "NIST National Vulnerability Database (NVD). Use lookup_cve for a "
        "specific CVE, search_cves to find CVEs by product or keyword, and "
        "summarize_risk to triage a set of CVEs by severity."
    ),
)

_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.NONE: 0,
    Severity.UNKNOWN: 0,
}


def _recommended_action(counts: SeverityCounts) -> str:
    """Generate a remediation priority string from a severity breakdown.

    Args:
        counts: Severity counts from a summarize_risk run.

    Returns:
        Human-readable recommended action string.
    """
    if counts.critical > 0:
        label = "vulnerability" if counts.critical == 1 else "vulnerabilities"
        return (
            f"IMMEDIATE: {counts.critical} CRITICAL {label} found — "
            "patch or mitigate within 24 hours."
        )
    if counts.high > 0:
        label = "vulnerability" if counts.high == 1 else "vulnerabilities"
        return (
            f"HIGH PRIORITY: {counts.high} HIGH {label} — "
            "schedule patching within 48–72 hours."
        )
    if counts.medium > 0:
        return (
            "MEDIUM PRIORITY: Schedule remediation within the next maintenance window."
        )
    if counts.low > 0:
        return "LOW RISK: Monitor and patch during next scheduled maintenance."
    return "MINIMAL RISK: No significant CVE scores found in the provided list."


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def lookup_cve(cve_id: str) -> dict[str, Any]:
    """Look up full details for a specific CVE by ID.

    Args:
        cve_id: The CVE identifier, e.g. ``"CVE-2021-44228"``.

    Returns:
        Full CVE record including description, CVSS score, severity,
        published/modified dates, vuln status, and up to 5 reference URLs.
        Returns an error dict if the CVE is not found in NVD.
    """
    async with NvdClient() as client:
        cve = await client.fetch_cve(cve_id)
    if cve is None:
        return {"error": f"{cve_id.upper()} not found in NVD."}
    return to_detail(cve).model_dump(mode="json")


@mcp.tool()
async def search_cves(keyword: str, max_results: int = 10) -> list[dict[str, Any]]:
    """Search for CVEs by product name or keyword.

    Args:
        keyword: Product name or search term, e.g. ``"Apache Log4j"``.
        max_results: Number of results to return. Clamped to 1–20. Default 10.

    Returns:
        List of matching CVEs sorted by CVSS score descending, each with
        CVE ID, one-line description, CVSS score, severity, and publish date.
    """
    max_results = max(1, min(max_results, 20))
    async with NvdClient() as client:
        cves = await client.search(keyword, max_results)
    summaries = [to_summary(cve) for cve in cves]
    summaries.sort(key=lambda s: s.cvss_score or 0.0, reverse=True)
    return [s.model_dump(mode="json") for s in summaries]


@mcp.tool()
async def summarize_risk(cve_ids: list[str]) -> dict[str, Any]:
    """Aggregate a risk summary for a list of CVE IDs.

    Fetches each CVE from NVD, computes a weighted composite risk score,
    and returns a severity breakdown with prioritized remediation guidance.

    Risk score formula: ``(CRITICAL×10 + HIGH×5 + MEDIUM×2 + LOW×1) / total_found``
    Score range: **0** (no risk) → **10** (all CRITICAL).

    Args:
        cve_ids: 1–10 CVE IDs, e.g. ``["CVE-2021-44228", "CVE-2022-22965"]``.

    Returns:
        Severity counts, composite risk score, top CRITICAL/HIGH CVEs,
        list of any IDs not found, and a recommended action string.

    Raises:
        ValueError: If ``cve_ids`` is empty, exceeds 10 items, or contains
            malformed CVE IDs.
    """
    if not cve_ids:
        raise ValueError("Provide at least one CVE ID.")
    if len(cve_ids) > 10:
        raise ValueError("Maximum 10 CVE IDs per request.")
    invalid = [c for c in cve_ids if not CVE_ID_PATTERN.match(c)]
    if invalid:
        raise ValueError(f"Invalid CVE ID format: {invalid}")

    not_found: list[str] = []
    summaries: list[CveSummary] = []

    async with NvdClient() as client:
        for i, cve_id in enumerate(cve_ids):
            if i > 0:
                # Polite stagger — NVD allows 5 req/30 s without an API key
                await asyncio.sleep(0.6)
            try:
                cve = await client.fetch_cve(cve_id)
                if cve is None:
                    not_found.append(cve_id.upper())
                else:
                    summaries.append(to_summary(cve))
            except (httpx.HTTPError, RuntimeError) as exc:
                logger.error("Failed to fetch %s: %s", cve_id, exc)
                not_found.append(cve_id.upper())

    counts = SeverityCounts()
    for s in summaries:
        match s.cvss_severity:
            case Severity.CRITICAL:
                counts.critical += 1
            case Severity.HIGH:
                counts.high += 1
            case Severity.MEDIUM:
                counts.medium += 1
            case Severity.LOW:
                counts.low += 1
            case _:
                counts.none += 1

    total = counts.total
    if total == 0:
        risk_score = 0.0
    else:
        weighted = (
            counts.critical * _SEVERITY_WEIGHTS[Severity.CRITICAL]
            + counts.high * _SEVERITY_WEIGHTS[Severity.HIGH]
            + counts.medium * _SEVERITY_WEIGHTS[Severity.MEDIUM]
            + counts.low * _SEVERITY_WEIGHTS[Severity.LOW]
        )
        risk_score = round(weighted / total, 2)

    top_critical = [
        TopCve(
            cve_id=s.cve_id,
            cvss_score=s.cvss_score,
            cvss_severity=s.cvss_severity,
            description=s.description,
        )
        for s in sorted(summaries, key=lambda s: s.cvss_score or 0.0, reverse=True)
        if s.cvss_severity in (Severity.CRITICAL, Severity.HIGH)
    ][:3]

    report = RiskReport(
        queried_cve_ids=[c.upper() for c in cve_ids],
        found=total,
        not_found=not_found,
        severity_counts=counts,
        risk_score=risk_score,
        top_critical=top_critical,
        recommended_action=_recommended_action(counts),
    )
    return report.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Start the NVD MCP server using stdio transport."""
    mcp.run()


if __name__ == "__main__":
    main()
