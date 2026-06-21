"""Shared pytest fixtures for nvd-mcp tests."""

import pytest

from nvd_mcp.models import (
    NvdCve,
    NvdCvssData,
    NvdCvssMetric,
    NvdDescription,
    NvdMetrics,
    NvdReference,
    NvdResponse,
    NvdVulnerability,
)


def make_cvss_metric(
    score: float,
    severity: str,
    vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    metric_type: str = "Primary",
    version: str = "3.1",
) -> NvdCvssMetric:
    """Build a minimal NvdCvssMetric for use in tests.

    Args:
        score: CVSS base score.
        severity: Severity label (e.g. ``"CRITICAL"``).
        vector: CVSS vector string.
        metric_type: ``"Primary"`` or ``"Secondary"``.
        version: CVSS version string.

    Returns:
        Populated NvdCvssMetric instance.
    """
    return NvdCvssMetric(
        source="nvd@nist.gov",
        type=metric_type,
        cvssData=NvdCvssData(
            version=version,
            vectorString=vector,
            baseScore=score,
            baseSeverity=severity,
        ),
    )


def make_cve(
    cve_id: str = "CVE-2021-44228",
    description: str = "A critical RCE vulnerability in Apache Log4j2.",
    score: float = 10.0,
    severity: str = "CRITICAL",
    vuln_status: str = "Analyzed",
    references: list[str] | None = None,
) -> NvdCve:
    """Build a minimal NvdCve for use in tests.

    Args:
        cve_id: CVE identifier.
        description: English description string.
        score: CVSS base score.
        severity: CVSS severity label.
        vuln_status: NVD vuln status string.
        references: List of reference URLs (defaults to one example URL).

    Returns:
        Populated NvdCve instance.
    """
    refs = references if references is not None else ["https://example.com/advisory"]
    return NvdCve(
        id=cve_id,
        published="2021-12-10T10:15:09.143",
        lastModified="2023-06-28T08:15:08.823",
        vulnStatus=vuln_status,
        descriptions=[NvdDescription(lang="en", value=description)],
        metrics=NvdMetrics(
            cvssMetricV31=[make_cvss_metric(score=score, severity=severity)]
        ),
        references=[NvdReference(url=url) for url in refs],
    )


def make_nvd_response(cves: list[NvdCve]) -> NvdResponse:
    """Wrap a list of NvdCve objects in a minimal NvdResponse envelope.

    Args:
        cves: List of CVE records to wrap.

    Returns:
        NvdResponse with the given CVEs as vulnerabilities.
    """
    return NvdResponse(
        resultsPerPage=len(cves),
        startIndex=0,
        totalResults=len(cves),
        vulnerabilities=[NvdVulnerability(cve=cve) for cve in cves],
    )


@pytest.fixture()
def log4shell_cve() -> NvdCve:
    """NvdCve fixture for Log4Shell (CVE-2021-44228)."""
    return make_cve(
        cve_id="CVE-2021-44228",
        description="Apache Log4j2 JNDI RCE vulnerability.",
        score=10.0,
        severity="CRITICAL",
    )


@pytest.fixture()
def medium_cve() -> NvdCve:
    """NvdCve fixture for a MEDIUM severity CVE."""
    return make_cve(
        cve_id="CVE-2023-00001",
        description="A medium severity example vulnerability.",
        score=5.0,
        severity="MEDIUM",
    )
