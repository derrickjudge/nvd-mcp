import re
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


class Severity(str, Enum):
    """CVSS severity label as defined by NVD."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# NVD API v2 response parsing models (internal — not exposed to tools)
# ---------------------------------------------------------------------------


class NvdCvssData(BaseModel):
    """Raw CVSS scoring data from a single NVD metric entry."""

    model_config = {"populate_by_name": True}

    version: str
    vector_string: str = Field(alias="vectorString")
    base_score: float = Field(alias="baseScore")
    base_severity: str = Field(alias="baseSeverity")


class NvdCvssMetric(BaseModel):
    """One CVSS metric record (source + score data) from the NVD response."""

    model_config = {"populate_by_name": True}

    source: str
    type: str
    cvss_data: NvdCvssData = Field(alias="cvssData")


class NvdDescription(BaseModel):
    """A localised CVE description string."""

    lang: str
    value: str


class NvdReference(BaseModel):
    """A single external reference URL attached to a CVE."""

    url: str
    source: str | None = None


class NvdMetrics(BaseModel):
    """All CVSS metric sets for a CVE, grouped by CVSS version."""

    model_config = {"populate_by_name": True}

    cvss_metric_v31: Annotated[list[NvdCvssMetric], Field(alias="cvssMetricV31")] = []
    cvss_metric_v30: Annotated[list[NvdCvssMetric], Field(alias="cvssMetricV30")] = []
    cvss_metric_v2: Annotated[list[NvdCvssMetric], Field(alias="cvssMetricV2")] = []


class NvdCve(BaseModel):
    """Full CVE record as returned by the NVD REST API v2."""

    model_config = {"populate_by_name": True}

    id: str
    published: str
    last_modified: str = Field(alias="lastModified")
    vuln_status: str | None = Field(default=None, alias="vulnStatus")
    descriptions: list[NvdDescription] = []
    metrics: NvdMetrics = Field(default_factory=NvdMetrics)
    references: list[NvdReference] = []


class NvdVulnerability(BaseModel):
    """Wrapper object that NVD uses to nest a CVE record in the response list."""

    cve: NvdCve


class NvdResponse(BaseModel):
    """Top-level NVD API v2 response envelope."""

    model_config = {"populate_by_name": True}

    results_per_page: int = Field(alias="resultsPerPage")
    start_index: int = Field(alias="startIndex")
    total_results: int = Field(alias="totalResults")
    vulnerabilities: list[NvdVulnerability] = []


# ---------------------------------------------------------------------------
# Tool output models (returned to the LLM / caller)
# ---------------------------------------------------------------------------


class CveDetail(BaseModel):
    """Full CVE details — returned by lookup_cve."""

    cve_id: str
    description: str
    published: str
    last_modified: str
    vuln_status: str
    cvss_score: float | None
    cvss_severity: Severity
    cvss_vector: str | None
    references: list[str]


class CveSummary(BaseModel):
    """Lightweight CVE entry — returned in search_cves results."""

    cve_id: str
    description: str
    cvss_score: float | None
    cvss_severity: Severity
    published: str


class SeverityCounts(BaseModel):
    """Count of CVEs at each CVSS severity level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    none: int = 0

    @property
    def total(self) -> int:
        """Total number of CVEs across all severity levels."""
        return self.critical + self.high + self.medium + self.low + self.none


class TopCve(BaseModel):
    """Summary of a high-severity CVE for inclusion in a risk report."""

    cve_id: str
    cvss_score: float | None
    cvss_severity: Severity
    description: str


class RiskReport(BaseModel):
    """Aggregated risk summary — returned by summarize_risk."""

    queried_cve_ids: list[str]
    found: int
    not_found: list[str]
    severity_counts: SeverityCounts
    risk_score: float
    top_critical: list[TopCve]
    recommended_action: str
