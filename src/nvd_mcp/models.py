from __future__ import annotations

import re
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


class Severity(str, Enum):
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
    model_config = {"populate_by_name": True}

    version: str
    vector_string: str = Field(alias="vectorString")
    base_score: float = Field(alias="baseScore")
    base_severity: str = Field(alias="baseSeverity")


class NvdCvssMetric(BaseModel):
    model_config = {"populate_by_name": True}

    source: str
    type: str
    cvss_data: NvdCvssData = Field(alias="cvssData")


class NvdDescription(BaseModel):
    lang: str
    value: str


class NvdReference(BaseModel):
    url: str
    source: Optional[str] = None


class NvdMetrics(BaseModel):
    model_config = {"populate_by_name": True}

    cvss_metric_v31: list[NvdCvssMetric] = Field(
        default_factory=list, alias="cvssMetricV31"
    )
    cvss_metric_v30: list[NvdCvssMetric] = Field(
        default_factory=list, alias="cvssMetricV30"
    )
    cvss_metric_v2: list[NvdCvssMetric] = Field(
        default_factory=list, alias="cvssMetricV2"
    )


class NvdCve(BaseModel):
    model_config = {"populate_by_name": True}

    id: str
    published: str
    last_modified: str = Field(alias="lastModified")
    vuln_status: Optional[str] = Field(default=None, alias="vulnStatus")
    descriptions: list[NvdDescription] = Field(default_factory=list)
    metrics: NvdMetrics = Field(default_factory=NvdMetrics)
    references: list[NvdReference] = Field(default_factory=list)


class NvdVulnerability(BaseModel):
    cve: NvdCve


class NvdResponse(BaseModel):
    model_config = {"populate_by_name": True}

    results_per_page: int = Field(alias="resultsPerPage")
    start_index: int = Field(alias="startIndex")
    total_results: int = Field(alias="totalResults")
    vulnerabilities: list[NvdVulnerability] = Field(default_factory=list)


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
    cvss_score: Optional[float]
    cvss_severity: Severity
    cvss_vector: Optional[str]
    references: list[str]


class CveSummary(BaseModel):
    """Lightweight CVE entry — returned in search_cves results."""

    cve_id: str
    description: str
    cvss_score: Optional[float]
    cvss_severity: Severity
    published: str


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    none: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.none


class TopCve(BaseModel):
    cve_id: str
    cvss_score: Optional[float]
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
