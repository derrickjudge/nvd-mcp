"""Unit tests for nvd_mcp.models."""

import pytest

from nvd_mcp.models import (
    CVE_ID_PATTERN,
    NvdMetrics,
    NvdResponse,
    Severity,
    SeverityCounts,
)

from .conftest import make_cve, make_nvd_response


class TestCveIdPattern:
    def test_valid_standard_format(self) -> None:
        assert CVE_ID_PATTERN.match("CVE-2021-44228")

    def test_valid_long_id(self) -> None:
        assert CVE_ID_PATTERN.match("CVE-2023-123456")

    def test_valid_case_insensitive(self) -> None:
        assert CVE_ID_PATTERN.match("cve-2021-44228")

    def test_invalid_missing_prefix(self) -> None:
        assert CVE_ID_PATTERN.match("2021-44228") is None

    def test_invalid_wrong_separator(self) -> None:
        assert CVE_ID_PATTERN.match("CVE_2021_44228") is None

    def test_invalid_letters_in_id(self) -> None:
        assert CVE_ID_PATTERN.match("CVE-2021-ABCD") is None


class TestSeverityEnum:
    def test_value_is_string(self) -> None:
        assert Severity.CRITICAL == "CRITICAL"

    def test_construct_from_string(self) -> None:
        assert Severity("HIGH") is Severity.HIGH

    def test_unknown_string_raises(self) -> None:
        with pytest.raises(ValueError):
            Severity("EXTREME")


class TestSeverityCounts:
    def test_total_sums_all_fields(self) -> None:
        counts = SeverityCounts(critical=2, high=3, medium=1, low=0, none=1)
        assert counts.total == 7

    def test_total_defaults_to_zero(self) -> None:
        assert SeverityCounts().total == 0


class TestNvdResponseParsing:
    def test_parses_empty_vulnerabilities(self) -> None:
        payload = {
            "resultsPerPage": 0,
            "startIndex": 0,
            "totalResults": 0,
        }
        response = NvdResponse.model_validate(payload)
        assert response.total_results == 0
        assert response.vulnerabilities == []

    def test_parses_single_vulnerability(self) -> None:
        cve = make_cve()
        nvd_response = make_nvd_response([cve])
        assert nvd_response.total_results == 1
        assert nvd_response.vulnerabilities[0].cve.id == "CVE-2021-44228"

    def test_alias_mapping(self) -> None:
        payload = {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [],
        }
        response = NvdResponse.model_validate(payload)
        assert response.results_per_page == 1

    def test_cvss_metric_alias_mapping(self) -> None:
        metrics = NvdMetrics.model_validate(
            {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": (
                                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                            ),
                            "baseScore": 10.0,
                            "baseSeverity": "CRITICAL",
                        },
                    }
                ]
            }
        )
        assert len(metrics.cvss_metric_v31) == 1
        assert metrics.cvss_metric_v31[0].cvss_data.base_score == 10.0
