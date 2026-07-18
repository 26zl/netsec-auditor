"""Tests for threat-intel enrichment — pure parse_*/prioritize helpers, no network."""

from __future__ import annotations

from netsec_auditor.intel.enrich import (
    parse_epss,
    parse_internetdb,
    parse_kev,
    prioritize,
)


def test_parse_epss_extracts_score_and_percentile() -> None:
    payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.99"}]}
    assert parse_epss(payload) == {"CVE-2021-44228": {"epss": 0.97, "percentile": 0.99}}


def test_parse_epss_empty_payload() -> None:
    assert parse_epss({}) == {}


def test_parse_kev_maps_cve_to_entry() -> None:
    payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j2",
                "dateAdded": "2021-12-10",
            }
        ]
    }
    result = parse_kev(payload)
    assert "CVE-2021-44228" in result
    assert result["CVE-2021-44228"]["vendorProject"] == "Apache"
    assert result["CVE-2021-44228"]["dateAdded"] == "2021-12-10"


def test_parse_internetdb_normalizes_keys() -> None:
    payload = {"ip": "1.1.1.1", "ports": [80, 443], "vulns": ["CVE-2021-44228"]}
    result = parse_internetdb(payload)
    assert result["ports"] == [80, 443]
    assert result["vulns"] == ["CVE-2021-44228"]
    # Missing fields default to empty lists and the ip field is dropped.
    assert result["cpes"] == []
    assert result["hostnames"] == []
    assert result["tags"] == []
    assert "ip" not in result


def test_parse_internetdb_empty_is_empty_dict() -> None:
    assert parse_internetdb({}) == {}


def test_prioritize_kev_is_critical() -> None:
    result = prioritize("CVE-2021-44228", cvss=10.0, epss=0.99, in_kev=True)
    assert result["priority"] == "critical"
    assert result["in_kev"] is True
    assert result["cve_id"] == "CVE-2021-44228"


def test_prioritize_high_epss_non_kev_is_high() -> None:
    assert prioritize("CVE-2020-0001", cvss=5.0, epss=0.95, in_kev=False)["priority"] == "high"


def test_prioritize_high_cvss_non_kev_is_high() -> None:
    assert prioritize("CVE-2017-0001", cvss=9.8, epss=0.1, in_kev=False)["priority"] == "high"


def test_prioritize_medium_from_cvss() -> None:
    assert prioritize("CVE-2018-0001", cvss=7.5, epss=0.2, in_kev=False)["priority"] == "medium"


def test_prioritize_low() -> None:
    assert prioritize("CVE-2019-0001", cvss=3.0, epss=0.1, in_kev=False)["priority"] == "low"
