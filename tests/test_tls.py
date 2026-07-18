"""Tests for TLS/SSL posture classification (pure logic, no network)."""

from __future__ import annotations

import inspect

from netsec_auditor.web.tls import (
    classify_cipher_findings,
    classify_protocol_findings,
    scan_tls,
)

_FINDING_KEYS = {"name", "severity", "description", "evidence", "remediation"}


def _only(findings: list[dict[str, str]]) -> dict[str, str]:
    assert len(findings) == 1, findings
    return findings[0]


def test_finding_shape_is_canonical() -> None:
    for finding in classify_protocol_findings({"TLSv1": True, "SSLv3": True}):
        assert set(finding) == _FINDING_KEYS
    for finding in classify_cipher_findings(["ECDHE-RSA-RC4-SHA"]):
        assert set(finding) == _FINDING_KEYS


def test_tls10_yields_medium_deprecated_finding() -> None:
    finding = _only(classify_protocol_findings({"TLSv1": True}))
    assert finding["severity"] == "medium"
    assert "TLS 1.0" in finding["name"]
    assert "deprecated" in finding["description"].lower()


def test_tls11_yields_medium_finding() -> None:
    finding = _only(classify_protocol_findings({"TLSv1.1": True}))
    assert finding["severity"] == "medium"
    assert "TLS 1.1" in finding["name"]


def test_sslv3_yields_high_finding() -> None:
    finding = _only(classify_protocol_findings({"SSLv3": True}))
    assert finding["severity"] == "high"
    assert "SSLv3" in finding["name"]


def test_sslv2_yields_high_finding() -> None:
    finding = _only(classify_protocol_findings({"SSLv2": True}))
    assert finding["severity"] == "high"


def test_all_modern_yields_no_findings() -> None:
    protocols = {
        "TLSv1": False, "TLSv1.1": False,
        "TLSv1.2": True, "TLSv1.3": True, "SSLv3": False,
    }
    assert classify_protocol_findings(protocols) == []


def test_missing_tls13_yields_low_info() -> None:
    finding = _only(classify_protocol_findings({"TLSv1.2": True, "TLSv1.3": False}))
    assert finding["severity"] == "low"
    assert "1.3" in finding["name"]


def test_untested_protocols_are_not_flagged() -> None:
    # None means "could not test", which must never produce a finding.
    protocols = {"TLSv1": None, "TLSv1.1": None, "SSLv3": None, "TLSv1.3": None}
    assert classify_protocol_findings(protocols) == []


def test_multiple_deprecated_protocols_all_reported() -> None:
    protocols = {"TLSv1": True, "TLSv1.1": True, "SSLv3": True}
    findings = classify_protocol_findings(protocols)
    severities = sorted(f["severity"] for f in findings)
    assert severities == ["high", "medium", "medium"]


def test_rc4_cipher_yields_high_finding() -> None:
    finding = _only(classify_cipher_findings(["ECDHE-RSA-RC4-SHA"]))
    assert finding["severity"] == "high"
    assert "ECDHE-RSA-RC4-SHA" in finding["name"]
    assert "RC4" in finding["description"]


def test_null_cipher_yields_high_finding() -> None:
    finding = _only(classify_cipher_findings(["ECDHE-RSA-NULL-SHA"]))
    assert finding["severity"] == "high"


def test_export_cipher_yields_high_finding() -> None:
    finding = _only(classify_cipher_findings(["EXP-RC2-CBC-MD5"]))
    assert finding["severity"] == "high"


def test_3des_cipher_yields_medium_sweet32_finding() -> None:
    finding = _only(classify_cipher_findings(["ECDHE-RSA-DES-CBC3-SHA"]))
    assert finding["severity"] == "medium"
    assert "SWEET32" in finding["description"]


def test_single_des_ranks_above_3des() -> None:
    # "3DES" is matched before bare "DES" so single-DES stays high, 3DES medium.
    assert classify_cipher_findings(["DES-CBC-SHA"])[0]["severity"] == "high"


def test_empty_cipher_inputs_yield_nothing() -> None:
    assert classify_cipher_findings([]) == []
    assert classify_cipher_findings([""]) == []


def test_scan_tls_is_async_and_importable() -> None:
    # Do not invoke it — that would touch the network. Just verify the contract.
    assert inspect.iscoroutinefunction(scan_tls)
    sig = inspect.signature(scan_tls)
    assert list(sig.parameters) == ["hostname", "port", "timeout"]
    assert sig.parameters["port"].default == 443
    assert sig.parameters["timeout"].default == 10.0
