"""Tests for offline pcap cleartext-credential scanning (pure, no scapy)."""

from __future__ import annotations

from netsec_auditor.capture.pcap import scan_cleartext_credentials


def test_http_basic_redacts_password() -> None:
    # base64("admin:secret") == "YWRtaW46c2VjcmV0"
    payload = b"GET / HTTP/1.1\r\nAuthorization: Basic YWRtaW46c2VjcmV0\r\n\r\n"
    findings = scan_cleartext_credentials([("10.0.0.5", "10.0.0.1", 80, payload)])
    assert findings
    ev = findings[0]["evidence"]
    assert "admin" in ev
    assert "secret" not in ev
    assert findings[0]["severity"] == "high"


def test_ftp_user_pass_redacted() -> None:
    records = [
        ("10.0.0.5", "10.0.0.1", 21, b"USER admin\r\n"),
        ("10.0.0.5", "10.0.0.1", 21, b"PASS hunter2\r\n"),
    ]
    findings = scan_cleartext_credentials(records)
    joined = " ".join(f["evidence"] for f in findings)
    assert "admin" in joined
    assert "hunter2" not in joined  # password must be redacted


def test_snmp_default_community_flagged() -> None:
    # Minimal SNMP v2c message: SEQ { INTEGER version=1, OCTET STRING "public", ... }
    payload = bytes([0x30, 0x0b, 0x02, 0x01, 0x01, 0x04, 0x06]) + b"public"
    findings = scan_cleartext_credentials([("10.0.0.5", "10.0.0.1", 161, payload)])
    assert any("public" in f["evidence"] for f in findings)


def test_no_secret_no_findings() -> None:
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    assert scan_cleartext_credentials([("10.0.0.5", "10.0.0.1", 80, payload)]) == []


def test_malformed_records_skipped() -> None:
    assert scan_cleartext_credentials([("bad",), None]) == []  # type: ignore[list-item]
