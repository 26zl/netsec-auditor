"""Tests for vulnerability detection and the packaged signature database."""

from __future__ import annotations

from netsec_auditor.scanner.engine import ServiceInfo
from netsec_auditor.vuln.detector import Severity, VulnerabilityDatabase


def test_severity_from_cvss() -> None:
    assert Severity.from_cvss(9.5) is Severity.CRITICAL
    assert Severity.from_cvss(7.0) is Severity.HIGH
    assert Severity.from_cvss(4.0) is Severity.MEDIUM
    assert Severity.from_cvss(0.1) is Severity.LOW
    assert Severity.from_cvss(0.0) is Severity.INFO


def test_version_less_than() -> None:
    vlt = VulnerabilityDatabase._version_less_than
    assert vlt("1.2", "1.10") is True
    assert vlt("8.9", "8.9") is False
    assert vlt("9.0", "8.9") is False
    assert vlt("garbage", "1.0") is False


def test_default_rules_loaded_and_match_all_rule_removed() -> None:
    db = VulnerabilityDatabase()
    ids = [r["id"] for r in db._rules]
    assert len(ids) >= 8
    # CVE-2023-44487 matched every HTTP service with no discriminator — removed.
    assert "CVE-2023-44487" not in ids


def test_rule_matches_respects_version_gate() -> None:
    db = VulnerabilityDatabase()
    old = ServiceInfo(name="ssh", product="OpenSSH", version="8.1")
    new = ServiceInfo(name="ssh", product="OpenSSH", version="9.6")
    assert "OPENSSH-OLD" in [v.id for v in db.match_service(old, 22)]
    assert "OPENSSH-OLD" not in [v.id for v in db.match_service(new, 22)]
