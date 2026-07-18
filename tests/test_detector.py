"""Tests for vulnerability detection and the packaged signature database."""

from __future__ import annotations

from netsec_auditor.scanner.engine import ServiceInfo
from netsec_auditor.vuln.detector import CVEQueryClient, Severity, VulnerabilityDatabase


def test_severity_from_cvss() -> None:
    assert Severity.from_cvss(9.5) is Severity.CRITICAL
    assert Severity.from_cvss(7.0) is Severity.HIGH
    assert Severity.from_cvss(4.0) is Severity.MEDIUM
    assert Severity.from_cvss(0.1) is Severity.LOW
    assert Severity.from_cvss(0.0) is Severity.INFO


def test_version_less_than() -> None:
    vlt = VulnerabilityDatabase._version_less_than
    assert vlt("1.2", "1.10") is True
    assert vlt("1.2", "1.2.0") is False
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
    vulnerable = ServiceInfo(name="http", product="Apache httpd", version="2.4.49")
    older = ServiceInfo(name="http", product="Apache httpd", version="2.4.48")
    fixed = ServiceInfo(name="http", product="Apache httpd", version="2.4.50")
    unrelated = ServiceInfo(name="http", product="Apache httpd", version="2.4.49.1")
    assert "CVE-2021-41773" in [v.id for v in db.match_service(vulnerable, 80)]
    assert "CVE-2021-41773" not in [v.id for v in db.match_service(older, 80)]
    assert "CVE-2021-41773" not in [v.id for v in db.match_service(fixed, 80)]
    assert "CVE-2021-41773" not in [v.id for v in db.match_service(unrelated, 80)]


def test_client_side_openssh_rule_is_not_in_server_signatures() -> None:
    db = VulnerabilityDatabase()
    assert "OPENSSH-OLD" not in [rule["id"] for rule in db._rules]


async def test_invalid_cve_id_is_rejected_before_any_nvd_request(tmp_path) -> None:
    client = CVEQueryClient(cache_dir=tmp_path)
    calls: list[dict] = []

    async def spy(params: dict) -> None:
        calls.append(params)
        return None

    client._request_nvd = spy  # type: ignore[method-assign]
    try:
        # A malformed CVE id must be rejected by the guard, never reaching the
        # network layer, and must never create a cache file.
        assert await client.get_cve("CVE-../../outside") is None
        assert calls == []
        assert list(tmp_path.iterdir()) == []
        # A well-formed id passes the guard and does reach _request_nvd.
        assert await client.get_cve("CVE-2021-44228") is None
        assert len(calls) == 1
    finally:
        await client.close()
