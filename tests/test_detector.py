"""Tests for vulnerability detection and the packaged signature database."""

from __future__ import annotations

import asyncio

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
    # CVE-2023-44487 has no product or version discriminator, so it would flag every HTTP service.
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


async def test_nvd_score_falls_back_to_cvss_v40_and_v2(tmp_path) -> None:
    # A CVE scored only in CVSS v4.0 (or only v2) must not be prioritized as a 0.0.
    def nvd_entry(cve_id: str, metrics: dict) -> dict:
        return {"cve": {"id": cve_id, "metrics": metrics}}

    def metric(score: float, vector: str) -> list[dict]:
        return [{"cvssData": {"baseScore": score, "vectorString": vector}}]

    data = {
        "vulnerabilities": [
            nvd_entry("CVE-2026-0001", {"cvssMetricV40": metric(9.3, "CVSS:4.0/AV:N")}),
            nvd_entry("CVE-2009-0001", {"cvssMetricV2": metric(7.5, "AV:N/AC:L")}),
            nvd_entry(
                "CVE-2024-0001",
                {"cvssMetricV31": metric(5.3, "CVSS:3.1/AV:N"),
                 "cvssMetricV40": metric(8.7, "CVSS:4.0/AV:N")},
            ),
            nvd_entry("CVE-2024-0002", {"cvssMetricV31": []}),
        ]
    }
    client = CVEQueryClient(cache_dir=tmp_path)
    try:
        results = client._parse_nvd_response(data)
    finally:
        await client.close()
    scores = {r["cve_id"]: (r["cvss_score"], r["severity"]) for r in results}

    assert scores["CVE-2026-0001"] == (9.3, "critical")
    assert scores["CVE-2009-0001"] == (7.5, "high")
    assert scores["CVE-2024-0001"] == (5.3, "medium")  # v3.1 is preferred when present
    assert scores["CVE-2024-0002"] == (0.0, "info")


async def test_nvd_requests_are_paced_and_survive_a_non_json_body(tmp_path, monkeypatch) -> None:
    # Without an API key NVD allows 5 requests per 30 s; back-to-back calls get 429s.
    import httpx

    sleeps: list[float] = []
    real_sleep = asyncio.sleep

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        await real_sleep(0)

    monkeypatch.setattr("netsec_auditor.vuln.detector.asyncio.sleep", fake_sleep)
    client = CVEQueryClient(cache_dir=tmp_path)

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>maintenance</html>", request=request)

    await client._client.aclose()
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        assert await client.get_cve("CVE-2024-0001") is None
        assert await client.get_cve("CVE-2024-0002") is None
    finally:
        await client.close()

    assert len(sleeps) == 1 and 5.0 < sleeps[0] <= 6.0


def test_end_of_life_rules_flag_unsupported_release_lines() -> None:
    db = VulnerabilityDatabase()

    def ids(name: str, version: str, product: str = "") -> set[str]:
        service = ServiceInfo(name=name, product=product, version=version)
        return {v.id for v in db.match_service(service, 0)}

    assert "MYSQL-OLD" in ids("mysql", "8.0.46")
    assert ids("mysql", "8.4.13") == set()
    assert "MYSQL-INNOVATION-EOL" in ids("mysql", "9.5.2")
    assert ids("mysql", "9.7.4") == set()
    assert "POSTGRES-OLD" in ids("postgresql", "14.24")
    assert ids("postgresql", "15.19") == set()
    assert "TOMCAT-OLD" in ids("http", "8.5.100", "Apache Tomcat")
    assert "TOMCAT-10.0-EOL" in ids("http", "10.0.27", "Apache Tomcat")
    assert ids("http", "10.1.61", "Apache Tomcat") == set()
    assert "NGINX-OLD" in ids("http", "1.28.3", "nginx")
    assert ids("http", "1.30.6", "nginx") == set()
    # nmap never reports the Log4j library as an HTTP product, so no rule pretends to.
    assert "CVE-2021-44228" not in {rule["id"] for rule in db._rules}
