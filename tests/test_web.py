"""Tests for web-scanner certificate hostname matching."""

from __future__ import annotations

import asyncio
import socket

import httpx
import pytest

from netsec_auditor.scanner.scope import Scope, ScopeError
from netsec_auditor.web.scanner import HTTPResponse, WebScanner


def test_hostname_matches_rfc6125() -> None:
    m = WebScanner._hostname_matches
    assert m("api.example.com", ["*.example.com"]) is True
    assert m("example.com", ["example.com"]) is True
    # A '*' wildcard covers exactly one label, so deeper names must not match.
    assert m("a.b.example.com", ["*.example.com"]) is False
    assert m("example.com", ["*.example.com"]) is False
    assert m("evil.com", ["*.example.com", "example.com"]) is False


def test_dangerous_method_check_uses_options_only() -> None:
    scanner = WebScanner(Scope(name="t", ip_addresses=["127.0.0.1"]))
    methods: list[str] = []

    async def fake_request(method: str, _url: str, **_kwargs: object) -> HTTPResponse:
        methods.append(method)
        return HTTPResponse(status_code=200, headers={"allow": "GET, PUT, DELETE"})

    scanner._safe_request = fake_request  # type: ignore[method-assign]
    findings = asyncio.run(scanner._check_http_methods("http://127.0.0.1"))
    asyncio.run(scanner.close())

    assert methods == ["OPTIONS"]
    assert {finding.name for finding in findings} == {
        "PUT method enabled — allows file upload",
        "DELETE method enabled",
    }


def test_sensitive_response_matches_are_redacted() -> None:
    scanner = WebScanner(Scope(name="t", ip_addresses=["127.0.0.1"]))
    response = HTTPResponse(
        status_code=200,
        headers={},
        body="api_key=super-secret-value password=hunter2",
    )
    findings = scanner._check_information_disclosure(response, "http://127.0.0.1")
    asyncio.run(scanner.close())

    rendered = " ".join(
        f"{finding.id} {finding.description} {finding.evidence}" for finding in findings
    )
    assert "super-secret-value" not in rendered
    assert "hunter2" not in rendered
    assert "[REDACTED]" in rendered


def test_cookie_findings_redact_cookie_value() -> None:
    scanner = WebScanner(Scope(name="t", ip_addresses=["127.0.0.1"]))
    response = HTTPResponse(
        status_code=200,
        headers={"set-cookie": "[REDACTED]"},
        set_cookie_headers=["session=top-secret; Path=/"],
    )
    findings = scanner._check_cookie_security(response, "http://127.0.0.1")
    asyncio.run(scanner.close())

    assert findings
    assert all("top-secret" not in finding.evidence for finding in findings)
    assert all("session=[REDACTED]" in finding.evidence for finding in findings)


def test_cookie_flags_are_matched_as_attributes_not_substrings() -> None:
    scanner = WebScanner(Scope(name="t", ip_addresses=["127.0.0.1"]))
    # Cookie names carrying the flag words must not mask the missing attributes.
    response = HTTPResponse(
        status_code=200,
        headers={},
        set_cookie_headers=[
            "__Secure-SID=a; Path=/",
            "httponly_pref=b; Path=/",
            "samesite_x=c; Path=/",
        ],
    )
    findings = scanner._check_cookie_security(response, "http://127.0.0.1")
    asyncio.run(scanner.close())

    assert len(findings) == 9
    assert sum("HttpOnly" in f.name for f in findings) == 3
    assert sum("Secure" in f.name for f in findings) == 3
    assert sum("SameSite" in f.name for f in findings) == 3


def test_cookie_with_all_flags_reports_nothing() -> None:
    scanner = WebScanner(Scope(name="t", ip_addresses=["127.0.0.1"]))
    response = HTTPResponse(
        status_code=200,
        headers={},
        set_cookie_headers=["sid=a; Path=/; HttpOnly; Secure; SameSite=Lax"],
    )
    findings = scanner._check_cookie_security(response, "http://127.0.0.1")
    asyncio.run(scanner.close())

    assert findings == []


async def test_redirect_outside_scope_is_not_followed() -> None:
    scope = Scope(name="t", ip_addresses=["127.0.0.1"])
    scanner = WebScanner(scope)
    contacted: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        contacted.append(request.url.host)
        return httpx.Response(302, headers={"Location": "http://192.0.2.2/"}, request=request)

    await scanner._client.aclose()
    scanner._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    # An out-of-scope redirect target is refused (returns None), never followed,
    # and the out-of-scope host is never contacted.
    assert await scanner._safe_request("GET", "http://127.0.0.1/") is None
    assert "192.0.2.2" not in contacted
    await scanner.close()


async def test_safe_request_refuses_write_methods() -> None:
    # The read-only allowlist in _safe_request itself must reject mutating methods
    # before any I/O — deleting the guard makes this raise-check fail.
    scanner = WebScanner(Scope(name="t", ip_addresses=["127.0.0.1"]))
    for method in ("POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"):
        with pytest.raises(ValueError):
            await scanner._safe_request(method, "http://127.0.0.1/")
    await scanner.close()


async def test_validate_url_rejects_out_of_scope_target() -> None:
    scanner = WebScanner(Scope(name="t", ip_addresses=["127.0.0.1"]))
    with pytest.raises(ScopeError):
        scanner._validate_url("http://192.0.2.9/")
    await scanner.close()


def test_sensitive_response_headers_are_redacted() -> None:
    headers = httpx.Headers(
        {
            "Server": "nginx",
            "X-Subject-Token": "gAAAAABsecrettoken",
            "WWW-Authenticate": "Bearer realm=example",
            "X-Vault-Token": "hvs.supersecret",
            "X-Powered-By": "PHP/8.2",
        }
    )
    sanitized = WebScanner._sanitize_headers(headers)
    assert sanitized["x-subject-token"] == "[REDACTED]"
    assert sanitized["www-authenticate"] == "[REDACTED]"
    assert sanitized["x-vault-token"] == "[REDACTED]"
    assert "gAAAAABsecrettoken" not in str(sanitized)
    assert "hvs.supersecret" not in str(sanitized)
    # Fingerprinting headers stay intact so technology detection still works.
    assert sanitized["server"] == "nginx"
    assert sanitized["x-powered-by"] == "PHP/8.2"


async def test_hostname_target_pins_connection_to_validated_ip() -> None:
    scope = Scope(name="t", cidr_ranges=["192.0.2.0/24"], domains=["scanme.test"])
    scanner = WebScanner(scope)
    seen: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["host"] = request.url.host
        seen["header_host"] = request.headers.get("Host")
        seen["sni"] = request.extensions.get("sni_hostname")
        return httpx.Response(200, text="ok", request=request)

    def fake_gai(*_a: object, **_k: object) -> list:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.50", 0))]

    original_gai = socket.getaddrinfo
    socket.getaddrinfo = fake_gai  # type: ignore[assignment]
    await scanner._client.aclose()
    scanner._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        resp = await scanner._safe_request("GET", "http://scanme.test/path")
    finally:
        socket.getaddrinfo = original_gai
        await scanner.close()

    assert resp is not None
    # The connection targets the scope-validated IP, not a re-resolved hostname.
    assert seen["host"] == "192.0.2.50"
    # Host header and TLS SNI still carry the original name (vhost-safe).
    assert seen["header_host"] == "scanme.test"
    assert seen["sni"] == "scanme.test"


def test_scan_marks_unreachable_host(monkeypatch) -> None:
    # A host with nothing on the port must be flagged unreachable, not reported
    # as an audited server with empty fields.
    import asyncio

    scanner = WebScanner(Scope(name="t", ip_addresses=["192.0.2.1"]))

    async def _no_response(*_a: object, **_k: object) -> None:
        return None

    scanner._safe_request = _no_response  # type: ignore[method-assign]
    result = asyncio.run(scanner.scan("http://192.0.2.1"))
    asyncio.run(scanner.close())

    assert result.reachable is False
    assert result.server == ""
