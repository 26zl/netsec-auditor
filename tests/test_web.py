"""Tests for web-scanner certificate hostname matching."""

from __future__ import annotations

from netsec_auditor.web.scanner import WebScanner


def test_hostname_matches_rfc6125() -> None:
    m = WebScanner._hostname_matches
    assert m("api.example.com", ["*.example.com"]) is True
    assert m("example.com", ["example.com"]) is True
    # A '*' wildcard covers exactly one label, so deeper names must not match.
    assert m("a.b.example.com", ["*.example.com"]) is False
    assert m("example.com", ["*.example.com"]) is False
    assert m("evil.com", ["*.example.com", "example.com"]) is False
