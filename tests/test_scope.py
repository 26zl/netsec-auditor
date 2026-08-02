"""Tests for scope authorization — the tool's core safety control."""

from __future__ import annotations

import pytest

from netsec_auditor.scanner.scope import Scope, ScopeError


def test_ip_in_authorized_cidr() -> None:
    scope = Scope(name="t", cidr_ranges=["10.0.0.0/24"])
    assert scope.validate_target("10.0.0.5") is True


def test_ip_outside_scope_is_rejected() -> None:
    scope = Scope(name="t", cidr_ranges=["10.0.0.0/24"])
    with pytest.raises(ScopeError):
        scope.validate_target("192.168.1.1")


def test_excluded_cidr_overrides_authorized_range() -> None:
    scope = Scope(
        name="t",
        cidr_ranges=["10.0.0.0/24"],
        excluded_cidr_ranges=["10.0.0.0/28"],
    )
    with pytest.raises(ScopeError):
        scope.validate_target("10.0.0.5")
    assert scope.validate_target("10.0.0.20") is True


def test_explicit_ip_and_excluded_ip() -> None:
    scope = Scope(
        name="t",
        ip_addresses=["203.0.113.10"],
        excluded_ip_addresses=["203.0.113.11"],
    )
    assert scope.validate_target("203.0.113.10") is True
    with pytest.raises(ScopeError):
        scope.validate_target("203.0.113.11")


def test_url_scheme_is_stripped_before_matching() -> None:
    scope = Scope(name="t", cidr_ranges=["10.0.0.0/24"])
    assert scope.validate_target("https://10.0.0.5:8443/admin") is True


def test_domain_match_and_exclusion() -> None:
    # localhost resolves offline, so this needs no network.
    scope = Scope(name="t", domains=["localhost"])
    assert scope.validate_target("localhost") is True
    assert scope.validate_target("http://localhost:8080/x") is True

    excluded = Scope(name="t", domains=["localhost"], excluded_domains=["localhost"])
    with pytest.raises(ScopeError):
        excluded.validate_target("localhost")


def test_cidr_target_subnet_containment() -> None:
    scope = Scope(name="t", cidr_ranges=["10.0.0.0/16"])
    # A subnet fully inside the authorized range is allowed.
    assert scope.validate_target("10.0.1.0/24") is True
    # A range broader than anything authorized is rejected (fail-closed).
    with pytest.raises(ScopeError):
        scope.validate_target("10.0.0.0/8")


def test_cidr_target_overlapping_exclusion_is_rejected() -> None:
    scope = Scope(
        name="t",
        cidr_ranges=["10.0.0.0/16"],
        excluded_cidr_ranges=["10.0.5.0/24"],
    )
    with pytest.raises(ScopeError):
        scope.validate_target("10.0.5.0/25")


def test_cidr_target_containing_excluded_ip_is_rejected() -> None:
    scope = Scope(
        name="t",
        cidr_ranges=["10.0.0.0/24"],
        excluded_ip_addresses=["10.0.0.42"],
    )
    with pytest.raises(ScopeError, match="excluded address"):
        scope.validate_target("10.0.0.0/24")


def test_all_dns_answers_must_be_authorized(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = [
        (2, 1, 6, "", ("10.0.0.10", 0)),
        (2, 1, 6, "", ("192.0.2.10", 0)),
    ]
    monkeypatch.setattr("socket.getaddrinfo", lambda *_args: answers)
    scope = Scope(name="t", cidr_ranges=["10.0.0.0/24"])
    with pytest.raises(ScopeError):
        scope.validate_target("multi.example")


def test_invalid_scope_limits_are_rejected() -> None:
    with pytest.raises(ScopeError, match="allowed_ports"):
        Scope(name="t", allowed_ports=[0, 443])
    with pytest.raises(ScopeError, match="max_scan_rate"):
        Scope(name="t", max_scan_rate=-1)


def test_unresolvable_target_raises() -> None:
    scope = Scope(name="t", cidr_ranges=["10.0.0.0/24"])
    with pytest.raises(ScopeError):
        scope.validate_target("this-host-does-not-exist.invalid")


def test_excluded_domain_covers_subdomains(monkeypatch: pytest.MonkeyPatch) -> None:
    # Excluding a name must also exclude everything beneath it, or an operator who
    # excluded prod would still scan db.prod.
    monkeypatch.setattr(
        "socket.getaddrinfo", lambda *_a, **_k: [(2, 1, 6, "", ("10.0.0.7", 0))]
    )
    scope = Scope(
        name="t",
        cidr_ranges=["10.0.0.0/24"],
        domains=["*.example.com"],
        excluded_domains=["prod.example.com"],
    )
    assert scope.validate_target("api.example.com") is True
    for excluded in ("prod.example.com", "db.prod.example.com", "a.b.prod.example.com"):
        with pytest.raises(ScopeError):
            scope.validate_target(excluded)


def test_wildcard_domain_matching() -> None:
    # Scope wildcards authorize all subdomains (broad, matches operator intent).
    match = Scope._domain_matches
    assert match("api.example.com", ["*.example.com"]) is True
    assert match("a.b.example.com", ["*.example.com"]) is True
    assert match("example.com", ["example.com"]) is True
    assert match("example.com", ["*.example.com"]) is False
    assert match("evil.com", ["*.example.com", "example.com"]) is False


def test_validate_port_semantics() -> None:
    unrestricted = Scope(name="t")
    assert unrestricted.validate_port(8080) is True

    restricted = Scope(name="t", allowed_ports=[80, 443])
    assert restricted.validate_port(443) is True
    with pytest.raises(ScopeError):
        restricted.validate_port(8080)
