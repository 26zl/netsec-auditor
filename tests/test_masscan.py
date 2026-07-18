"""Tests for the masscan output parser."""

from __future__ import annotations

from netsec_auditor.discovery.masscan import masscan_available, parse_masscan_list


def test_parse_masscan_list() -> None:
    text = (
        "#masscan\n"
        "open tcp 80 192.168.1.1 1700000000\n"
        "open tcp 443 192.168.1.1 1700000000\n"
        "open tcp 22 192.168.1.50 1700000000\n"
        "# end\n"
    )
    assert parse_masscan_list(text) == ["192.168.1.1", "192.168.1.50"]


def test_parse_masscan_empty_and_garbage() -> None:
    assert parse_masscan_list("") == []
    assert parse_masscan_list("garbage line\n#comment\n") == []


def test_masscan_available_returns_bool() -> None:
    assert isinstance(masscan_available(), bool)
