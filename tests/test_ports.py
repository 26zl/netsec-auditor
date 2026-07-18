"""Tests for CLI port-specification parsing."""

from __future__ import annotations

import pytest
import typer

from netsec_auditor.cli import _parse_ports
from netsec_auditor.scanner.engine import COMMON_PORTS, TOP_1000_PORTS


def test_named_port_sets() -> None:
    assert _parse_ports("common") == COMMON_PORTS
    assert _parse_ports("top1000") == TOP_1000_PORTS
    assert _parse_ports("all") == list(range(1, 65536))


def test_explicit_and_range() -> None:
    assert _parse_ports("80,443") == [80, 443]
    assert _parse_ports("20-22") == [20, 21, 22]
    assert _parse_ports("22, 80-82") == [22, 80, 81, 82]


def test_invalid_raises_exit() -> None:
    with pytest.raises(typer.Exit):
        _parse_ports("notaport")
