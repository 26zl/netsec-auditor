"""Tests for the scanner engine helpers."""

from __future__ import annotations

import asyncio

from netsec_auditor.scanner.engine import (
    NetworkDiscovery,
    PortState,
    _RateLimiter,
    is_privileged,
)


def test_portstate_parse_known_and_unknown() -> None:
    assert PortState.parse("open") is PortState.OPEN
    assert PortState.parse("closed|filtered") is PortState.CLOSED_FILTERED
    assert PortState.parse("unfiltered") is PortState.UNFILTERED
    # nmap states outside the enum must not crash the parser.
    assert PortState.parse("gibberish") is PortState.UNKNOWN


def test_is_privileged_returns_bool() -> None:
    assert isinstance(is_privileged(), bool)


def test_probe_ports_present() -> None:
    assert NetworkDiscovery.PROBE_PORTS
    assert all(isinstance(p, int) for p in NetworkDiscovery.PROBE_PORTS)


def test_rate_limiter_unlimited_is_instant() -> None:
    async def run() -> None:
        rl = _RateLimiter(0)
        await rl.acquire()
        await rl.acquire()

    asyncio.run(run())
