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


def test_scan_network_uses_isolated_nmap_instance_per_unit() -> None:
    import nmap

    from netsec_auditor.scanner.engine import PortScanner
    from netsec_auditor.scanner.scope import Scope

    created: list = []

    class FakeHost(dict):
        def hostname(self) -> str:
            return ""

    class FakePortScanner:
        def __init__(self) -> None:
            created.append(self)
            self._hosts: dict = {}

        def scan(self, hosts: str, ports: str, arguments: str, timeout: float) -> None:
            # Each instance only ever holds the host it was asked to scan.
            self._hosts = {
                hosts: FakeHost(
                    {
                        "addresses": {"ipv4": hosts},
                        "status": {"state": "up"},
                        "tcp": {80: {"state": "open", "name": "http", "conf": "10"}},
                    }
                )
            }

        def all_hosts(self) -> list:
            return list(self._hosts)

        def __getitem__(self, key: str) -> dict:
            return self._hosts[key]

    original = nmap.PortScanner
    nmap.PortScanner = FakePortScanner  # type: ignore[misc, assignment]
    try:
        scope = Scope(name="t", ip_addresses=["10.0.0.1", "10.0.0.2"], max_scan_rate=0)
        engine = PortScanner(scope)
        result = asyncio.run(
            engine.scan_network(
                ["10.0.0.1", "10.0.0.2"],
                ports=[80],
                scan_type="connect",
                service_detection=False,
                concurrency=2,
            )
        )
    finally:
        nmap.PortScanner = original  # type: ignore[misc]

    # One fresh nmap instance per scanned unit — not a single shared, clobbered scanner.
    assert len(created) == 2
    # Each host is reported under its own address, proving no cross-contamination.
    assert {h.ip for h in result.hosts} == {"10.0.0.1", "10.0.0.2"}
