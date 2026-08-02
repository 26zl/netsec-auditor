"""Tests for the protocol probe framework contract."""

from __future__ import annotations

import asyncio

import pytest

from netsec_auditor import profiles
from netsec_auditor.protocols.base import (
    ProbeResult,
    ProbeSpec,
    probers_for_port,
    read_framed,
    register,
)
from netsec_auditor.protocols.scan import identify_services


async def _noop(host: str, port: int, timeout: float) -> ProbeResult | None:
    return None


def test_probe_result_to_dict() -> None:
    r = ProbeResult(
        protocol="modbus",
        port=502,
        transport="tcp",
        is_ot=True,
        device_info={"vendor": "Acme"},
    )
    d = r.to_dict()
    assert d["protocol"] == "modbus"
    assert d["is_ot"] is True
    assert d["device_info"]["vendor"] == "Acme"


def test_register_indexes_by_port() -> None:
    spec = ProbeSpec(
        name="unit-test-proto",
        default_port=65001,
        transport="tcp",
        is_ot=True,
        probe=_noop,
    )
    register([spec])

    assert spec in probers_for_port(65001)


def test_registry_separates_transports_on_one_port() -> None:
    tcp = ProbeSpec("unit-test-tcp", 65002, "tcp", True, _noop)
    udp = ProbeSpec("unit-test-udp", 65002, "udp", True, _noop)
    register([tcp, udp])

    # A host with only the TCP port open must not also receive the UDP datagram.
    assert probers_for_port(65002, "tcp") == [tcp]
    assert probers_for_port(65002, "udp") == [udp]
    assert probers_for_port(65002) == [tcp, udp]  # None still matches both


def test_registered_ethernetip_transports_are_distinct() -> None:
    import netsec_auditor.protocols  # noqa: F401  (populates the registry)

    assert [s.name for s in probers_for_port(44818, "tcp")] == ["ethernetip"]
    assert [s.name for s in probers_for_port(44818, "udp")] == ["ethernetip-udp"]


def test_identify_services_skips_unsafe_probes_under_the_ot_profile() -> None:
    calls: list[str] = []

    async def _record(host: str, port: int, timeout: float) -> ProbeResult | None:
        calls.append("ran")
        return ProbeResult(protocol="unit-test-unsafe", port=port)

    register([ProbeSpec("unit-test-unsafe", 65003, "tcp", False, _record, is_safe=False)])

    assert asyncio.run(identify_services("10.0.0.1", [65003], profiles.OT)) == []
    assert calls == []  # allow_intrusive=False must actually suppress it

    assert asyncio.run(identify_services("10.0.0.1", [65003], profiles.IT)) != []
    assert calls == ["ran"]


def test_identify_services_restricts_transport_when_udp_ports_given() -> None:
    seen: list[str] = []

    def _prober(name: str):
        async def probe(host: str, port: int, timeout: float) -> ProbeResult | None:
            seen.append(name)
            return None
        return probe

    register([
        ProbeSpec("unit-test-t", 65004, "tcp", False, _prober("tcp")),
        ProbeSpec("unit-test-u", 65004, "udp", False, _prober("udp")),
    ])

    asyncio.run(identify_services("10.0.0.1", [65004], profiles.IT, udp_ports=[]))
    assert seen == ["tcp"]


def test_identify_services_validates_arguments_with_no_matching_prober() -> None:
    # The guards used to sit behind the "no specs" early return.
    with pytest.raises(ValueError, match="timeout"):
        asyncio.run(identify_services("10.0.0.1", [65535], profiles.IT, timeout=0))
    with pytest.raises(ValueError, match="rate_per_second"):
        asyncio.run(
            identify_services("10.0.0.1", [65535], profiles.IT, rate_per_second=-1)
        )


def test_read_framed_reassembles_a_segmented_frame() -> None:
    chunks = [b"\x00\x00\x00\x06ab", b"cd"]

    class _Reader:
        async def read(self, n: int) -> bytes:
            return chunks.pop(0) if chunks else b""

    def frame_length(data: bytes) -> int | None:
        if len(data) < 4:
            return None
        return 4 + int.from_bytes(data[1:4], "big")

    # A single read() would have returned only the first segment.
    assert asyncio.run(read_framed(_Reader(), 1.0, frame_length)) == b"\x00\x00\x00\x06abcd"


def test_read_framed_returns_what_arrived_when_the_frame_never_completes() -> None:
    class _Reader:
        async def read(self, n: int) -> bytes:
            await asyncio.sleep(0.05)
            return b"\x00\x00\x00\xff"  # promises 259 bytes, delivers 4 at a time

    got = asyncio.run(read_framed(_Reader(), 0.1, lambda d: 4 + int.from_bytes(d[1:4], "big")))
    assert got.startswith(b"\x00\x00\x00\xff")
    assert len(got) < 259  # timed out, but the partial reply is still handed back
