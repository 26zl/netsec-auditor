"""Unit tests for read-only UDP amplification / reflector exposure probes.

Every request builder is pure and asserted against known byte vectors; the
``probe_*`` coroutines are exercised with a monkeypatched ``udp_request``, so no
test performs any real network I/O.
"""

from __future__ import annotations

import asyncio
import struct
from collections.abc import Callable

import pytest

from netsec_auditor.protocols import amplification
from netsec_auditor.protocols.amplification import (
    SPECS,
    build_chargen_request,
    build_memcached_stats_request,
    build_ntp_monlist_request,
    build_ntp_version_request,
    build_ssdp_amp_request,
)

# NTP monlist


def test_build_ntp_monlist_request_layout() -> None:
    req = build_ntp_monlist_request()
    assert len(req) == 8  # 8-byte mode-7 private header
    assert req[0] == 0x17  # response 0 | more 0 | version 2 | mode 7
    assert req[0] & 0x07 == 7  # mode bits = 7 (private / mode 7)
    assert (req[0] >> 3) & 0x07 == 2  # version bits = 2
    assert req[1] == 0x00  # auth 0, sequence 0
    assert req[2] == 0x03  # implementation 3 (IMPL_XNTPD)
    assert req[3] == 0x2A  # request code 42 (REQ_MON_GETLIST_1)
    assert req[:4] == b"\x17\x00\x03\x2a"  # the well-known monlist prefix
    assert req[4:] == b"\x00\x00\x00\x00"  # zero padding


def test_build_ntp_version_request_is_mode3_client() -> None:
    req = build_ntp_version_request()
    assert len(req) == 48  # standard NTP packet size
    assert req[0] == 0x1B
    assert req[0] & 0x07 == 3  # mode 3 = client
    assert (req[0] >> 3) & 0x07 == 3  # version 3
    assert req[1:] == b"\x00" * 47


# memcached


def test_build_memcached_stats_request_layout() -> None:
    req = build_memcached_stats_request()
    assert len(req) >= 8  # at least the UDP frame header
    assert req.endswith(b"stats\r\n")
    request_id, seq, count, reserved = struct.unpack("!HHHH", req[:8])
    assert request_id == 0
    assert seq == 0
    assert count == 1  # single datagram
    assert reserved == 0
    assert req[8:] == b"stats\r\n"


# CharGen


def test_build_chargen_request_is_single_byte() -> None:
    assert len(build_chargen_request()) == 1


# SSDP


def test_build_ssdp_amp_request_is_msearch() -> None:
    req = build_ssdp_amp_request()
    assert b"M-SEARCH" in req
    assert b"ssdp:all" in req
    assert req.startswith(b"M-SEARCH * HTTP/1.1\r\n")


# SPECS


def test_specs_cover_expected_udp_reflectors() -> None:
    assert len(SPECS) == 4
    ports = {s.default_port for s in SPECS}
    assert ports == {123, 11211, 19, 1900}
    for spec in SPECS:
        assert spec.transport == "udp"
        assert spec.is_ot is False  # amplification probes are never flagged OT
        assert spec.is_safe is True  # read-only, single query
        assert callable(spec.probe)


# probers (patched udp I/O)


def _patch_udp(
    monkeypatch: pytest.MonkeyPatch, responder: Callable[[bytes], bytes | None]
) -> None:
    async def fake_udp(host: str, port: int, payload: bytes, timeout: float) -> bytes | None:
        return responder(payload)

    monkeypatch.setattr(amplification, "udp_request", fake_udp)


def test_probe_memcached_flags_reflector(monkeypatch: pytest.MonkeyPatch) -> None:
    reply = b"\x00\x00\x00\x00\x00\x01\x00\x00STAT pid 1\r\nSTAT version 1.6\r\nEND\r\n"
    _patch_udp(monkeypatch, lambda _payload: reply)
    result = asyncio.run(amplification.probe_memcached("10.0.0.1", 11211, 0.1))
    assert result is not None
    assert result.protocol == "memcached"
    assert result.transport == "udp"
    assert result.is_ot is False
    assert result.device_info["reflector"] == "true"
    assert result.device_info["severity"] == "high"
    assert result.device_info["amplification"]
    assert result.device_info["command"] == "stats"


def test_probe_memcached_none_without_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_udp(monkeypatch, lambda _payload: None)
    assert asyncio.run(amplification.probe_memcached("10.0.0.1", 11211, 0.1)) is None


def test_probe_chargen_flags_reflector(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_udp(monkeypatch, lambda _payload: bytes(range(32, 127)))
    result = asyncio.run(amplification.probe_chargen("10.0.0.1", 19, 0.1))
    assert result is not None
    assert result.protocol == "chargen"
    assert result.device_info["severity"] == "medium"
    assert result.device_info["reflector"] == "true"


def test_probe_ssdp_amp_flags_reflector(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_udp(monkeypatch, lambda _payload: b"HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n")
    result = asyncio.run(amplification.probe_ssdp_amp("10.0.0.1", 1900, 0.1))
    assert result is not None
    assert result.protocol == "ssdp-amp"
    assert result.device_info["severity"] == "medium"
    assert result.device_info["reflector"] == "true"


def test_probe_ntp_monlist_high(monkeypatch: pytest.MonkeyPatch) -> None:
    def responder(payload: bytes) -> bytes | None:
        assert payload == build_ntp_monlist_request()  # monlist query reached transport
        return b"\x17\x00\x03\x2a" + b"\x00" * 100  # a (fake) monlist reply

    _patch_udp(monkeypatch, responder)
    result = asyncio.run(amplification.probe_ntp("10.0.0.1", 123, 0.1))
    assert result is not None
    assert result.protocol == "ntp-monlist"
    assert result.device_info["severity"] == "high"
    assert result.device_info["monlist_enabled"] == "true"
    assert result.device_info["cve"] == "CVE-2013-5211"


def test_probe_ntp_falls_back_to_version_liveness(monkeypatch: pytest.MonkeyPatch) -> None:
    monlist = build_ntp_monlist_request()
    version = build_ntp_version_request()

    def responder(payload: bytes) -> bytes | None:
        if payload == monlist:
            return None  # monlist filtered
        if payload == version:
            return b"\x1c" + b"\x00" * 47  # a mode-4 (server) reply
        raise AssertionError("unexpected payload")

    _patch_udp(monkeypatch, responder)
    result = asyncio.run(amplification.probe_ntp("10.0.0.1", 123, 0.1))
    assert result is not None
    assert result.protocol == "ntp"
    assert result.device_info["reflector"] == "false"
    assert result.device_info["monlist_enabled"] == "false"
    assert result.device_info["severity"] == "low"


def test_probe_ntp_none_when_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_udp(monkeypatch, lambda _payload: None)
    assert asyncio.run(amplification.probe_ntp("10.0.0.1", 123, 0.1)) is None


def test_probes_never_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom(host: str, port: int, payload: bytes, timeout: float) -> bytes:
        raise OSError("transport blew up")

    monkeypatch.setattr(amplification, "udp_request", boom)
    assert asyncio.run(amplification.probe_ntp("10.0.0.1", 123, 0.1)) is None
    assert asyncio.run(amplification.probe_memcached("10.0.0.1", 11211, 0.1)) is None
    assert asyncio.run(amplification.probe_chargen("10.0.0.1", 19, 0.1)) is None
    assert asyncio.run(amplification.probe_ssdp_amp("10.0.0.1", 1900, 0.1)) is None
