"""Tests for the SNMP read-only probe (BER encode/decode)."""

from __future__ import annotations

import asyncio

import pytest

from netsec_auditor.protocols import snmp
from netsec_auditor.protocols.snmp import (
    SPECS,
    build_snmp_get,
    parse_snmp_response,
)


def _get_response(descr: bytes) -> bytes:
    """A crafted SNMP GetResponse carrying ``descr`` as sysDescr."""
    oid = bytes([0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    value = bytes([0x04, len(descr)]) + descr
    varbind = bytes([0x30, len(oid) + len(value)]) + oid + value
    vblist = bytes([0x30, len(varbind)]) + varbind
    ints = bytes([0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00])  # id/err/idx
    pdu_body = ints + vblist
    pdu = bytes([0xA2, len(pdu_body)]) + pdu_body
    body = bytes([0x02, 0x01, 0x01]) + bytes([0x04, 0x06]) + b"public" + pdu
    return bytes([0x30, len(body)]) + body


def test_build_snmp_get_structure() -> None:
    pkt = build_snmp_get("public", version=1)
    assert pkt[0] == 0x30              # outer SEQUENCE
    assert b"public" in pkt            # community string present
    assert bytes([0xA0]) in pkt        # GetRequest PDU tag
    # sysDescr OID 1.3.6.1.2.1.1.1.0 encodes with leading 0x2B (1.3).
    assert bytes([0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]) in pkt


def test_parse_snmp_response_roundtrip() -> None:
    assert parse_snmp_response(_get_response(b"TestRouter")).get("value") == "TestRouter"


def test_parse_rejects_non_response() -> None:
    assert parse_snmp_response(b"\x30\x03\x02\x01\x00") == {}
    assert parse_snmp_response(b"garbage") == {}


def test_snmp_registered() -> None:
    assert any(s.name == "snmp" and s.default_port == 161 for s in SPECS)
    assert all(s.transport == "udp" for s in SPECS)


def test_snmp_spec_is_marked_unsafe() -> None:
    # Guessing the "private" read-write community is a default-credential attempt,
    # so the profile gate must be able to suppress it.
    assert all(s.is_safe is False for s in SPECS)


def test_probe_snmp_sends_its_four_attempts_concurrently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inflight = 0
    peak = 0

    async def fake_udp(host: str, port: int, payload: bytes, timeout: float) -> bytes | None:
        nonlocal inflight, peak
        inflight += 1
        peak = max(peak, inflight)
        await asyncio.sleep(0)
        inflight -= 1
        return None

    monkeypatch.setattr(snmp, "udp_request", fake_udp)
    assert asyncio.run(snmp.probe_snmp("10.0.0.1", 161, 0.1)) is None
    assert peak == 4  # a silent host costs one timeout, not four


def test_probe_snmp_prefers_public_v2c(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_udp(host: str, port: int, payload: bytes, timeout: float) -> bytes | None:
        return _get_response(b"TestRouter") if b"public" in payload else None

    monkeypatch.setattr(snmp, "udp_request", fake_udp)
    result = asyncio.run(snmp.probe_snmp("10.0.0.1", 161, 0.1))
    assert result is not None
    assert result.device_info["default_community"] == "public"
    assert result.device_info["version"] == "v2c"
    assert result.device_info["sys_descr"] == "TestRouter"
