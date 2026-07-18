"""Tests for the SNMP read-only probe (BER encode/decode)."""

from __future__ import annotations

from netsec_auditor.protocols.snmp import (
    SPECS,
    build_snmp_get,
    parse_snmp_response,
)


def test_build_snmp_get_structure() -> None:
    pkt = build_snmp_get("public", version=1)
    assert pkt[0] == 0x30              # outer SEQUENCE
    assert b"public" in pkt            # community string present
    assert bytes([0xA0]) in pkt        # GetRequest PDU tag
    # sysDescr OID 1.3.6.1.2.1.1.1.0 encodes with leading 0x2B (1.3).
    assert bytes([0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]) in pkt


def test_parse_snmp_response_roundtrip() -> None:
    # A crafted GetResponse carrying sysDescr = "TestRouter".
    descr = b"TestRouter"
    oid = bytes([0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    value = bytes([0x04, len(descr)]) + descr
    varbind = bytes([0x30, len(oid) + len(value)]) + oid + value
    vblist = bytes([0x30, len(varbind)]) + varbind
    ints = bytes([0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00])  # id/err/idx
    pdu_body = ints + vblist
    pdu = bytes([0xA2, len(pdu_body)]) + pdu_body
    community = bytes([0x04, 0x06]) + b"public"
    version = bytes([0x02, 0x01, 0x01])
    body = version + community + pdu
    message = bytes([0x30, len(body)]) + body

    parsed = parse_snmp_response(message)
    assert parsed.get("value") == "TestRouter"


def test_parse_rejects_non_response() -> None:
    assert parse_snmp_response(b"\x30\x03\x02\x01\x00") == {}
    assert parse_snmp_response(b"garbage") == {}


def test_snmp_registered() -> None:
    assert any(s.name == "snmp" and s.default_port == 161 for s in SPECS)
    assert all(s.transport == "udp" for s in SPECS)
