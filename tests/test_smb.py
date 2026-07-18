"""Tests for the read-only SMB negotiate probe."""

from __future__ import annotations

import struct

from netsec_auditor.protocols.smb import (
    SPECS,
    build_smb1_negotiate,
    build_smb2_negotiate,
    parse_smb_negotiate_response,
)


def test_build_smb1_negotiate() -> None:
    pkt = build_smb1_negotiate()
    assert b"\xffSMB" in pkt
    assert pkt[4:8] == b"\xffSMB"          # after the 4-byte NetBIOS header
    assert pkt[8] == 0x72                  # SMB_COM_NEGOTIATE
    assert b"NT LM 0.12" in pkt


def test_build_smb2_negotiate() -> None:
    pkt = build_smb2_negotiate()
    assert pkt[4:8] == b"\xfeSMB"
    for dialect in (0x0202, 0x0311):
        assert struct.pack("<H", dialect) in pkt


def test_parse_smb2_response_dialect_and_signing() -> None:
    resp = b"\x00\x00\x00\x50" + b"\xfeSMB" + b"\x00" * 60
    resp += struct.pack("<HHH", 65, 0x03, 0x0311)  # structsize, signing req+enabled, 3.1.1
    parsed = parse_smb_negotiate_response(resp)
    assert parsed["dialect"] == "3.1.1"
    assert parsed["signing_required"] == "true"


def test_parse_smb1_response_flags_smbv1() -> None:
    resp = b"\x00\x00\x00\x30" + b"\xffSMB" + b"\x72" + b"\x00" * 40
    assert parse_smb_negotiate_response(resp).get("smbv1_supported") == "true"


def test_parse_rejects_non_smb() -> None:
    assert parse_smb_negotiate_response(b"garbage") == {}
    assert parse_smb_negotiate_response(b"") == {}


def test_smb_registered() -> None:
    assert any(s.name == "smb" and s.default_port == 445 and s.transport == "tcp" for s in SPECS)
