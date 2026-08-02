"""Tests for the read-only SMB negotiate probe."""

from __future__ import annotations

import struct

from netsec_auditor.protocols.smb import (
    SPECS,
    build_smb1_negotiate,
    build_smb2_negotiate,
    netbios_frame_length,
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


def test_smb2_preauth_salt_is_random() -> None:
    # A constant salt would be a static wire fingerprint for the probe.
    first, second = build_smb2_negotiate(), build_smb2_negotiate()
    assert first != second
    differing = sum(a != b for a, b in zip(first, second, strict=True))
    assert 0 < differing <= 32  # only the 32-byte preauth salt varies


def test_netbios_frame_length_drives_reassembly() -> None:
    pkt = build_smb2_negotiate()
    assert netbios_frame_length(pkt[:3]) is None  # 24-bit length not yet complete
    assert netbios_frame_length(pkt) == len(pkt)


def test_parse_smb2_response_dialect_and_signing() -> None:
    resp = b"\x00\x00\x00\x50" + b"\xfeSMB" + b"\x00" * 60
    resp += struct.pack("<HHH", 65, 0x03, 0x0311)  # structsize, signing req+enabled, 3.1.1
    parsed = parse_smb_negotiate_response(resp)
    assert parsed["dialect"] == "3.1.1"
    assert parsed["signing_required"] == "true"


def _smb1_response(status: int, dialect_index: int) -> bytes:
    header = b"\xffSMB" + b"\x72" + struct.pack("<I", status) + b"\x00" * 23
    body = bytes([17]) + struct.pack("<H", dialect_index) + b"\x00" * 40
    return b"\x00\x00\x00\x30" + header + body


def test_parse_smb1_response_flags_smbv1_when_dialect_negotiated() -> None:
    info = parse_smb_negotiate_response(_smb1_response(0, 5))
    assert info.get("smbv1_supported") == "true"
    assert info.get("dialect") == "NT LM 0.12"


def test_parse_smb1_response_does_not_flag_smbv1_when_dialects_rejected() -> None:
    # SMB1 disabled: the server still answers \xffSMB but negotiates no dialect,
    # so claiming support here would raise a false EternalBlue precondition.
    info = parse_smb_negotiate_response(_smb1_response(0xC0000002, 0xFFFF))
    assert "smbv1_supported" not in info
    assert info.get("dialect") == "none"


def test_parse_smb1_response_without_dialect_words_is_not_smbv1() -> None:
    resp = b"\x00\x00\x00\x30" + b"\xffSMB" + b"\x72" + b"\x00" * 40
    assert "smbv1_supported" not in parse_smb_negotiate_response(resp)


def test_parse_rejects_non_smb() -> None:
    assert parse_smb_negotiate_response(b"garbage") == {}
    assert parse_smb_negotiate_response(b"") == {}


def test_smb_registered() -> None:
    assert any(s.name == "smb" and s.default_port == 445 and s.transport == "tcp" for s in SPECS)
