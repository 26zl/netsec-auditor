"""SNMP read-only probe — detects agents reachable with default community strings.

A device answering an SNMPv1/v2c GET for the ``public`` or ``private`` community
is a classic enterprise finding (information disclosure, and often write access
on ``private``). This probe only issues GET requests — never SET — and returns
the system description. The BER/ASN.1 encoding is done by hand so no third-party
SNMP library is required. Pure ``build_snmp_get``/``parse_snmp_response`` helpers
make it unit-testable without a network.
"""

from __future__ import annotations

from netsec_auditor.protocols.base import ProbeResult, ProbeSpec, udp_request

SNMP_PORT = 161
_SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"
_DEFAULT_COMMUNITIES = ("public", "private")


def _encode_length(length: int) -> bytes:
    """BER definite-length encoding (short form < 128, else long form)."""
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_int(value: int) -> bytes:
    if value == 0:
        return _tlv(0x02, b"\x00")
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if body[0] & 0x80:  # keep it positive
        body = b"\x00" + body
    return _tlv(0x02, body)


def _encode_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])  # first two arcs share one byte
    for arc in parts[2:]:
        chunk = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            chunk.insert(0, (arc & 0x7F) | 0x80)  # 7 bits/byte, high bit = continue
            arc >>= 7
        body.extend(chunk)
    return _tlv(0x06, bytes(body))


def build_snmp_get(community: str, oid: str = _SYS_DESCR_OID, request_id: int = 1,
                   version: int = 1) -> bytes:
    """Build an SNMP GET request (version 0 = v1, 1 = v2c)."""
    varbind = _tlv(0x30, _encode_oid(oid) + b"\x05\x00")  # OID + NULL value
    varbind_list = _tlv(0x30, varbind)
    pdu = _tlv(
        0xA0,  # GetRequest PDU
        _encode_int(request_id) + _encode_int(0) + _encode_int(0) + varbind_list,
    )
    message = _encode_int(version) + _tlv(0x04, community.encode()) + pdu
    return _tlv(0x30, message)


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one BER TLV at offset; returns (tag, value, next_offset)."""
    tag = data[offset]
    length = data[offset + 1]
    pos = offset + 2
    if length & 0x80:  # long-form length
        num = length & 0x7F
        length = int.from_bytes(data[pos:pos + num], "big")
        pos += num
    return tag, data[pos:pos + length], pos + length


def parse_snmp_response(data: bytes) -> dict[str, str]:
    """Extract the first variable-binding value from an SNMP GetResponse."""
    try:
        _, message, _ = _read_tlv(data, 0)          # outer SEQUENCE
        _, _, pos = _read_tlv(message, 0)           # version
        _, _, pos = _read_tlv(message, pos)         # community
        tag, pdu, _ = _read_tlv(message, pos)       # PDU
        if tag != 0xA2:                             # GetResponse expected
            return {}
        _, _, ppos = _read_tlv(pdu, 0)              # request-id
        _, err, ppos = _read_tlv(pdu, ppos)         # error-status
        if err and err[0] != 0:
            return {}
        _, _, ppos = _read_tlv(pdu, ppos)           # error-index
        _, vblist, _ = _read_tlv(pdu, ppos)         # varbind list
        _, vb, _ = _read_tlv(vblist, 0)             # first varbind
        _, _, vpos = _read_tlv(vb, 0)               # OID
        _, value, _ = _read_tlv(vb, vpos)           # value
        return {"value": value.decode("utf-8", "replace").strip()}
    except (IndexError, ValueError):
        return {}


async def probe_snmp(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Probe for an SNMP agent answering a default community string."""
    for community in _DEFAULT_COMMUNITIES:
        for version in (1, 0):  # try v2c then v1
            request = build_snmp_get(community, version=version)
            data = await udp_request(host, port, request, timeout)
            if not data:
                continue
            info = parse_snmp_response(data)
            if not info:
                continue
            return ProbeResult(
                protocol="snmp",
                port=port,
                transport="udp",
                is_ot=False,
                device_info={
                    "default_community": community,
                    "version": "v2c" if version == 1 else "v1",
                    "sys_descr": info.get("value", ""),
                },
                banner=info.get("value", ""),
            )
    return None


SPECS: list[ProbeSpec] = [
    ProbeSpec(name="snmp", default_port=SNMP_PORT, transport="udp", is_ot=False, probe=probe_snmp),
]
