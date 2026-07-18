"""Unit tests for OT/ICS read-only protocol probes.

These exercise only the pure ``build_*`` / ``parse_*`` helpers against
hand-crafted byte vectors derived from each protocol specification. No network
I/O is performed here; the async ``probe_*`` functions are covered indirectly
through their build/parse building blocks.
"""

from __future__ import annotations

import struct

from netsec_auditor.protocols import ot

# Modbus/TCP


def test_build_modbus_request_headers() -> None:
    req = ot.build_modbus_request()
    assert struct.unpack(">H", req[2:4])[0] == 0x0000  # MBAP protocol id
    assert struct.unpack(">H", req[4:6])[0] == 5  # length = unit + 4-byte PDU
    assert req[7] == 0x2B  # function code: Read Device Identification
    assert req[8] == 0x0E  # MEI type
    assert req[9] == 0x01  # read device id code = basic


def test_parse_modbus_device_id() -> None:
    objects = [(0x00, b"Acme Controls"), (0x01, b"AB-1234"), (0x02, b"1.2")]
    pdu = bytes((0x2B, 0x0E, 0x01, 0x81, 0x00, 0x00, len(objects)))
    for obj_id, value in objects:
        pdu += bytes((obj_id, len(value))) + value
    header = struct.pack(">HHHB", 1, 0x0000, len(pdu) + 1, 0)
    info = ot.parse_modbus_response(header + pdu)
    assert info == {
        "vendor": "Acme Controls",
        "product_code": "AB-1234",
        "version": "1.2",
    }


def test_parse_modbus_report_slave_id() -> None:
    body = bytes((0xAA, 0xFF)) + b"S7-CPU"
    pdu = bytes((0x11, len(body))) + body
    header = struct.pack(">HHHB", 1, 0x0000, len(pdu) + 1, 0)
    info = ot.parse_modbus_response(header + pdu)
    assert info["slave_id"] == "0xaa"
    assert info["run_status"] == "on"
    assert info["additional"] == "S7-CPU"


def test_parse_modbus_rejects_non_modbus() -> None:
    # Protocol id != 0 must be rejected.
    assert ot.parse_modbus_response(struct.pack(">HHHB", 1, 0x0001, 5, 0) + b"\x2b") == {}
    assert ot.parse_modbus_response(b"\x00") == {}


# Siemens S7comm


def test_build_s7_cotp_cr_headers() -> None:
    cr = ot.build_s7_cotp_cr()
    assert cr[0] == 0x03  # TPKT version
    assert cr[5] == 0xE0  # COTP Connection Request PDU type
    assert 0xC1 in cr and 0xC2 in cr  # calling/called TSAP parameters present


def test_build_s7_szl_request_headers() -> None:
    req = ot.build_s7_szl_request(0x001C, 0x0000)
    assert req[7] == 0x32  # S7 protocol id
    assert req[8] == 0x07  # ROSCTR = Userdata
    assert req[-4:-2] == b"\x00\x1c"  # SZL-ID in the request data block


def _s7_szl_1c_response(records: list[tuple[int, bytes]]) -> bytes:
    rec_len = 34  # 2-byte index + 32-byte string
    body = b""
    for index, text in records:
        body += struct.pack(">H", index) + text.ljust(32, b"\x00")
    block = struct.pack(
        ">BBHHHHH", 0xFF, 0x09, len(body) + 8, 0x001C, 0x0000, rec_len, len(records)
    ) + body
    param = bytes.fromhex("000112081284010000000000")  # 12-byte userdata response parameter
    header = struct.pack(">BBHHHH", 0x32, 0x07, 0x0000, 0x0200, len(param), len(block))
    s7 = header + param + block
    cotp = b"\x02\xf0\x80"
    return struct.pack(">BBH", 0x03, 0x00, 4 + len(cotp) + len(s7)) + cotp + s7


def test_parse_s7_szl_component_identification() -> None:
    response = _s7_szl_1c_response(
        [
            (0x0001, b"SIMATIC 300 station"),
            (0x0005, b"S C-J2U000012345"),
            (0x0007, b"CPU 315-2 PN/DP"),
        ]
    )
    info = ot.parse_s7_szl_response(response)
    assert info == {
        "system_name": "SIMATIC 300 station",
        "serial": "S C-J2U000012345",
        "module_type": "CPU 315-2 PN/DP",
    }


def test_parse_s7_rejects_garbage() -> None:
    assert ot.parse_s7_szl_response(b"\x00\x00\x00\x04junk") == {}
    assert ot.parse_s7_szl_response(b"") == {}


# EtherNet/IP (CIP)


def test_build_enip_request() -> None:
    req = ot.build_enip_request()
    assert len(req) == 24
    assert struct.unpack("<H", req[:2])[0] == 0x0063  # ListIdentity command
    assert struct.unpack("<H", req[2:4])[0] == 0  # no command-specific data


def _enip_list_identity_response(name: bytes) -> bytes:
    identity = struct.pack("<H", 1)  # encapsulation protocol version
    identity += bytes(16)  # socket address (ignored by the parser)
    identity += struct.pack("<H", 1)  # vendor id
    identity += struct.pack("<H", 14)  # device type
    identity += struct.pack("<H", 54)  # product code
    identity += bytes((2, 11))  # revision major.minor
    identity += struct.pack("<H", 0x0060)  # status
    identity += struct.pack("<I", 0x00A1B2C3)  # serial number
    identity += bytes((len(name),)) + name  # product name
    identity += bytes((3,))  # device state
    item = struct.pack("<HH", 0x000C, len(identity)) + identity
    body = struct.pack("<H", 1) + item  # item count = 1
    header = struct.pack("<HHII8sI", 0x0063, len(body), 0, 0, b"\x00" * 8, 0)
    return header + body


def test_parse_enip_identity() -> None:
    info = ot.parse_enip_response(_enip_list_identity_response(b"1756-L61/B LOGIX5561"))
    assert info == {
        "vendor_id": "1",
        "device_type": "14",
        "product_code": "54",
        "revision": "2.11",
        "serial": "0x00a1b2c3",
        "product_name": "1756-L61/B LOGIX5561",
    }


def test_parse_enip_rejects_wrong_command() -> None:
    bad = struct.pack("<HHII8sI", 0x0004, 0, 0, 0, b"\x00" * 8, 0)
    assert ot.parse_enip_response(bad) == {}


# BACnet/IP


def test_build_bacnet_request() -> None:
    req = ot.build_bacnet_request()
    assert req[0] == 0x81  # BVLC type BACnet/IP
    assert req[1] == 0x0B  # Original-Broadcast-NPDU
    assert struct.unpack(">H", req[2:4])[0] == len(req)  # BVLC length field
    assert req[-2:] == b"\x10\x08"  # Unconfirmed-Request Who-Is APDU


def _bacnet_iam_response(instance: int, vendor: int) -> bytes:
    obj = (8 << 22) | instance  # object type 8 = device
    apdu = bytes((0x10, 0x00))  # Unconfirmed-Request / I-Am
    apdu += bytes((0xC4,)) + struct.pack(">I", obj)  # tag 12, length 4: object identifier
    apdu += bytes((0x22, 0x01, 0xE0))  # tag 2 unsigned: max APDU accepted
    apdu += bytes((0x91, 0x03))  # tag 9 enumerated: segmentation supported
    apdu += bytes((0x21, vendor))  # tag 2 unsigned: vendor id
    npdu = bytes((0x01, 0x00))  # version 1, control 0 (no dest/src specifiers)
    body = npdu + apdu
    return struct.pack(">BBH", 0x81, 0x0A, len(body) + 4) + body


def test_parse_bacnet_iam() -> None:
    info = ot.parse_bacnet_response(_bacnet_iam_response(260, 99))
    assert info == {
        "object_id": "8:260",
        "device_instance": "260",
        "vendor_id": "99",
    }


def test_parse_bacnet_iam_with_source_specifier() -> None:
    # control 0x08 => source network present; APDU offset must account for it.
    obj = (8 << 22) | 7
    apdu = bytes((0x10, 0x00, 0xC4)) + struct.pack(">I", obj)
    apdu += bytes((0x22, 0x01, 0xE0, 0x91, 0x03, 0x21, 0x2A))
    npdu = bytes((0x01, 0x08, 0x00, 0x01, 0x01, 0x0A))  # SNET 0x0001, SLEN 1, SADR 0x0A
    body = npdu + apdu
    packet = struct.pack(">BBH", 0x81, 0x0A, len(body) + 4) + body
    info = ot.parse_bacnet_response(packet)
    assert info["device_instance"] == "7"
    assert info["vendor_id"] == "42"


def test_parse_bacnet_rejects_non_bacnet() -> None:
    assert ot.parse_bacnet_response(b"\x00\x00\x00\x00\x00\x00") == {}


# DNP3


def test_dnp3_crc_reference_vector() -> None:
    # CRC-16/DNP check value for the ASCII string "123456789".
    assert ot.dnp3_crc(b"123456789") == 0xEA82


def test_build_dnp3_request() -> None:
    frame = ot.build_dnp3_request(dst=4, src=1)
    assert frame[0] == 0x05 and frame[1] == 0x64  # DNP3 start octets
    assert frame[2] == 0x05  # length (control + addresses)
    assert frame[3] == 0xC9  # control: DIR|PRM, request-link-status (FC 9)
    assert struct.unpack("<H", frame[8:10])[0] == ot.dnp3_crc(frame[:8])  # trailing CRC


def test_parse_dnp3_response() -> None:
    header = struct.pack("<BBBBHH", 0x05, 0x64, 0x05, 0x0B, 4, 1)  # link status, dst 4, src 1
    frame = header + struct.pack("<H", ot.dnp3_crc(header))
    info = ot.parse_dnp3_response(frame)
    assert info["dnp3"] == "detected"
    assert info["source"] == "1"
    assert info["destination"] == "4"
    assert info["link_function"] == "0x0b"
    assert info["direction"] == "outstation"


def test_parse_dnp3_rejects_non_dnp3() -> None:
    assert ot.parse_dnp3_response(b"\x00\x64\x05\xc9\x00\x00\x00\x00") == {}


# OPC-UA


def test_build_opcua_request() -> None:
    url = "opc.tcp://plc.local:4840"
    req = ot.build_opcua_request(url)
    assert req[:4] == b"HELF"  # Hello message, final chunk
    assert struct.unpack("<I", req[4:8])[0] == len(req)  # message size field
    assert url.encode() in req  # endpoint URL carried in the body


def test_parse_opcua_acknowledge() -> None:
    body = struct.pack("<IIIII", 0, 65536, 65536, 16777216, 5000)
    msg = b"ACKF" + struct.pack("<I", 8 + len(body)) + body
    info = ot.parse_opcua_response(msg)
    assert info["message_type"] == "ACK"
    assert info["protocol_version"] == "0"
    assert info["receive_buffer"] == "65536"
    assert info["send_buffer"] == "65536"


def test_parse_opcua_error() -> None:
    reason = b"Bad_TcpEndpointUrlInvalid"
    body = struct.pack("<Ii", 0x80830000, len(reason)) + reason
    msg = b"ERRF" + struct.pack("<I", 8 + len(body)) + body
    info = ot.parse_opcua_response(msg)
    assert info["message_type"] == "ERR"
    assert info["error_code"] == "0x80830000"
    assert info["reason"] == "Bad_TcpEndpointUrlInvalid"


def test_parse_opcua_rejects_non_opcua() -> None:
    assert ot.parse_opcua_response(b"HTTP/1.1") == {}


# Registry metadata


def test_specs_are_ot_and_safe() -> None:
    assert len(ot.SPECS) >= 5
    for spec in ot.SPECS:
        assert spec.is_ot is True
        assert spec.is_safe is True
        assert spec.transport in ("tcp", "udp")
        assert callable(spec.probe)


def test_spec_names_unique() -> None:
    names = [spec.name for spec in ot.SPECS]
    assert len(names) == len(set(names))
