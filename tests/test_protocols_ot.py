"""Unit tests for OT/ICS read-only protocol probes.

These exercise the pure ``build_*`` / ``parse_*`` helpers against hand-crafted
byte vectors derived from each protocol specification, and run the async
``probe_*`` functions against in-memory peers. No network I/O is performed.
"""

from __future__ import annotations

import asyncio
import struct
import time

import pytest

from netsec_auditor.protocols import ot

# Modbus/TCP


def test_build_modbus_request_headers() -> None:
    req = ot.build_modbus_request()
    assert struct.unpack(">H", req[2:4])[0] == 0x0000  # MBAP protocol id
    assert struct.unpack(">H", req[4:6])[0] == 5  # length = unit + 4-byte PDU
    assert req[6] == 0xFF  # unit id for a device addressed directly over TCP
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


def test_parse_modbus_rejects_implausible_length_and_function() -> None:
    # An all-zero 8-byte reply has MBAP length 0 and must not fingerprint as OT.
    assert ot.parse_modbus_response(bytes(8)) == {}
    # Length field claiming more bytes than arrived.
    assert ot.parse_modbus_response(struct.pack(">HHHB", 1, 0, 99, 0xFF) + b"\x03") == {}
    # Consistent MBAP but a function code no Modbus device uses.
    assert ot.parse_modbus_response(struct.pack(">HHHB", 1, 0, 2, 0xFF) + b"\x7f") == {}
    # Same framing with a real function code is accepted.
    assert ot.parse_modbus_response(
        struct.pack(">HHHB", 1, 0, 2, 0xFF) + b"\x04"
    ) == {"function_code": "0x04"}


def test_modbus_frame_length_from_mbap() -> None:
    req = ot.build_modbus_request()
    assert ot.modbus_frame_length(req[:3]) is None  # prefix not yet readable
    assert ot.modbus_frame_length(req) == len(req)


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


def test_build_cotp_disconnect_is_a_read_only_teardown() -> None:
    dr = ot.build_cotp_disconnect()
    assert dr == b"\x03\x00\x00\x0b" + bytes((0x06, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00))
    assert dr[0] == 0x03  # TPKT version
    assert dr[5] == 0x80  # COTP Disconnect Request TPDU type


def test_tpkt_frame_length_from_header() -> None:
    cr = ot.build_s7_cotp_cr()
    assert ot.tpkt_frame_length(cr[:3]) is None  # length field not yet complete
    assert ot.tpkt_frame_length(cr) == len(cr)


def _fake_s7_stream(
    monkeypatch: pytest.MonkeyPatch, connection_confirm: bytes
) -> tuple[list[bytes], list[bool]]:
    """Patch open_connection with an in-memory peer; returns (sent frames, closed flag)."""
    sent: list[bytes] = []
    closed: list[bool] = []
    replies = [connection_confirm]

    class _Reader:
        async def read(self, n: int) -> bytes:
            return replies.pop(0) if replies else b""  # then EOF

    class _Writer:
        def write(self, data: bytes) -> None:
            sent.append(data)

        async def drain(self) -> None:
            return None

        def close(self) -> None:
            closed.append(True)

        async def wait_closed(self) -> None:
            return None

    async def fake_open(host: str, port: int) -> tuple[_Reader, _Writer]:
        return _Reader(), _Writer()

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    return sent, closed


def test_s7_exchange_sends_cotp_disconnect_before_closing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # CC: DST-REF 0x0001 (ours), SRC-REF 0x0002 (the PLC's).
    cc = b"\x03\x00\x00\x0b" + bytes((0x06, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00))
    sent, closed = _fake_s7_stream(monkeypatch, cc)
    cotp_ok, _ = asyncio.run(ot._s7_exchange("10.0.0.1", 102, 0.2))
    assert cotp_ok is True
    assert sent[-1] == ot.build_cotp_disconnect(dst_ref=0x0002)  # slot released, not a bare FIN
    assert sent[-1][6:8] == cc[8:10]  # the DR names the PLC's reference, or it is discarded
    assert closed == [True]


def test_s7_exchange_rejects_reply_without_tpkt_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An unrelated binary service on 102 whose 6th byte happens to look like a CC.
    not_tpkt = b"\x16\x03\x01\x00\x51\xd0\x00\x01"
    sent, _ = _fake_s7_stream(monkeypatch, not_tpkt)
    cotp_ok, szl = asyncio.run(ot._s7_exchange("10.0.0.1", 102, 0.2))
    assert cotp_ok is False
    assert szl is None
    assert ot.build_cotp_disconnect() not in sent  # nothing to disconnect


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
    # Unicast confirmed ReadProperty(Device 4194303, Object_Identifier).
    assert req == bytes.fromhex("81 0a 00 11 01 04 00 05 01 0c 0c 02 3f ff ff 19 4b")
    assert struct.unpack(">H", req[2:4])[0] == len(req)  # BVLC length field
    apdu = req[6:]
    assert apdu[0] >> 4 == 0  # Confirmed-Request, so the answer is a unicast ACK
    assert apdu[3] == 0x0C  # service choice 12 = ReadProperty
    assert struct.unpack(">I", apdu[5:9])[0] == (8 << 22) | 4194303  # wildcard Device
    assert apdu[-1] == 75  # property Object_Identifier


def test_bacnet_request_is_not_routed_off_the_target() -> None:
    # A broadcast or routed request is fanned out by a BBMD to its whole distribution
    # table, and a Who-Is is often answered with a broadcast I-Am.
    req = ot.build_bacnet_request()
    assert req[1] == 0x0A  # Original-Unicast-NPDU
    assert req[4:6] == b"\x01\x04"  # NPDU: expecting reply, no DNET/SNET specifiers
    assert req[6:8] != b"\x10\x08"  # not an Unconfirmed-Request Who-Is


def _bacnet_reply(apdu: bytes, npdu: bytes = b"\x01\x00") -> bytes:
    body = npdu + apdu
    return struct.pack(">BBH", 0x81, 0x0A, len(body) + 4) + body


def _read_property_ack(instance: int, invoke_id: int = 1) -> bytes:
    echoed = struct.pack(">I", (8 << 22) | 4194303)  # devices may echo the wildcard
    value = struct.pack(">I", (8 << 22) | instance)
    # ComplexACK/ReadProperty: object id, property id, then the value in tags 3 open/close.
    return (
        bytes((0x30, invoke_id, 0x0C)) + b"\x0c" + echoed + b"\x19\x4b"
        + b"\x3e\xc4" + value + b"\x3f"
    )


def test_parse_bacnet_read_property_ack() -> None:
    info = ot.parse_bacnet_response(_bacnet_reply(_read_property_ack(260)))
    assert info == {
        "response": "complex-ack",
        "object_id": "8:260",
        "device_instance": "260",
    }


def test_parse_bacnet_ack_with_source_specifier() -> None:
    # control 0x08 => source network present; APDU offset must account for it.
    npdu = bytes((0x01, 0x08, 0x00, 0x01, 0x01, 0x0A))  # SNET 0x0001, SLEN 1, SADR 0x0A
    info = ot.parse_bacnet_response(_bacnet_reply(_read_property_ack(7), npdu))
    assert info["device_instance"] == "7"


@pytest.mark.parametrize(
    ("apdu", "expected"),
    [
        (bytes((0x50, 0x01, 0x0C, 0x91, 0x01, 0x91, 0x1F)),
         {"response": "error", "error_class": "1", "error_code": "31"}),
        (bytes((0x60, 0x01, 0x09)), {"response": "reject", "reject_reason": "9"}),
        (bytes((0x71, 0x01, 0x04)), {"response": "abort", "abort_reason": "4"}),
    ],
    ids=["error", "reject", "abort"],
)
def test_parse_bacnet_error_reject_abort_prove_a_bacnet_stack(
    apdu: bytes, expected: dict[str, str]
) -> None:
    assert ot.parse_bacnet_response(_bacnet_reply(apdu)) == expected


def test_parse_bacnet_ignores_replies_to_other_requests() -> None:
    obj = struct.pack(">I", (8 << 22) | 260)
    unsolicited_iam = bytes((0x10, 0x00, 0xC4)) + obj + bytes((0x22, 0x01, 0xE0, 0x91, 0x03))
    assert ot.parse_bacnet_response(_bacnet_reply(unsolicited_iam)) == {}
    assert ot.parse_bacnet_response(_bacnet_reply(_read_property_ack(260, invoke_id=2))) == {}


def test_parse_bacnet_rejects_non_bacnet() -> None:
    assert ot.parse_bacnet_response(b"\x00\x00\x00\x00\x00\x00") == {}


def _vendor_ack(vendor: int, invoke_id: int = 2) -> bytes:
    obj = struct.pack(">I", (8 << 22) | 260)
    value = vendor.to_bytes(max(1, (vendor.bit_length() + 7) // 8), "big")
    # ComplexACK/ReadProperty of Vendor_Identifier (120): an application-tagged Unsigned.
    return (
        bytes((0x30, invoke_id, 0x0C)) + b"\x0c" + obj + b"\x19\x78"
        + b"\x3e" + bytes((0x20 | len(value),)) + value + b"\x3f"
    )


def test_build_bacnet_vendor_request() -> None:
    req = ot.build_bacnet_request(260, 120, 2)
    # Same unicast confirmed ReadProperty, now of Device 260's Vendor_Identifier.
    assert req == bytes.fromhex("81 0a 00 11 01 04 00 05 02 0c 0c 02 00 01 04 19 78")


def test_parse_bacnet_vendor_response() -> None:
    assert ot.parse_bacnet_vendor_response(_bacnet_reply(_vendor_ack(42))) == "42"
    assert ot.parse_bacnet_vendor_response(_bacnet_reply(_vendor_ack(260))) == "260"
    # A reply to the first request, or an Error, carries no vendor identifier.
    assert ot.parse_bacnet_vendor_response(_bacnet_reply(_vendor_ack(42, invoke_id=1))) is None
    error = bytes((0x50, 0x02, 0x0C, 0x91, 0x02, 0x91, 0x20))
    assert ot.parse_bacnet_vendor_response(_bacnet_reply(error)) is None
    assert ot.parse_bacnet_vendor_response(b"\x00" * 8) is None


def _bacnet_device(
    monkeypatch: pytest.MonkeyPatch,
    vendor_reply: bytes | None,
    vendor_delay: float = 0.0,
    first_reply: bytes | None = None,
    vendor_raises: bool = False,
) -> list[bytes]:
    """Patch udp_request with a device answering each ReadProperty by its invoke id."""
    sent: list[bytes] = []

    async def fake_udp(host: str, port: int, payload: bytes, timeout: float) -> bytes | None:
        sent.append(payload)
        if payload[8] == 1:  # invoke id of the Object_Identifier read
            return first_reply or _bacnet_reply(_read_property_ack(260))
        await asyncio.sleep(vendor_delay)
        if vendor_raises:
            raise OSError("vendor read blew up")
        return vendor_reply

    monkeypatch.setattr(ot, "udp_request", fake_udp)
    return sent


def test_probe_bacnet_reads_the_vendor_once_the_instance_is_known(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _bacnet_device(monkeypatch, _bacnet_reply(_vendor_ack(42)))
    result = asyncio.run(ot.probe_bacnet("10.0.0.1", 47808, 0.5))
    assert sent == [ot.build_bacnet_request(), ot.build_bacnet_request(260, 120, 2)]
    assert result is not None
    assert result.is_ot is True
    assert result.banner == "8:260"
    assert result.device_info == {
        "response": "complex-ack",
        "object_id": "8:260",
        "device_instance": "260",
        "vendor_id": "42",
    }


@pytest.mark.parametrize("vendor_raises", [False, True], ids=["no-reply", "raises"])
def test_probe_bacnet_keeps_the_first_result_when_the_vendor_read_fails(
    monkeypatch: pytest.MonkeyPatch, vendor_raises: bool
) -> None:
    sent = _bacnet_device(monkeypatch, None, vendor_raises=vendor_raises)
    result = asyncio.run(ot.probe_bacnet("10.0.0.1", 47808, 0.5))
    assert len(sent) == 2  # the vendor read was attempted
    assert result is not None
    assert result.device_info["device_instance"] == "260"
    assert "vendor_id" not in result.device_info


def test_probe_bacnet_vendor_read_stays_inside_the_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _bacnet_device(monkeypatch, _bacnet_reply(_vendor_ack(42)), vendor_delay=5.0)
    started = time.perf_counter()
    result = asyncio.run(ot.probe_bacnet("10.0.0.1", 47808, 0.3))
    assert time.perf_counter() - started < 0.3 + 0.2  # cut at the probe's own deadline
    assert len(sent) == 2
    assert result is not None
    assert result.device_info["device_instance"] == "260"
    assert "vendor_id" not in result.device_info


def test_probe_bacnet_skips_the_vendor_read_without_an_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = _bacnet_reply(bytes((0x50, 0x01, 0x0C, 0x91, 0x01, 0x91, 0x1F)))
    sent = _bacnet_device(monkeypatch, _bacnet_reply(_vendor_ack(42)), first_reply=error)
    result = asyncio.run(ot.probe_bacnet("10.0.0.1", 47808, 0.5))
    assert sent == [ot.build_bacnet_request()]
    assert result is not None
    assert result.device_info["response"] == "error"


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


def test_parse_dnp3_rejects_bad_crc() -> None:
    # Any service whose reply starts 05 64 would otherwise be flagged is_ot.
    header = struct.pack("<BBBBHH", 0x05, 0x64, 0x05, 0x0B, 4, 1)
    assert ot.parse_dnp3_response(header + struct.pack("<H", 0x0000)) == {}
    assert ot.parse_dnp3_response(header + b"\xff\xff") == {}
    # The same header with the correct CRC is still accepted.
    good = header + struct.pack("<H", ot.dnp3_crc(header))
    assert ot.parse_dnp3_response(good)["dnp3"] == "detected"


def _fake_dnp3_outstation(
    monkeypatch: pytest.MonkeyPatch, address: int | None, hang_up: bool = False
) -> list[list[bytes]]:
    """Patch open_connection with an outstation answering only frames for ``address``.

    Returns the frames written, one list per TCP connection opened.
    """
    connections: list[list[bytes]] = []

    async def fake_open(host: str, port: int, **kwargs: object) -> tuple[object, object]:
        frames: list[bytes] = []
        connections.append(frames)
        replies: asyncio.Queue[bytes] = asyncio.Queue()

        class _Reader:
            async def read(self, n: int) -> bytes:
                if hang_up:
                    return b""
                return await replies.get()  # silent until a matching frame arrives

            def at_eof(self) -> bool:
                return hang_up

        class _Writer:
            def write(self, data: bytes) -> None:
                frames.append(data)
                if struct.unpack("<H", data[4:6])[0] == address:
                    header = struct.pack("<BBBBHH", 0x05, 0x64, 0x05, 0x0B, 0, address)
                    replies.put_nowait(header + struct.pack("<H", ot.dnp3_crc(header)))

            async def drain(self) -> None:
                return None

            def close(self) -> None:
                return None

            async def wait_closed(self) -> None:
                return None

        return _Reader(), _Writer()

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    return connections


def test_probe_dnp3_sweeps_link_addresses_on_one_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An outstation at address 4 discards every other address, so a dst=0-only
    # probe would time out against it.
    connections = _fake_dnp3_outstation(monkeypatch, address=4)
    result = asyncio.run(ot.probe_dnp3("10.0.0.1", 20000, 0.6))
    assert result is not None
    assert result.is_ot is True
    assert result.device_info["source"] == "4"
    # One session: single-connection outstations would otherwise contend with the master.
    assert len(connections) == 1
    frames = connections[0]
    assert [struct.unpack("<H", f[4:6])[0] for f in frames] == [0, 1, 3, 4]  # stops at 4
    assert all(f[2] == 0x05 and f[3] == 0xC9 for f in frames)  # header-only link status


def test_probe_dnp3_silent_sweep_stays_inside_the_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connections = _fake_dnp3_outstation(monkeypatch, address=None)
    started = time.perf_counter()
    assert asyncio.run(ot.probe_dnp3("10.0.0.1", 20000, 0.3)) is None
    assert time.perf_counter() - started < 0.3 + 0.25
    assert len(connections) == 1
    assert len(connections[0]) == len(ot._DNP3_LINK_ADDRESSES)


def test_probe_dnp3_stops_when_the_outstation_hangs_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connections = _fake_dnp3_outstation(monkeypatch, address=None, hang_up=True)
    assert asyncio.run(ot.probe_dnp3("10.0.0.1", 20000, 0.6)) is None
    assert connections == [[ot.build_dnp3_request(dst=0)]]


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
