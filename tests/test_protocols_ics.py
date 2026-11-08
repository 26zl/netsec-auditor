"""Unit tests for the further OT/ICS read-only identification probes.

Request bytes are pinned to the reference framings (nmap's ICS scripts and probe
database, and Wireshark's dissectors for IEC 104, KNXnet/IP, FINS, AMS and HART-IP);
reply vectors use the layouts those dissectors decode. Probes run against in-memory
peers, so no test performs any network I/O.
"""

from __future__ import annotations

import asyncio
import dataclasses
import ssl
import struct
import time
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from netsec_auditor import profiles
from netsec_auditor.protocols import ics, probers_for_port
from netsec_auditor.protocols.base import ProbeResult, tcp_request, udp_request
from netsec_auditor.protocols.scan import identify_services

LOCAL = ("10.0.0.9", 50123)
HTTP_REPLY = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"


class _FakeTcpPeer:
    """In-memory TCP peer answering the n-th written message with ``replies[n]``."""

    def __init__(self, replies: list[bytes | None]) -> None:
        self.replies = list(replies)
        self.written: list[bytes] = []
        self.opened: list[dict[str, object]] = []
        self.closed = False

    async def open(self, host: str, port: int, **kwargs: object) -> tuple[Any, Any]:
        self.opened.append(kwargs)
        queue: asyncio.Queue[bytes] = asyncio.Queue()
        peer = self

        class _Reader:
            async def read(self, n: int) -> bytes:
                return await queue.get()  # silent until a reply is queued

            def at_eof(self) -> bool:
                return False

        class _Writer:
            def write(self, data: bytes) -> None:
                peer.written.append(data)
                reply = peer.replies.pop(0) if peer.replies else None
                if reply is not None:
                    queue.put_nowait(reply)

            async def drain(self) -> None:
                return None

            def get_extra_info(self, name: str) -> object:
                return {"sockname": LOCAL, "peername": (host, port)}.get(name)

            def close(self) -> None:
                peer.closed = True

            async def wait_closed(self) -> None:
                return None

        return _Reader(), _Writer()


def _tcp_peer(monkeypatch: pytest.MonkeyPatch, replies: list[bytes | None]) -> _FakeTcpPeer:
    peer = _FakeTcpPeer(replies)
    monkeypatch.setattr(asyncio, "open_connection", peer.open)
    return peer


def _udp_peer(monkeypatch: pytest.MonkeyPatch, reply: bytes | None) -> list[bytes]:
    """Patch datagram endpoints with a connected fake socket answering ``reply``."""
    sent: list[bytes] = []

    async def fake_endpoint(
        loop: asyncio.AbstractEventLoop,
        protocol_factory: Callable[[], asyncio.DatagramProtocol],
        remote_addr: tuple[str, int] | None = None,
        **kwargs: object,
    ) -> tuple[Any, asyncio.DatagramProtocol]:
        protocol = protocol_factory()

        class _Transport:
            def get_extra_info(self, name: str) -> object:
                return {"sockname": LOCAL, "peername": remote_addr}.get(name)

            def sendto(self, data: bytes, addr: object = None) -> None:
                sent.append(data)
                if reply is not None:
                    loop.call_soon(protocol.datagram_received, reply, remote_addr)

            def close(self) -> None:
                return None

        return _Transport(), protocol

    loop_class = asyncio.base_events.BaseEventLoop
    monkeypatch.setattr(loop_class, "create_datagram_endpoint", fake_endpoint)
    return sent


# Shared base helper: requests built from the connected socket


def test_tcp_and_udp_requests_build_payloads_from_the_connected_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[tuple[str, int], tuple[str, int]]] = []

    def builder(local: tuple[str, int], remote: tuple[str, int]) -> bytes:
        seen.append((local, remote))
        return b"hello"

    peer = _tcp_peer(monkeypatch, [b"pong"])
    assert asyncio.run(tcp_request("10.0.0.5", 4000, builder, 0.5)) == b"pong"
    assert peer.written == [b"hello"]
    sent = _udp_peer(monkeypatch, b"pong")
    assert asyncio.run(udp_request("10.0.0.5", 4001, builder, 0.5)) == b"pong"
    assert sent == [b"hello"]
    assert seen == [(LOCAL, ("10.0.0.5", 4000)), (LOCAL, ("10.0.0.5", 4001))]


# IEC 60870-5-104


def test_iec104_request_is_only_a_testfr_act() -> None:
    req = ics.build_iec104_request()
    assert req == bytes.fromhex("68 04 43 00 00 00")  # TESTFR act, as iec-identify opens with
    assert req[2] & 0x03 == 0x03  # U-format APCI
    assert req[2] not in (0x07, 0x13)  # never STARTDT act or STOPDT act


def test_parse_iec104_accepts_only_testfr_con() -> None:
    assert ics.parse_iec104_response(bytes.fromhex("68 04 83 00 00 00")) == {"apci": "TESTFR con"}
    assert ics.parse_iec104_response(bytes.fromhex("68 04 0b 00 00 00")) == {}  # STARTDT con
    assert ics.parse_iec104_response(bytes.fromhex("68 04 83 00")) == {}
    assert ics.parse_iec104_response(HTTP_REPLY) == {}


def test_iec104_frame_length() -> None:
    assert ics.iec104_frame_length(b"\x68") is None
    assert ics.iec104_frame_length(b"\x68\x04") == 6
    assert ics.iec104_frame_length(HTTP_REPLY) == len(HTTP_REPLY)  # not 104: stop reading


def test_probe_iec104_sends_nothing_but_testfr(monkeypatch: pytest.MonkeyPatch) -> None:
    peer = _tcp_peer(monkeypatch, [bytes.fromhex("68 04 83 00 00 00")])
    result = asyncio.run(ics.probe_iec104("10.0.0.5", 2404, 0.5))
    assert peer.written == [ics.build_iec104_request()]
    assert result is not None and result.is_ot and result.protocol == "iec-104"
    assert result.device_info == {"apci": "TESTFR con"}


# Niagara Fox

FOX_REPLY = (
    b"fox a 0 -1 fox hello\n{\n"
    b"fox.version=s:1.0.1\nid=i:255\nhostName=s:xpvm-0omdc01xmy\nhostAddress=s:192.168.1.1\n"
    b"app.name=s:Station\napp.version=s:3.8.311\n"
    b"vm.name=s:Java HotSpot(TM) Embedded Client VM\nvm.version=s:25.141-b06\n"
    b"os.name=s:QNX\nos.version=s:6.5.0\nstation.name=s:BAS_Plant_1\nlang=s:en\n"
    b"timeZone=s:America/Chicago;-21600000;3600000;02:00:00.000,wall,march,8\n"
    b"hostId=s:Qnx-NPM6-0000-1234-5678\nbrandId=s:vykon\n"
    b"sysInfo=o:bog 61[<bog version=\"1.0\">]\n"
    b"};;\n"
)


def test_fox_request_is_the_minimal_hello() -> None:
    assert ics.build_fox_request() == b"fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};;\n"


def test_parse_fox_hello_fields() -> None:
    assert ics.parse_fox_response(FOX_REPLY) == {
        "fox_version": "1.0.1",
        "host_name": "xpvm-0omdc01xmy",
        "host_address": "192.168.1.1",
        "app_name": "Station",
        "app_version": "3.8.311",
        "vm_name": "Java HotSpot(TM) Embedded Client VM",
        "vm_version": "25.141-b06",
        "os_name": "QNX",
        "os_version": "6.5.0",
        "station_name": "BAS_Plant_1",
        "time_zone": "America/Chicago",
        "host_id": "Qnx-NPM6-0000-1234-5678",
        "brand_id": "vykon",
    }


def test_parse_fox_rejects_non_fox_and_strips_control_characters() -> None:
    assert ics.parse_fox_response(HTTP_REPLY) == {}
    assert ics.parse_fox_response(ics.build_fox_request()) == {}  # an echoed request
    hostile = b"fox a 0 -1 fox hello\n{\nstation.name=s:evil\x1b]0;title\x07name\n};;\n"
    assert ics.parse_fox_response(hostile) == {"station_name": "evil]0;titlename"}
    assert ics.parse_fox_response(b"fox a 0 -1 fox hello\n{\n};;\n") == {"hello": "received"}


def test_fox_frame_length() -> None:
    assert ics.fox_frame_length(b"fox a 0 -1 fox") is None
    assert ics.fox_frame_length(FOX_REPLY) == len(FOX_REPLY) - 1  # up to "};;"
    assert ics.fox_frame_length(HTTP_REPLY) == len(HTTP_REPLY)


@pytest.mark.parametrize(
    ("probe", "port", "tls"),
    [(ics.probe_fox, 1911, False), (ics.probe_fox_tls, 4911, True)],
    ids=["plain", "tls"],
)
def test_probe_fox(
    monkeypatch: pytest.MonkeyPatch,
    probe: Callable[[str, int, float], Awaitable[ProbeResult | None]],
    port: int,
    tls: bool,
) -> None:
    peer = _tcp_peer(monkeypatch, [FOX_REPLY])
    result = asyncio.run(probe("10.0.0.5", port, 0.5))
    assert peer.written == [ics.build_fox_request()]
    assert result is not None and result.protocol == "niagara-fox"
    assert result.banner == "Station 3.8.311"
    context = peer.opened[0].get("ssl")
    if tls:
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_NONE and context.check_hostname is False
        assert result.extra == {"tls": True}
    else:
        assert context is None and result.extra == {}


# KNXnet/IP


def _knx_description_response(name: bytes = b"KNX IP Router 752", status: int = 0x01) -> bytes:
    dib = struct.pack(">BBBBH", 54, 0x01, 0x02, status, 0x1101)  # DEVICE_INFO, TP1, 1.1.1
    dib += b"\x00\x00" + bytes.fromhex("00fa12345678")  # project id, serial
    dib += bytes((224, 0, 23, 12)) + bytes.fromhex("00246d012345")  # multicast, MAC
    dib += name.ljust(30, b"\x00")
    families = bytes((8, 0x02, 0x02, 0x01, 0x03, 0x01, 0x04, 0x01))
    body = dib + families
    return struct.pack(">BBHH", 0x06, 0x10, 0x0204, 6 + len(body)) + body


def test_knx_request_names_our_socket_as_control_endpoint() -> None:
    # Header, then HPAI: length 8, IPV4_UDP, 10.0.0.9, port 50123.
    expected = bytes.fromhex("06 10 02 03 00 0e 08 01 0a 00 00 09 c3 cb")
    assert ics.build_knx_request(LOCAL) == expected
    # Without an IPv4 address of our own, the route-back HPAI 0.0.0.0:0 is used.
    assert ics.build_knx_request(("fe80::1", 50123))[-6:] == bytes(6)


def test_parse_knx_description_response() -> None:
    assert ics.parse_knx_response(_knx_description_response()) == {
        "knx_address": "1.1.1",
        "medium": "TP1",
        "serial": "00fa12345678",
        "mac": "00:24:6d:01:23:45",
        "programming_mode": "on",
        "name": "KNX IP Router 752",
    }


def test_parse_knx_rejects_other_messages() -> None:
    good = _knx_description_response()
    assert ics.parse_knx_response(good[:2] + b"\x02\x02" + good[4:]) == {}  # SEARCH_RESPONSE
    assert ics.parse_knx_response(good[:40]) == {}  # truncated DIB
    assert ics.parse_knx_response(good[:6] + b"\x30" + good[7:]) == {}  # wrong DIB length
    assert ics.parse_knx_response(good[:4] + b"\x01\x00" + good[6:]) == {}  # total > datagram
    assert ics.parse_knx_response(HTTP_REPLY * 3) == {}


def test_probe_knx_addresses_its_reply_to_the_connected_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _udp_peer(monkeypatch, _knx_description_response())
    result = asyncio.run(ics.probe_knx("10.0.0.5", 3671, 0.5))
    assert sent == [ics.build_knx_request(LOCAL)]  # unicast, HPAI = our own socket
    assert result is not None and result.transport == "udp" and result.is_ot
    assert result.device_info["name"] == "KNX IP Router 752"


# Omron FINS


def _fins_response(end_code: int = 0x0000, sid: int = 0x5E) -> bytes:
    header = bytes((0xC0, 0x00, 0x02, 0x00, 0x09, 0x00, 0x00, 0x05, 0x00, sid))
    body = b"CJ2M-CPU33".ljust(20, b"\x00") + b"02.01".ljust(20, b"\x00")
    body += bytes(40) + bytes.fromhex("0014 08 8000 00 00 0000 00 0000".replace(" ", ""))
    return header + b"\x05\x01" + end_code.to_bytes(2, "big") + body


def test_fins_request_uses_our_node_number() -> None:
    req = ics.build_fins_request(LOCAL)
    assert req == bytes.fromhex("80 00 02 00 00 00 00 09 00 5e 05 01 00")
    assert req[10:12] == b"\x05\x01"  # Controller Data Read, the only command sent
    assert ics.build_fins_request(("10.0.1.0", 1))[7] == 0x63  # node 0 is invalid
    assert ics.build_fins_request(("10.0.1.255", 1))[7] == 0x63
    assert ics.build_fins_request(("fe80::1", 1))[7] == 0x63


def test_parse_fins_controller_data() -> None:
    assert ics.parse_fins_response(_fins_response()) == {
        "end_code": "0x0000",
        "model": "CJ2M-CPU33",
        "version": "02.01",
    }
    # The CPU error flag bits do not change a normal completion.
    assert ics.parse_fins_response(_fins_response(0x0040))["model"] == "CJ2M-CPU33"
    # An error end code still proves FINS but carries no controller data.
    assert ics.parse_fins_response(_fins_response(0x2108)[:14]) == {"end_code": "0x2108"}


def test_parse_fins_rejects_other_replies() -> None:
    assert ics.parse_fins_response(_fins_response(sid=0x01)) == {}  # not our service id
    assert ics.parse_fins_response(_fins_response()[:10] + b"\x01\x01" + bytes(42)) == {}
    assert ics.parse_fins_response(b"\x80" + _fins_response()[1:]) == {}  # a command
    assert ics.parse_fins_response(HTTP_REPLY) == {}


def test_probe_fins(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _udp_peer(monkeypatch, _fins_response())
    result = asyncio.run(ics.probe_fins("10.0.0.5", 9600, 0.5))
    assert sent == [ics.build_fins_request(LOCAL)]
    assert result is not None and result.protocol == "omron-fins"
    assert result.banner == "CJ2M-CPU33"


# Beckhoff ADS / AMS


def _ads_response(
    error: int = 0, result: int = 0, invoke: int = 0x4E534131, flags: int = 0x0005
) -> bytes:
    data = b"" if error else struct.pack("<IBBH16s", result, 3, 1, 4024, b"TwinCAT System")
    header = struct.pack(
        "<6sH6sHHHIII", bytes((10, 0, 0, 9, 1, 1)), 32905, bytes((5, 12, 34, 56, 1, 1)), 10000,
        0x0001, flags, len(data), error, invoke,
    )
    return struct.pack("<HI", 0, len(header) + len(data)) + header + data


def test_ads_request_is_read_device_info_with_net_ids_from_addresses() -> None:
    req = ics.build_ads_request(LOCAL, ("10.0.0.5", 48898))
    assert req[:6] == struct.pack("<HI", 0, 32)  # AMS/TCP header, 32-byte AMS header only
    target, target_port, source, source_port, command, flags, size, error, _ = struct.unpack(
        "<6sH6sHHHIII", req[6:]
    )
    assert (target, target_port) == (bytes((10, 0, 0, 5, 1, 1)), 10000)
    assert (source, source_port) == (bytes((10, 0, 0, 9, 1, 1)), 32905)
    assert (command, flags, size, error) == (0x0001, 0x0004, 0, 0)  # Read Device Info request


def test_parse_ads_device_info() -> None:
    assert ics.parse_ads_response(_ads_response()) == {
        "ams_net_id": "5.12.34.56.1.1",
        "version": "3.1.4024",
        "device_name": "TwinCAT System",
    }
    # An AMS-level error (e.g. target port not found) still proves an AMS router.
    assert ics.parse_ads_response(_ads_response(error=0x0006)) == {
        "ams_net_id": "5.12.34.56.1.1",
        "ams_error": "0x00000006",
    }
    assert ics.parse_ads_response(_ads_response(result=0x0701))["ads_error"] == "0x00000701"


def test_parse_ads_rejects_other_frames() -> None:
    assert ics.parse_ads_response(_ads_response(invoke=1)) == {}  # not our request
    assert ics.parse_ads_response(_ads_response(flags=0x0004)) == {}  # a request, not a reply
    good = _ads_response()
    assert ics.parse_ads_response(good[:2] + b"\xff\xff\x00\x00" + good[6:]) == {}  # oversized
    assert ics.parse_ads_response(b"\x00\x10" + good[2:]) == {}  # not an AMS command frame
    assert ics.parse_ads_response(HTTP_REPLY) == {}


def test_probe_ads(monkeypatch: pytest.MonkeyPatch) -> None:
    peer = _tcp_peer(monkeypatch, [_ads_response()])
    result = asyncio.run(ics.probe_ads("10.0.0.5", 48898, 0.5))
    assert peer.written == [ics.build_ads_request(LOCAL, ("10.0.0.5", 48898))]
    assert result is not None and result.banner == "TwinCAT System"


# HART-IP


def _hartip_reply(message_id: int, sequence: int, body: bytes = b"", status: int = 0) -> bytes:
    return struct.pack(">BBBBHH", 1, 1, message_id, status, sequence, 8 + len(body)) + body


def _command0_reply(revision: int = 7, checksum_delta: int = 0, response_code: int = 0) -> bytes:
    ident = bytes((0xFE, 0x26, 0x11, 5, revision, 10, 5, 0x0C, 0x00, 0x12, 0x34, 0x56,
                   5, 4, 0x00, 0x01, 0x00, 0x00, 0x26, 0x00, 0x26, 0x01))
    pdu = bytes((0x06, 0x80, 0x00, 2 + len(ident), response_code, 0x00)) + ident
    checksum = 0
    for byte in pdu:
        checksum ^= byte
    return _hartip_reply(3, 2, pdu + bytes(((checksum + checksum_delta) & 0xFF,)))


INITIATE_OK = _hartip_reply(0, 1, bytes((0x01, 0x00, 0x00, 0x4E, 0x20)))


def test_hartip_requests_match_the_reference_framing() -> None:
    assert ics.build_hartip_session_initiate() == bytes.fromhex("010000000001000D0100004E20")
    assert ics.build_hartip_command0() == bytes.fromhex("010003000002000D0280000082")
    assert ics.build_hartip_session_close() == bytes.fromhex("0100010000030008")


def test_parse_hartip_command0() -> None:
    assert ics.parse_hartip_command0(_command0_reply()) == {
        "hart_revision": "7",
        "device_revision": "10",
        "software_revision": "5",
        "device_id": "123456",
        "expanded_device_type": "0x2611",
        "manufacturer_id": "0x0026",
    }
    hart5 = ics.parse_hartip_command0(_command0_reply(revision=5))
    assert (hart5["manufacturer_id"], hart5["device_type"]) == ("0x26", "0x11")


def test_parse_hartip_command0_rejects_invalid_frames() -> None:
    assert ics.parse_hartip_command0(_command0_reply(checksum_delta=1)) == {}
    assert ics.parse_hartip_command0(_command0_reply(response_code=0x40)) == {}
    reply = _command0_reply()
    assert ics.parse_hartip_command0(reply[:8] + b"\x02" + reply[9:]) == {}  # not an ACK
    assert ics.parse_hartip_command0(reply[:3] + b"\x0e" + reply[4:]) == {}  # error status
    assert ics.parse_hartip_command0(HTTP_REPLY) == {}


def test_probe_hartip_opens_reads_identity_and_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    peer = _tcp_peer(monkeypatch, [INITIATE_OK, _command0_reply(), _hartip_reply(1, 3)])
    result = asyncio.run(ics.probe_hartip("10.0.0.5", 5094, 0.5))
    assert peer.written == [
        ics.build_hartip_session_initiate(),
        ics.build_hartip_command0(),
        ics.build_hartip_session_close(),
    ]
    assert peer.closed
    assert result is not None and result.protocol == "hart-ip"
    assert result.device_info["session_status"] == "0"
    assert result.device_info["device_id"] == "123456"
    assert result.banner == "HART-IP device 123456"


def test_probe_hartip_sends_no_command_when_the_session_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = _tcp_peer(monkeypatch, [_hartip_reply(0, 1, status=15)])
    result = asyncio.run(ics.probe_hartip("10.0.0.5", 5094, 0.5))
    assert peer.written == [ics.build_hartip_session_initiate()]
    assert result is not None and result.device_info == {"session_status": "15"}


def test_probe_hartip_keeps_the_session_result_when_command0_times_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer = _tcp_peer(monkeypatch, [INITIATE_OK, None])
    started = time.perf_counter()
    result = asyncio.run(ics.probe_hartip("10.0.0.5", 5094, 0.3))
    assert time.perf_counter() - started < 0.3 + 0.2
    assert peer.written == [ics.build_hartip_session_initiate(), ics.build_hartip_command0()]
    assert result is not None and result.device_info == {"session_status": "0"}


# Phoenix Contact PC Worx


def _pcworx_info_reply() -> bytes:
    reply = bytearray(200)
    reply[:4] = b"\x81\x06\x00\xc8"
    for offset, text in ((30, b"ILC 330 ETH"), (66, b"3.95T"), (79, b"Mar  2 2012"),
                         (91, b"09:39:02"), (152, b"2737193")):
        reply[offset:offset + len(text)] = text
    return bytes(reply)


PCWORX_CONNECT_REPLY = bytes.fromhex("81 01 00 14 00 00 00 01 00 00 00 00 00 02 00 00 00 2a 00 00")


def test_pcworx_requests_match_the_reference_framing() -> None:
    reference = b"\x01\x01\x00\x1a\x00\x00\x00\x00x\x80\x00\x03\x00\x0cIBETH01N0_M\x00"
    assert reference == ics._PCWORX_CONNECT
    setup, read_info = ics.build_pcworx_requests(0x2A)
    assert setup == bytes.fromhex(
        "01 05 00 16 00 01 00 00 78 80 00 2a 00 00 00 06 00 04 02 95 00 00"
    )
    assert read_info == bytes.fromhex("01 06 00 0e 00 02 00 00 00 00 00 2a 04 00")
    assert len(setup) == setup[3] and len(read_info) == read_info[3]  # length fields hold


def test_parse_pcworx_replies() -> None:
    assert ics.parse_pcworx_session(PCWORX_CONNECT_REPLY) == 0x2A
    assert ics.parse_pcworx_session(b"\x81\x02" + PCWORX_CONNECT_REPLY[2:]) is None
    assert ics.parse_pcworx_session(PCWORX_CONNECT_REPLY[:12]) is None
    assert ics.parse_pcworx_info(_pcworx_info_reply()) == {
        "plc_type": "ILC 330 ETH",
        "firmware_version": "3.95T",
        "firmware_date": "Mar  2 2012",
        "firmware_time": "09:39:02",
        "model_number": "2737193",
    }
    assert ics.parse_pcworx_info(HTTP_REPLY) == {}


def test_probe_pcworx_info_exchange(monkeypatch: pytest.MonkeyPatch) -> None:
    peer = _tcp_peer(monkeypatch, [PCWORX_CONNECT_REPLY, b"\x81\x05\x00\x04", _pcworx_info_reply()])
    result = asyncio.run(ics.probe_pcworx("10.0.0.5", 1962, 0.5))
    setup, read_info = ics.build_pcworx_requests(0x2A)  # the session id the PLC assigned
    assert peer.written == [ics._PCWORX_CONNECT, setup, read_info]
    assert result is not None and result.banner == "ILC 330 ETH"
    assert result.device_info["model_number"] == "2737193"


# GE SRTP


def test_srtp_request_and_strict_reply_check() -> None:
    assert ics.build_srtp_request() == bytes(56)
    assert ics.parse_srtp_response(b"\x01" + bytes(55)) == {"init": "acknowledged"}
    assert ics.parse_srtp_response(bytes(56)) == {}  # an echo is not an acknowledgement
    assert ics.parse_srtp_response(b"\x01" + bytes(56)) == {}  # 57 bytes
    assert ics.parse_srtp_response(b"\x01" + bytes(54)) == {}  # 55 bytes


def test_probe_srtp(monkeypatch: pytest.MonkeyPatch) -> None:
    peer = _tcp_peer(monkeypatch, [b"\x01" + bytes(55)])
    result = asyncio.run(ics.probe_srtp("10.0.0.5", 18245, 0.5))
    assert peer.written == [bytes(56)]
    assert result is not None and result.device_info == {"init": "acknowledged"}


# CODESYS V2


def _codesys_reply() -> bytes:
    reply = bytearray(160)
    reply[:4] = b"\xbb\xbb\x01\x00"
    reply[64:64 + 12] = b"Nucleus PLUS"
    reply[96:96 + 28] = b"Nucleus PLUS version unknown"
    reply[128:128 + 27] = b"3S-Smart Software Solutions"
    return bytes(reply)


def test_codesys_request_and_reply() -> None:
    assert ics.build_codesys_request() == bytes.fromhex("bb bb 01 00 00 00 01")
    assert ics.parse_codesys_response(_codesys_reply()) == {
        "target_strings": "Nucleus PLUS; Nucleus PLUS version unknown; 3S-Smart Software Solutions"
    }
    assert ics.parse_codesys_response(b"\xaa" + _codesys_reply()[1:]) == {}  # no 0xBB marker
    assert ics.parse_codesys_response(b"\xbb" + bytes(159)) == {}  # no target strings
    assert ics.parse_codesys_response(_codesys_reply()[:40]) == {}  # too short
    assert ics.parse_codesys_response(HTTP_REPLY * 2) == {}


def test_probe_codesys(monkeypatch: pytest.MonkeyPatch) -> None:
    peer = _tcp_peer(monkeypatch, [_codesys_reply()])
    result = asyncio.run(ics.probe_codesys("10.0.0.5", 2455, 0.5))
    assert peer.written == [ics.build_codesys_request()]
    assert result is not None and result.banner == "Nucleus PLUS"


# Cross-cutting: unrelated services, timeouts, registry


TCP_PROBES = [
    (ics.probe_iec104, 2404),
    (ics.probe_fox, 1911),
    (ics.probe_ads, 48898),
    (ics.probe_hartip, 5094),
    (ics.probe_pcworx, 1962),
    (ics.probe_srtp, 18245),
    (ics.probe_codesys, 1200),
]
TCP_IDS = ["iec104", "fox", "ads", "hartip", "pcworx", "srtp", "codesys"]


@pytest.mark.parametrize(("probe", "port"), TCP_PROBES, ids=TCP_IDS)
def test_tcp_probes_ignore_an_unrelated_service(
    monkeypatch: pytest.MonkeyPatch,
    probe: Callable[[str, int, float], Awaitable[ProbeResult | None]],
    port: int,
) -> None:
    _tcp_peer(monkeypatch, [HTTP_REPLY])
    assert asyncio.run(probe("10.0.0.5", port, 0.2)) is None


@pytest.mark.parametrize(("probe", "port"), TCP_PROBES, ids=TCP_IDS)
def test_tcp_probes_stay_inside_their_timeout(
    monkeypatch: pytest.MonkeyPatch,
    probe: Callable[[str, int, float], Awaitable[ProbeResult | None]],
    port: int,
) -> None:
    _tcp_peer(monkeypatch, [None])  # accepts the connection, never answers
    started = time.perf_counter()
    assert asyncio.run(probe("10.0.0.5", port, 0.2)) is None
    assert time.perf_counter() - started < 0.2 + 0.2


@pytest.mark.parametrize(
    ("probe", "port"), [(ics.probe_knx, 3671), (ics.probe_fins, 9600)], ids=["knx", "fins"]
)
def test_udp_probes_ignore_unrelated_datagrams(
    monkeypatch: pytest.MonkeyPatch,
    probe: Callable[[str, int, float], Awaitable[ProbeResult | None]],
    port: int,
) -> None:
    _udp_peer(monkeypatch, HTTP_REPLY * 3)
    assert asyncio.run(probe("10.0.0.5", port, 0.2)) is None


def test_ics_specs_are_registered_as_ot_with_safety_by_request_count() -> None:
    expected = {
        "iec-104": (2404, "tcp", True),
        "niagara-fox": (1911, "tcp", True),
        "niagara-fox-tls": (4911, "tcp", True),
        "knxnet-ip": (3671, "udp", True),
        "omron-fins": (9600, "udp", True),
        "beckhoff-ads": (48898, "tcp", True),
        "ge-srtp": (18245, "tcp", True),
        "codesys": (1200, "tcp", True),
        "codesys-2455": (2455, "tcp", True),
        "hart-ip": (5094, "tcp", False),  # several requests per probe
        "pcworx": (1962, "tcp", False),
    }
    assert {s.name: (s.default_port, s.transport, s.is_safe) for s in ics.SPECS} == expected
    for spec in ics.SPECS:
        assert spec.is_ot is True
        assert spec.default_port in profiles.OT_PORTS  # the interlock knows every port
        assert spec in probers_for_port(spec.default_port, spec.transport)


def test_ot_profile_skips_the_session_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    dialled: list[int] = []

    async def refuse(host: str, port: int, **kwargs: object) -> tuple[Any, Any]:
        dialled.append(port)
        raise ConnectionRefusedError

    monkeypatch.setattr(asyncio, "open_connection", refuse)
    ports = [2404, 5094, 1962]
    ot_profile = dataclasses.replace(profiles.OT, scan_delay=0.0)
    asyncio.run(identify_services("10.0.0.5", ports, ot_profile, timeout=0.2, udp_ports=[]))
    assert dialled == [2404]
    dialled.clear()
    asyncio.run(identify_services("10.0.0.5", ports, profiles.IT, timeout=0.2, udp_ports=[]))
    assert sorted(dialled) == [1962, 2404, 5094]
