"""Further OT/ICS read-only identification probes.

IEC 60870-5-104 telecontrol, Niagara Fox and KNXnet/IP building automation, and the
Omron FINS, Beckhoff ADS, HART-IP, Phoenix Contact PC Worx, GE SRTP and CODESYS V2
controller protocols. Each probe sends only unicast identification requests to its
one target (nothing that writes, starts or stops, activates data transfer, logs in
or broadcasts), validates replies strictly so an unrelated service on the port
yields no result, and finishes within its timeout.

The conventions follow :mod:`netsec_auditor.protocols.ot`: pure ``build_*`` /
``parse_*`` helpers, and an ``async probe_*`` that never raises.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import re
import ssl
import struct

from netsec_auditor.protocols.base import (
    ProbeResult,
    ProbeSpec,
    read_framed,
    tcp_request,
    udp_request,
)

_MAX_TEXT = 128


def _printable(raw: bytes, limit: int = _MAX_TEXT) -> str:
    """Decode a NUL-terminated or padded field, keeping printable characters only."""
    text = raw.split(b"\x00", 1)[0].decode("latin-1")
    return "".join(ch for ch in text if ch.isprintable()).strip()[:limit]


def _result(
    protocol: str,
    port: int,
    transport: str,
    info: dict[str, str],
    banner: str,
    extra: dict[str, object] | None = None,
) -> ProbeResult:
    return ProbeResult(
        protocol=protocol,
        port=port,
        transport=transport,
        is_ot=True,
        device_info=info,
        banner=banner,
        extra=extra or {},
    )


def _unverified_tls_context() -> ssl.SSLContext:
    """Client context without certificate checks; the probe only identifies the station."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


# IEC 60870-5-104 (port 2404, TCP)

IEC104_PORT = 2404
_IEC104_START = 0x68
_IEC104_TESTFR_CON = bytes((0x68, 0x04, 0x83, 0x00, 0x00, 0x00))


def build_iec104_request() -> bytes:
    """U-format TESTFR act, a link test only.

    STARTDT is never sent: on a redundant RTU it can take the active connection away
    from the SCADA master, and without it no ASDU or data transfer ever flows.
    """
    return bytes((_IEC104_START, 0x04, 0x43, 0x00, 0x00, 0x00))


def iec104_frame_length(data: bytes) -> int | None:
    """APDU size from its length octet; a reply not starting 0x68 ends at once."""
    if not data:
        return None
    if data[0] != _IEC104_START:
        return len(data)
    return 2 + data[1] if len(data) >= 2 else None


def parse_iec104_response(data: bytes) -> dict[str, str]:
    """Report the TESTFR con only an IEC 104 station sends; ``{}`` otherwise."""
    if data[:6] != _IEC104_TESTFR_CON:
        return {}
    return {"apci": "TESTFR con"}


async def probe_iec104(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Detect an IEC 60870-5-104 station via TESTFR act / con (presence only)."""
    try:
        reply = await asyncio.wait_for(
            tcp_request(
                host, port, build_iec104_request(), timeout, frame_length=iec104_frame_length
            ),
            timeout,
        )
    except Exception:
        return None
    info = parse_iec104_response(reply) if reply else {}
    return _result("iec-104", port, "tcp", info, "IEC 60870-5-104") if info else None


# Niagara Fox (port 1911, TCP; 4911 over TLS)

FOX_PORT = 1911
FOX_TLS_PORT = 4911
_FOX_HELLO = b"fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};;\n"
_FOX_FIELDS = {
    b"fox.version": "fox_version",
    b"station.name": "station_name",
    b"hostName": "host_name",
    b"hostAddress": "host_address",
    b"app.name": "app_name",
    b"app.version": "app_version",
    b"vm.name": "vm_name",
    b"vm.version": "vm_version",
    b"os.name": "os_name",
    b"os.version": "os_version",
    b"brandId": "brand_id",
    b"hostId": "host_id",
    b"timeZone": "time_zone",
    b"fatal": "fatal",
}


def build_fox_request() -> bytes:
    """The minimal Fox hello a client opens with; it carries no credentials."""
    return _FOX_HELLO


def fox_frame_length(data: bytes) -> int | None:
    """A Fox message ends with ``};;``; a reply not starting ``fox `` ends at once."""
    if len(data) >= 4 and not data.startswith(b"fox "):
        return len(data)
    end = data.find(b"};;")
    return end + 3 if end >= 0 else None


def parse_fox_response(data: bytes) -> dict[str, str]:
    """Extract the station's key=type:value hello fields; ``{}`` when not Fox."""
    if not data.startswith(b"fox a 0") or b"fox hello" not in data.split(b"\n", 1)[0]:
        return {}
    start = data.find(b"{")
    if start < 0:
        return {}
    info: dict[str, str] = {}
    for line in data[start + 1:].split(b"\n"):
        if line.startswith(b"}"):
            break
        key, _, typed = line.partition(b"=")
        kind, sep, value = typed.partition(b":")
        name = _FOX_FIELDS.get(key)
        if name is None or not sep or kind not in (b"s", b"i"):
            continue
        text = _printable(value)
        if name == "time_zone":
            text = text.split(";", 1)[0]  # the zone name, without its DST rules
        if text:
            info[name] = text
    return info or {"hello": "received"}


async def _run_fox(host: str, port: int, timeout: float, *, tls: bool) -> ProbeResult | None:
    context = _unverified_tls_context() if tls else None
    try:
        reply = await asyncio.wait_for(
            tcp_request(
                host, port, build_fox_request(), timeout,
                frame_length=fox_frame_length, ssl_context=context,
            ),
            timeout,
        )
    except Exception:
        return None
    info = parse_fox_response(reply) if reply else {}
    if not info:
        return None
    banner = " ".join(v for v in (info.get("app_name"), info.get("app_version")) if v)
    return _result(
        "niagara-fox", port, "tcp", info, banner or "Niagara Fox",
        {"tls": True} if tls else None,
    )


async def probe_fox(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify a Niagara station from its reply to the Fox hello."""
    return await _run_fox(host, port, timeout, tls=False)


async def probe_fox_tls(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify a Niagara station from its Fox hello reply over TLS."""
    return await _run_fox(host, port, timeout, tls=True)


# KNXnet/IP (port 3671, UDP)

KNX_PORT = 3671
_KNX_DESCRIPTION_REQUEST = 0x0203
_KNX_DESCRIPTION_RESPONSE = 0x0204
_KNX_DEVICE_INFO_LENGTH = 54
_KNX_MEDIA = {0x02: "TP1", 0x04: "PL110", 0x10: "RF", 0x20: "IP"}


def build_knx_request(local: tuple[str, int]) -> bytes:
    """Unicast DESCRIPTION_REQUEST whose control endpoint is our own UDP socket.

    A non-IPv4 local address falls back to the 0.0.0.0:0 route-back HPAI, which tells
    the server to answer the source of the datagram instead.
    """
    host, port = local
    try:
        address = ipaddress.IPv4Address(host).packed
    except ValueError:
        address, port = bytes(4), 0
    hpai = struct.pack(">BB4sH", 0x08, 0x01, address, port)  # length, IPV4_UDP, ip, port
    return struct.pack(">BBHH", 0x06, 0x10, _KNX_DESCRIPTION_REQUEST, 6 + len(hpai)) + hpai


def parse_knx_response(data: bytes) -> dict[str, str]:
    """Read the device-information DIB of a DESCRIPTION_RESPONSE; ``{}`` otherwise."""
    if len(data) < 6 + _KNX_DEVICE_INFO_LENGTH:
        return {}
    header_len, version, service, total = struct.unpack(">BBHH", data[:6])
    if (header_len, version, service) != (0x06, 0x10, _KNX_DESCRIPTION_RESPONSE):
        return {}
    if not 6 + _KNX_DEVICE_INFO_LENGTH <= total <= len(data):
        return {}
    dib = data[6:6 + _KNX_DEVICE_INFO_LENGTH]
    if dib[0] != _KNX_DEVICE_INFO_LENGTH or dib[1] != 0x01:  # DEVICE_INFO DIB
        return {}
    address = int.from_bytes(dib[4:6], "big")
    info = {
        "knx_address": f"{address >> 12}.{(address >> 8) & 0x0F}.{address & 0xFF}",
        "medium": _KNX_MEDIA.get(dib[2], f"0x{dib[2]:02x}"),
        "serial": dib[8:14].hex(),
        "mac": ":".join(f"{b:02x}" for b in dib[18:24]),
        "programming_mode": "on" if dib[3] & 0x01 else "off",
    }
    name = _printable(dib[24:54])
    if name:
        info["name"] = name
    return info


async def probe_knx(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify a KNXnet/IP server via a unicast DESCRIPTION_REQUEST."""
    try:
        reply = await asyncio.wait_for(
            udp_request(host, port, lambda local, _remote: build_knx_request(local), timeout),
            timeout,
        )
    except Exception:
        return None
    info = parse_knx_response(reply) if reply else {}
    return _result("knxnet-ip", port, "udp", info, info.get("name", "KNXnet/IP")) if info else None


# Omron FINS (port 9600, UDP)

FINS_PORT = 9600
_FINS_SID = 0x5E
_FINS_FALLBACK_NODE = 0x63


def _fins_node(host: str) -> int:
    """The FINS node our address implies: its last octet, as automatic generation maps."""
    try:
        node = ipaddress.IPv4Address(host).packed[3]
    except ValueError:
        return _FINS_FALLBACK_NODE
    return node if 0 < node < 255 else _FINS_FALLBACK_NODE


def build_fins_request(local: tuple[str, int]) -> bytes:
    """Controller Data Read (05 01) of the model and version from the CPU unit.

    The source node is our own address's last octet, so a PLC that learns node
    addresses from incoming frames maps that node to us instead of remapping a node
    another device uses, and a PLC that derives reply addresses from it answers us.
    """
    node = _fins_node(local[0])
    # ICF (command, response required), RSV, GCT, DNA/DA1/DA2 = local CPU unit,
    # SNA, SA1 = our node, SA2, SID.
    header = bytes((0x80, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, node, 0x00, _FINS_SID))
    return header + bytes((0x05, 0x01, 0x00))  # MRC/SRC 05 01 Controller Data Read, data 00


def parse_fins_response(data: bytes) -> dict[str, str]:
    """Read the end code and controller model/version of a 05 01 response."""
    if len(data) < 14 or data[0] not in (0xC0, 0xC1) or data[1] != 0x00:
        return {}
    if data[9] != _FINS_SID or data[10:12] != b"\x05\x01":
        return {}
    end_code = int.from_bytes(data[12:14], "big")
    info = {"end_code": f"0x{end_code:04x}"}
    # Normal completion, ignoring the relay and CPU error flag bits.
    if end_code & 0x7F3F == 0 and len(data) >= 54:
        model, version = _printable(data[14:34]), _printable(data[34:54])
        if model:
            info["model"] = model
        if version:
            info["version"] = version
    return info


async def probe_fins(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify an Omron PLC via FINS Controller Data Read."""
    try:
        reply = await asyncio.wait_for(
            udp_request(host, port, lambda local, _remote: build_fins_request(local), timeout),
            timeout,
        )
    except Exception:
        return None
    info = parse_fins_response(reply) if reply else {}
    if not info:
        return None
    return _result("omron-fins", port, "udp", info, info.get("model", "Omron FINS"))


# Beckhoff ADS / AMS (port 48898, TCP)

ADS_PORT = 48898
_ADS_SYSTEM_SERVICE = 10000  # the AMS port every TwinCAT system exposes
_ADS_CLIENT_PORT = 32905  # an AMS port from the range clients are given dynamically
_ADS_READ_DEVICE_INFO = 0x0001
_ADS_REQUEST = 0x0004  # state flags: ADS command, request
_ADS_RESPONSE = 0x0001
_ADS_INVOKE_ID = 0x4E534131
_AMS_HEADER = struct.Struct("<6sH6sHHHIII")


def _ams_net_id(host: str) -> bytes:
    """The <ipv4>.1.1 AMS NetId TwinCAT assigns by default for an IP address."""
    try:
        return ipaddress.IPv4Address(host).packed + b"\x01\x01"
    except ValueError:
        return bytes(4) + b"\x01\x01"


def build_ads_request(local: tuple[str, int], remote: tuple[str, int]) -> bytes:
    """AMS/TCP ADS Read Device Info to the target's system service."""
    header = _AMS_HEADER.pack(
        _ams_net_id(remote[0]), _ADS_SYSTEM_SERVICE,
        _ams_net_id(local[0]), _ADS_CLIENT_PORT,
        _ADS_READ_DEVICE_INFO, _ADS_REQUEST, 0, 0, _ADS_INVOKE_ID,
    )
    return struct.pack("<HI", 0, len(header)) + header


def ads_frame_length(data: bytes) -> int | None:
    """AMS/TCP size from its header; a reply without the zero reserved field ends at once."""
    if len(data) < 6:
        return None
    if data[:2] != b"\x00\x00":
        return len(data)
    return 6 + int.from_bytes(data[2:6], "little")


def parse_ads_response(data: bytes) -> dict[str, str]:
    """Report the AMS NetId and device name/version; an AMS error still proves ADS."""
    if len(data) < 6 + _AMS_HEADER.size:
        return {}
    reserved, length = struct.unpack("<HI", data[:6])
    if reserved != 0 or not _AMS_HEADER.size <= length <= len(data) - 6:
        return {}
    _, _, source, _, command, flags, data_len, error, invoke = _AMS_HEADER.unpack(
        data[6:6 + _AMS_HEADER.size]
    )
    if command != _ADS_READ_DEVICE_INFO or not flags & _ADS_RESPONSE:
        return {}
    if invoke != _ADS_INVOKE_ID:
        return {}
    info = {"ams_net_id": ".".join(str(b) for b in source)}
    if error:
        info["ams_error"] = f"0x{error:08x}"
        return info
    start = 6 + _AMS_HEADER.size
    body = data[start:start + min(data_len, length - _AMS_HEADER.size)]
    if len(body) >= 24:  # result, major, minor, build, 16-byte device name
        result = int.from_bytes(body[:4], "little")
        if result:
            info["ads_error"] = f"0x{result:08x}"
        else:
            info["version"] = f"{body[4]}.{body[5]}.{int.from_bytes(body[6:8], 'little')}"
            name = _printable(body[8:24])
            if name:
                info["device_name"] = name
    return info


async def probe_ads(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify a Beckhoff TwinCAT AMS router via ADS Read Device Info."""
    try:
        reply = await asyncio.wait_for(
            tcp_request(host, port, build_ads_request, timeout, frame_length=ads_frame_length),
            timeout,
        )
    except Exception:
        return None
    info = parse_ads_response(reply) if reply else {}
    banner = info.get("device_name", "Beckhoff ADS")
    return _result("beckhoff-ads", port, "tcp", info, banner) if info else None


# HART-IP (port 5094, TCP)

HARTIP_PORT = 5094
_HARTIP_HEADER = struct.Struct(">BBBBHH")  # version, type, message id, status, sequence, size
_HARTIP_SESSION_INITIATE = 0
_HARTIP_SESSION_CLOSE = 1
_HARTIP_PDU = 3
_HARTIP_REPLY_TYPES = (1, 3, 15)  # response, error, NAK
_HARTIP_INACTIVITY_MS = 20000


def _xor(data: bytes) -> int:
    checksum = 0
    for byte in data:
        checksum ^= byte
    return checksum


def _hartip_message(message_id: int, sequence: int, body: bytes = b"") -> bytes:
    size = _HARTIP_HEADER.size + len(body)
    return _HARTIP_HEADER.pack(1, 0, message_id, 0, sequence, size) + body


def build_hartip_session_initiate() -> bytes:
    """Session Initiate as a primary master with a 20 s inactivity close timer."""
    body = struct.pack(">BI", 0x01, _HARTIP_INACTIVITY_MS)
    return _hartip_message(_HARTIP_SESSION_INITIATE, 1, body)


def build_hartip_command0() -> bytes:
    """HART command 0 (Read Unique Identifier, read-only) to polling address 0."""
    pdu = bytes((0x02, 0x80, 0x00, 0x00))  # STX short frame, primary master + addr 0, cmd 0
    return _hartip_message(_HARTIP_PDU, 2, pdu + bytes((_xor(pdu),)))


def build_hartip_session_close() -> bytes:
    """Session Close, ending the session before the TCP connection closes."""
    return _hartip_message(_HARTIP_SESSION_CLOSE, 3)


def hartip_frame_length(data: bytes) -> int | None:
    """HART-IP size from its header; a reply that is not version 1 ends at once."""
    if not data:
        return None
    if data[0] != 0x01:
        return len(data)
    return int.from_bytes(data[6:8], "big") if len(data) >= 8 else None


def parse_hartip_reply(data: bytes, message_id: int, sequence: int) -> int | None:
    """Status of a HART-IP reply to ``message_id``/``sequence``, or None if not one."""
    if len(data) < _HARTIP_HEADER.size:
        return None
    version, kind, mid, status, seq, size = _HARTIP_HEADER.unpack(data[:_HARTIP_HEADER.size])
    if version != 1 or kind not in _HARTIP_REPLY_TYPES or mid != message_id or seq != sequence:
        return None
    return status if size >= _HARTIP_HEADER.size else None


def parse_hartip_command0(data: bytes) -> dict[str, str]:
    """Identity fields from a command 0 reply; ``{}`` unless it is a valid ACK."""
    if parse_hartip_reply(data, _HARTIP_PDU, 2) != 0:
        return {}
    pdu = data[_HARTIP_HEADER.size:int.from_bytes(data[6:8], "big")]
    # Delimiter, address, command, byte count, response code, device status, data, checksum.
    if len(pdu) < 6 or pdu[0] != 0x06 or pdu[2] != 0x00 or pdu[4] != 0x00:
        return {}
    count = pdu[3]
    if len(pdu) < 5 + count or _xor(pdu[:4 + count]) != pdu[4 + count]:
        return {}
    ident = pdu[6:4 + count]
    if len(ident) < 12 or ident[0] != 0xFE:  # command 0 data starts with 254
        return {}
    revision = ident[4]
    info = {
        "hart_revision": str(revision),
        "device_revision": str(ident[5]),
        "software_revision": str(ident[6]),
        "device_id": ident[9:12].hex(),
    }
    if revision >= 7 and len(ident) >= 19:
        info["expanded_device_type"] = f"0x{int.from_bytes(ident[1:3], 'big'):04x}"
        info["manufacturer_id"] = f"0x{int.from_bytes(ident[17:19], 'big'):04x}"
    else:
        info["manufacturer_id"] = f"0x{ident[1]:02x}"
        info["device_type"] = f"0x{ident[2]:02x}"
    return info


async def _hartip_exchange(
    host: str, port: int, timeout: float, info: dict[str, str]
) -> None:
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(build_hartip_session_initiate())
        await writer.drain()
        reply = await read_framed(reader, timeout, hartip_frame_length)
        status = parse_hartip_reply(reply, _HARTIP_SESSION_INITIATE, 1)
        if status is None:
            return
        info["session_status"] = str(status)
        if status != 0:
            return
        writer.write(build_hartip_command0())
        await writer.drain()
        info.update(parse_hartip_command0(await read_framed(reader, timeout, hartip_frame_length)))
        writer.write(build_hartip_session_close())
        await writer.drain()
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError, OSError):
            await writer.wait_closed()


async def probe_hartip(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify a HART-IP device: Session Initiate, command 0, Session Close."""
    info: dict[str, str] = {}
    with contextlib.suppress(Exception):
        async with asyncio.timeout(timeout):
            await _hartip_exchange(host, port, timeout, info)
    if not info:
        return None
    banner = f"HART-IP device {info['device_id']}" if "device_id" in info else "HART-IP"
    return _result("hart-ip", port, "tcp", info, banner)


# Phoenix Contact PC Worx (port 1962, TCP)

PCWORX_PORT = 1962
_PCWORX_CONNECT = (
    bytes((0x01, 0x01, 0x00, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x78, 0x80, 0x00, 0x03, 0x00, 0x0C))
    + b"IBETH01N0_M\x00"
)
_PCWORX_CONNECT_ACK = bytes((0x81, 0x01, 0x00, 0x14))
_PCWORX_FIELDS = (
    ("plc_type", 30),
    ("firmware_version", 66),
    ("firmware_date", 79),
    ("firmware_time", 91),
    ("model_number", 152),
)


def build_pcworx_requests(session: int) -> tuple[bytes, bytes]:
    """The session set-up and info read that follow the connect reply."""
    setup = bytes((
        0x01, 0x05, 0x00, 0x16, 0x00, 0x01, 0x00, 0x00, 0x78, 0x80, 0x00, session,
        0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x02, 0x95, 0x00, 0x00,
    ))
    read_info = bytes((
        0x01, 0x06, 0x00, 0x0E, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, session, 0x04, 0x00,
    ))
    return setup, read_info


def pcworx_frame_length(data: bytes) -> int | None:
    """Message size from its header; a reply not starting 0x81 ends at once."""
    if not data:
        return None
    if data[0] != 0x81:
        return len(data)
    return int.from_bytes(data[2:4], "big") if len(data) >= 4 else None


def parse_pcworx_session(data: bytes) -> int | None:
    """Session id from the connect reply, or None when it is not PC Worx."""
    if len(data) < 20 or data[:4] != _PCWORX_CONNECT_ACK:
        return None
    return data[17]


def parse_pcworx_info(data: bytes) -> dict[str, str]:
    """PLC type, model and firmware strings from the info reply."""
    if not data.startswith(b"\x81"):
        return {}
    info: dict[str, str] = {}
    for key, offset in _PCWORX_FIELDS:
        text = _printable(data[offset:offset + 64])
        if text:
            info[key] = text
    return info


async def _pcworx_exchange(
    host: str, port: int, timeout: float, info: dict[str, str]
) -> None:
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(_PCWORX_CONNECT)
        await writer.drain()
        session = parse_pcworx_session(await read_framed(reader, timeout, pcworx_frame_length))
        if session is None:
            return
        info["connect"] = "acknowledged"
        setup, read_info = build_pcworx_requests(session)
        writer.write(setup)
        await writer.drain()
        await read_framed(reader, timeout, pcworx_frame_length)
        writer.write(read_info)
        await writer.drain()
        info.update(parse_pcworx_info(await read_framed(reader, timeout, pcworx_frame_length)))
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError, OSError):
            await writer.wait_closed()


async def probe_pcworx(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify a Phoenix Contact PLC via the PC Worx info exchange."""
    info: dict[str, str] = {}
    with contextlib.suppress(Exception):
        async with asyncio.timeout(timeout):
            await _pcworx_exchange(host, port, timeout, info)
    if not info:
        return None
    return _result("pcworx", port, "tcp", info, info.get("plc_type", "PC Worx"))


# GE SRTP (port 18245, TCP)

SRTP_PORT = 18245
_SRTP_MESSAGE_SIZE = 56


def build_srtp_request() -> bytes:
    """The all-zero 56-byte initialisation an SRTP client opens with; no service request."""
    return bytes(_SRTP_MESSAGE_SIZE)


def srtp_frame_length(data: bytes) -> int | None:
    """SRTP messages here are the fixed 56-byte header."""
    return _SRTP_MESSAGE_SIZE


def parse_srtp_response(data: bytes) -> dict[str, str]:
    """Presence only: an SRTP PLC answers with exactly 56 bytes starting 0x01."""
    if len(data) != _SRTP_MESSAGE_SIZE or data[0] != 0x01:
        return {}
    return {"init": "acknowledged"}


async def probe_srtp(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Detect a GE SRTP endpoint via the initialisation exchange (presence only)."""
    try:
        reply = await asyncio.wait_for(
            tcp_request(host, port, build_srtp_request(), timeout, frame_length=srtp_frame_length),
            timeout,
        )
    except Exception:
        return None
    info = parse_srtp_response(reply) if reply else {}
    return _result("ge-srtp", port, "tcp", info, "GE SRTP") if info else None


# CODESYS V2 runtime (ports 1200 and 2455, TCP)

CODESYS_PORT = 1200
CODESYS_ALT_PORT = 2455
_CODESYS_IDENTIFY = bytes((0xBB, 0xBB, 0x01, 0x00, 0x00, 0x00, 0x01))  # little-endian
_CODESYS_MIN_REPLY = 64
_CODESYS_INFO_END = 160  # the target-info strings sit within the first 160 bytes
_CODESYS_STRING = re.compile(rb"[\x20-\x7e]{4,}")


def build_codesys_request() -> bytes:
    """The V2 runtime target-identification request (no login, no program access)."""
    return _CODESYS_IDENTIFY


def codesys_frame_length(data: bytes) -> int | None:
    """Wait for the target-info fields only when the reply carries the 0xBB marker."""
    if not data:
        return None
    return _CODESYS_INFO_END if data[0] == 0xBB else len(data)


def parse_codesys_response(data: bytes) -> dict[str, str]:
    """Presence plus the printable target strings; ``{}`` without both."""
    if len(data) < _CODESYS_MIN_REPLY or data[0] != 0xBB:
        return {}
    strings = [s.decode("ascii")[:64] for s in _CODESYS_STRING.findall(data[8:1024])][:4]
    if not strings:
        return {}
    return {"target_strings": "; ".join(strings)}


async def probe_codesys(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify a CODESYS V2 runtime via its target-identification request."""
    try:
        reply = await asyncio.wait_for(
            tcp_request(
                host, port, build_codesys_request(), timeout, frame_length=codesys_frame_length
            ),
            timeout,
        )
    except Exception:
        return None
    info = parse_codesys_response(reply) if reply else {}
    if not info:
        return None
    return _result("codesys", port, "tcp", info, info["target_strings"].split("; ", 1)[0])


# Registry

SPECS: list[ProbeSpec] = [
    ProbeSpec("iec-104", IEC104_PORT, "tcp", True, probe_iec104),
    ProbeSpec("niagara-fox", FOX_PORT, "tcp", True, probe_fox),
    ProbeSpec("niagara-fox-tls", FOX_TLS_PORT, "tcp", True, probe_fox_tls),
    ProbeSpec("knxnet-ip", KNX_PORT, "udp", True, probe_knx),
    ProbeSpec("omron-fins", FINS_PORT, "udp", True, probe_fins),
    ProbeSpec("beckhoff-ads", ADS_PORT, "tcp", True, probe_ads),
    ProbeSpec("ge-srtp", SRTP_PORT, "tcp", True, probe_srtp),
    ProbeSpec("codesys", CODESYS_PORT, "tcp", True, probe_codesys),
    ProbeSpec("codesys-2455", CODESYS_ALT_PORT, "tcp", True, probe_codesys),
    # Session protocols send several requests, so only profiles allowing intrusive probes run them.
    ProbeSpec("hart-ip", HARTIP_PORT, "tcp", True, probe_hartip, is_safe=False),
    ProbeSpec("pcworx", PCWORX_PORT, "tcp", True, probe_pcworx, is_safe=False),
]
