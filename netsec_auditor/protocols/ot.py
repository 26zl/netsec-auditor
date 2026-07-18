"""OT/ICS read-only protocol identification probes.

Every prober is strictly read-only: it sends a single identification request
(device identification, list-identity, who-is, link-status, hello) and parses
the reply. No write, control, or configuration function codes are ever used.

Each protocol exposes three pieces: a pure ``build_<name>_request`` byte
builder, a pure ``parse_<name>_response`` extractor (returns device-info fields,
``{}`` when it cannot recognise the reply), and an ``async probe_<name>`` that
performs the I/O and never raises.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct

from netsec_auditor.protocols.base import (
    ProbeResult,
    ProbeSpec,
    tcp_request,
    udp_request,
)

MODBUS_PORT = 502
S7COMM_PORT = 102
ETHERNETIP_PORT = 44818
BACNET_PORT = 47808
DNP3_PORT = 20000
OPCUA_PORT = 4840


# Modbus/TCP (port 502)

_MODBUS_DEVICE_ID_OBJECTS = {
    0x00: "vendor",
    0x01: "product_code",
    0x02: "version",
    0x03: "vendor_url",
    0x04: "product_name",
    0x05: "model_name",
    0x06: "application_name",
}


def build_modbus_request(unit_id: int = 0, transaction_id: int = 1) -> bytes:
    """Read Device Identification request (FC 0x2B / MEI 0x0E, basic category)."""
    pdu = bytes((0x2B, 0x0E, 0x01, 0x00))  # FC, MEI type, read-id code=basic, object id 0
    length = len(pdu) + 1  # +1 accounts for the unit-id byte
    header = struct.pack(">HHHB", transaction_id, 0x0000, length, unit_id)  # MBAP header
    return header + pdu


def parse_modbus_response(data: bytes) -> dict[str, str]:
    """Extract device info from a Modbus reply; ``{}`` when it is not Modbus."""
    try:
        if len(data) < 8:
            return {}
        _tid, proto, _length, _unit = struct.unpack(">HHHB", data[:7])
        if proto != 0x0000:  # MBAP protocol id must be 0 for Modbus
            return {}
        fc = data[7]
        if fc == 0x2B and len(data) > 8 and data[8] == 0x0E:
            return _parse_modbus_device_id(data)
        if fc == 0x11:
            return _parse_modbus_report_slave_id(data)
        if fc == 0x03:  # read-holding-registers echo -> liveness only
            return {"function": "read-holding-registers"}
        if fc & 0x80:  # exception reply, still a Modbus speaker
            code = data[8] if len(data) > 8 else 0
            return {"exception_code": f"0x{code:02x}"}
        return {"function_code": f"0x{fc:02x}"}
    except (struct.error, IndexError):
        return {}


def _parse_modbus_device_id(data: bytes) -> dict[str, str]:
    # PDU tail: read-code, conformity, more-follows, next-object, count, then objects
    info: dict[str, str] = {}
    count = data[13]
    off = 14
    for _ in range(count):
        if off + 2 > len(data):
            break
        obj_id, obj_len = data[off], data[off + 1]
        off += 2
        value = data[off:off + obj_len]
        off += obj_len
        key = _MODBUS_DEVICE_ID_OBJECTS.get(obj_id)
        if key:
            text = value.decode("latin-1", "replace").strip("\x00 ")
            if text:
                info[key] = text
    return info


def _parse_modbus_report_slave_id(data: bytes) -> dict[str, str]:
    # PDU: FC(0x11), byte-count, slave-id, run-indicator, then vendor-specific data
    info: dict[str, str] = {"function": "report-slave-id"}
    if len(data) < 10:
        return info
    byte_count = data[8]
    body = data[9:9 + byte_count]
    if body:
        info["slave_id"] = f"0x{body[0]:02x}"
    if len(body) > 1:
        info["run_status"] = "on" if body[1] == 0xFF else "off"
    extra = body[2:].decode("latin-1", "replace").strip("\x00 ")
    if extra:
        info["additional"] = extra
    return info


async def probe_modbus(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify a Modbus/TCP device via Read Device Identification."""
    try:
        data = await tcp_request(host, port, build_modbus_request(), timeout)
        if not data:
            return None
        info = parse_modbus_response(data)
    except Exception:
        return None
    if not info:
        return None
    return ProbeResult(
        protocol="modbus",
        port=port,
        transport="tcp",
        is_ot=True,
        device_info=info,
        banner=info.get("product_name", info.get("vendor", "")),
    )


# Siemens S7comm (port 102, ISO-on-TCP / RFC 1006)

_S7_SZL_1C_INDEX = {
    0x0001: "system_name",
    0x0002: "module_name",
    0x0003: "plant_id",
    0x0004: "copyright",
    0x0005: "serial",
    0x0007: "module_type",
    0x0008: "memory_serial",
    0x000A: "oem_id",
    0x000B: "location",
}


def _tpkt(payload: bytes) -> bytes:
    # TPKT: version 3, reserved 0, 16-bit total length including this 4-byte header
    return struct.pack(">BBH", 0x03, 0x00, len(payload) + 4) + payload


def build_s7_cotp_cr(
    src_ref: int = 0x0001, src_tsap: int = 0x0100, dst_tsap: int = 0x0102
) -> bytes:
    """COTP Connection Request (rack 0 / slot 2 by default)."""
    params = bytes((0xC0, 0x01, 0x0A))  # tpdu-size parameter -> 2**10 = 1024
    params += struct.pack(">BBH", 0xC1, 0x02, src_tsap)  # calling (source) TSAP
    params += struct.pack(">BBH", 0xC2, 0x02, dst_tsap)  # called (destination) TSAP
    body = struct.pack(">BHHB", 0xE0, 0x0000, src_ref, 0x00) + params  # CR type 0xE0
    cotp = bytes((len(body),)) + body  # length indicator excludes itself
    return _tpkt(cotp)


def build_s7_setup_communication(pdu_ref: int = 0x0100) -> bytes:
    """S7 Job (ROSCTR 0x01) Setup Communication, negotiating PDU size."""
    cotp = bytes((0x02, 0xF0, 0x80))  # COTP DT: LI 2, type 0xF0 (data), TPDU no. 0x80 (EOT)
    param = struct.pack(">BBHHH", 0xF0, 0x00, 0x0001, 0x0001, 0x03C0)  # func 0xF0, PDU len 960
    header = struct.pack(">BBHHHH", 0x32, 0x01, 0x0000, pdu_ref, len(param), 0x0000)
    return _tpkt(cotp + header + param)


def build_s7_szl_request(
    szl_id: int = 0x001C, szl_index: int = 0x0000, pdu_ref: int = 0x0200
) -> bytes:
    """S7 Userdata (ROSCTR 0x07) Read SZL request (0x001C component identification)."""
    cotp = bytes((0x02, 0xF0, 0x80))  # COTP DT header
    # Userdata parameter: head 00 01 12, len 4, method 0x11, type/group 0x44 (req/CPU),
    # subfunction 0x01 (read SZL), sequence 0x00.
    param = bytes((0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00))
    # Data: return code 0xFF, transport 0x09 (octet string), length 4, SZL-ID, SZL-index.
    payload = struct.pack(">BBHHH", 0xFF, 0x09, 0x0004, szl_id, szl_index)
    header = struct.pack(">BBHHHH", 0x32, 0x07, 0x0000, pdu_ref, len(param), len(payload))
    return _tpkt(cotp + header + param + payload)


def parse_s7_szl_response(data: bytes) -> dict[str, str]:
    """Extract module/serial/firmware strings from an S7 Read-SZL reply."""
    try:
        if len(data) < 8 or data[0] != 0x03:  # TPKT version 3
            return {}
        if data[7] != 0x32:  # S7 protocol id after TPKT(4) + COTP DT(3)
            return {}
        rosctr = data[8]
        header_len = 12 if rosctr in (0x02, 0x03) else 10  # Ack_Data carries error class/code
        par_len, dat_len = struct.unpack(">HH", data[13:17])
        block = data[7 + header_len + par_len:7 + header_len + par_len + dat_len]
        if len(block) < 12 or block[0] != 0xFF:  # data return code 0xFF = success
            return {}
        szl_id = struct.unpack(">H", block[4:6])[0]
        rec_len, rec_count = struct.unpack(">HH", block[8:12])
        return _parse_s7_szl_records(szl_id, block[12:], rec_len, rec_count)
    except (struct.error, IndexError):
        return {}


def _parse_s7_szl_records(
    szl_id: int, body: bytes, rec_len: int, rec_count: int
) -> dict[str, str]:
    info: dict[str, str] = {}
    if rec_len < 2:
        return info
    for i in range(rec_count):
        rec = body[i * rec_len:(i + 1) * rec_len]
        if len(rec) < 2:
            break
        index = struct.unpack(">H", rec[:2])[0]
        value = rec[2:]
        if (szl_id & 0x00FF) == 0x1C:  # component identification -> ASCII strings
            key = _S7_SZL_1C_INDEX.get(index)
            if key:
                text = value.decode("latin-1", "replace").strip("\x00 ")
                if text:
                    info[key] = text
        elif (szl_id & 0x00FF) == 0x11:  # module identification
            info.update(_parse_s7_module_id(index, value))
    return info


def _parse_s7_module_id(index: int, value: bytes) -> dict[str, str]:
    # Record: MlfB order number (20 bytes ASCII) then BGType and version words.
    info: dict[str, str] = {}
    mlfb = value[:20].decode("latin-1", "replace").strip("\x00 ")
    if index == 0x0001 and mlfb:
        info["module"] = mlfb
    if len(value) >= 26:
        info["firmware"] = f"{value[24]}.{value[25]}"
    return info


async def _s7_exchange(
    host: str, port: int, timeout: float
) -> tuple[bool, bytes | None]:
    # S7 needs a stateful COTP + setup handshake on one socket, so it cannot use the
    # single-shot tcp_request helper; the connection handling mirrors it otherwise.
    cotp_ok = False
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout
        )
    except (TimeoutError, ConnectionError, OSError):
        return (False, None)
    try:
        writer.write(build_s7_cotp_cr())
        await writer.drain()
        cc = await asyncio.wait_for(reader.read(2048), timeout)
        if not cc or len(cc) < 6 or (cc[5] & 0xF0) != 0xD0:  # COTP Connection Confirm 0xD0
            return (False, None)
        cotp_ok = True
        writer.write(build_s7_setup_communication())
        await writer.drain()
        await asyncio.wait_for(reader.read(2048), timeout)
        writer.write(build_s7_szl_request())
        await writer.drain()
        szl = await asyncio.wait_for(reader.read(2048), timeout)
        return (cotp_ok, szl)
    except (TimeoutError, ConnectionError, OSError):
        return (cotp_ok, None)
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError, OSError):
            await writer.wait_closed()


async def probe_s7(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify a Siemens S7 PLC via COTP connect + Read-SZL component identification."""
    try:
        cotp_ok, szl = await _s7_exchange(host, port, timeout)
    except Exception:
        return None
    if not cotp_ok:
        return None
    info = parse_s7_szl_response(szl) if szl else {}
    return ProbeResult(
        protocol="s7comm",
        port=port,
        transport="tcp",
        is_ot=True,
        device_info=info,
        banner=info.get("module_type", info.get("module", "")),
        extra={"cotp": "connection-confirm"},
    )


# EtherNet/IP - CIP (port 44818, TCP and UDP)

_ENIP_LIST_IDENTITY = 0x0063
_CIP_IDENTITY_ITEM = 0x000C


def build_enip_request(sender_context: bytes = b"") -> bytes:
    """ListIdentity encapsulation request (command 0x0063, empty command data)."""
    ctx = (sender_context + b"\x00" * 8)[:8]
    # Encapsulation header (all little-endian): command, length, session, status, context, options
    return struct.pack("<HHII8sI", _ENIP_LIST_IDENTITY, 0x0000, 0, 0, ctx, 0)


def parse_enip_response(data: bytes) -> dict[str, str]:
    """Extract the CIP Identity object from a ListIdentity reply."""
    try:
        if len(data) < 24:
            return {}
        command, length = struct.unpack("<HH", data[:4])
        if command != _ENIP_LIST_IDENTITY:
            return {}
        body = data[24:24 + length]
        if len(body) < 6:
            return {}
        item_count = struct.unpack("<H", body[:2])[0]
        item_type, item_len = struct.unpack("<HH", body[2:6])
        if item_count < 1 or item_type != _CIP_IDENTITY_ITEM:
            return {}
        return _parse_cip_identity(body[6:6 + item_len])
    except (struct.error, IndexError):
        return {}


def _parse_cip_identity(item: bytes) -> dict[str, str]:
    # version(2) socket-addr(16) vendor(2) type(2) product-code(2) rev(2) status(2)
    # serial(4) name-len(1) name state(1) -- all little-endian except socket address.
    if len(item) < 33:
        return {}
    vendor_id, device_type, product_code = struct.unpack("<HHH", item[18:24])
    major, minor = item[24], item[25]
    serial = struct.unpack("<I", item[28:32])[0]
    name_len = item[32]
    name = item[33:33 + name_len].decode("latin-1", "replace").strip("\x00 ")
    return {
        "vendor_id": str(vendor_id),
        "device_type": str(device_type),
        "product_code": str(product_code),
        "revision": f"{major}.{minor}",
        "serial": f"0x{serial:08x}",
        "product_name": name,
    }


async def _run_enip(
    host: str, port: int, timeout: float, transport: str
) -> ProbeResult | None:
    try:
        sender = udp_request if transport == "udp" else tcp_request
        data = await sender(host, port, build_enip_request(), timeout)
        if not data:
            return None
        info = parse_enip_response(data)
    except Exception:
        return None
    if not info:
        return None
    return ProbeResult(
        protocol="ethernetip",
        port=port,
        transport=transport,
        is_ot=True,
        device_info=info,
        banner=info.get("product_name", ""),
    )


async def probe_enip(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify an EtherNet/IP device over TCP via ListIdentity."""
    return await _run_enip(host, port, timeout, "tcp")


async def probe_enip_udp(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify an EtherNet/IP device over UDP via ListIdentity."""
    return await _run_enip(host, port, timeout, "udp")


# BACnet/IP (port 47808, UDP)


def build_bacnet_request() -> bytes:
    """Unconfirmed Who-Is (global broadcast) to elicit an I-Am reply."""
    apdu = bytes((0x10, 0x08))  # Unconfirmed-Request PDU, service choice 0x08 = Who-Is
    npdu = bytes((0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF))  # dest present, DNET 0xFFFF, hop 255
    body = npdu + apdu
    # BVLC: type 0x81 (BACnet/IP), function 0x0B (Original-Broadcast-NPDU), total length
    return struct.pack(">BBH", 0x81, 0x0B, len(body) + 4) + body


def parse_bacnet_response(data: bytes) -> dict[str, str]:
    """Extract device instance and vendor id from a BACnet I-Am reply."""
    try:
        if len(data) < 6 or data[0] != 0x81:  # BVLC type = BACnet/IP
            return {}
        apdu = _bacnet_apdu(data)
        if apdu is None or len(apdu) < 2:
            return {}
        if apdu[0] != 0x10 or apdu[1] != 0x00:  # Unconfirmed-Request / I-Am
            return {}
        return _parse_bacnet_iam(apdu[2:])
    except (struct.error, IndexError):
        return {}


def _bacnet_apdu(data: bytes) -> bytes | None:
    # Skip BVLC (4 bytes) then the variable NPDU, whose length depends on the control byte.
    off = 4
    if off + 2 > len(data):
        return None
    control = data[off + 1]
    off += 2
    if control & 0x20:  # destination network/address present
        dlen = data[off + 2]
        off += 3 + dlen
    if control & 0x08:  # source network/address present
        slen = data[off + 2]
        off += 3 + slen
    if control & 0x20:  # hop count follows a destination specifier
        off += 1
    return data[off:]


def _parse_bacnet_iam(apdu: bytes) -> dict[str, str]:
    info: dict[str, str] = {}
    off = 0
    params: list[bytes] = []
    while off < len(apdu) and len(params) < 4:
        value, off = _read_bacnet_app_tag(apdu, off)
        if value is None:
            break
        params.append(value)
    if params:
        obj = int.from_bytes(params[0], "big")
        info["object_id"] = f"{obj >> 22}:{obj & 0x3FFFFF}"
        info["device_instance"] = str(obj & 0x3FFFFF)
    if len(params) >= 4:
        info["vendor_id"] = str(int.from_bytes(params[3], "big"))
    return info


def _read_bacnet_app_tag(data: bytes, off: int) -> tuple[bytes | None, int]:
    # Application tag byte: high nibble = tag number, low 3 bits = length (5 => extended).
    if off >= len(data):
        return (None, off)
    length = data[off] & 0x07
    off += 1
    if length == 5:
        length = data[off]
        off += 1
    return (data[off:off + length], off + length)


async def probe_bacnet(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify a BACnet/IP device via Who-Is / I-Am."""
    try:
        data = await udp_request(host, port, build_bacnet_request(), timeout)
        if not data:
            return None
        info = parse_bacnet_response(data)
    except Exception:
        return None
    if not info:
        return None
    return ProbeResult(
        protocol="bacnet",
        port=port,
        transport="udp",
        is_ot=True,
        device_info=info,
        banner=info.get("object_id", ""),
    )


# DNP3 (port 20000, TCP)


def dnp3_crc(data: bytes) -> int:
    """CRC-16/DNP (reflected poly 0xA6BC, init 0x0000, xor-out 0xFFFF)."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (crc ^ 0xFFFF) & 0xFFFF


def build_dnp3_request(dst: int = 0, src: int = 0) -> bytes:
    """Data-link Request Link Status frame (function 0x09)."""
    # Header: start 0x0564, length 5, control 0xC9 (DIR|PRM, FC 9), dest/src little-endian.
    header = struct.pack("<BBBBHH", 0x05, 0x64, 0x05, 0xC9, dst, src)
    return header + struct.pack("<H", dnp3_crc(header))


def parse_dnp3_response(data: bytes) -> dict[str, str]:
    """Detect a DNP3 frame (0x05 0x64) and read its link header."""
    try:
        if len(data) < 8 or data[0] != 0x05 or data[1] != 0x64:  # DNP3 start octets
            return {}
        length, control = data[2], data[3]
        dst, src = struct.unpack("<HH", data[4:8])
        return {
            "dnp3": "detected",
            "length": str(length),
            "source": str(src),
            "destination": str(dst),
            "link_function": f"0x{control & 0x0F:02x}",
            "direction": "master" if control & 0x80 else "outstation",
        }
    except (struct.error, IndexError):
        return {}


async def probe_dnp3(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Detect a DNP3 outstation via a Request Link Status frame."""
    try:
        data = await tcp_request(host, port, build_dnp3_request(), timeout)
        if not data:
            return None
        info = parse_dnp3_response(data)
    except Exception:
        return None
    if not info:
        return None
    return ProbeResult(
        protocol="dnp3",
        port=port,
        transport="tcp",
        is_ot=True,
        device_info=info,
        banner=info.get("dnp3", ""),
    )


# OPC-UA (port 4840, TCP)

_OPCUA_MESSAGE_TYPES = ("HEL", "ACK", "ERR", "OPN", "MSG", "CLO")


def build_opcua_request(endpoint_url: str) -> bytes:
    """OPC-UA Hello (HEL) message advertising buffer sizes and the endpoint URL."""
    url = endpoint_url.encode("utf-8")
    # Body: protocol version, receive/send buffer, max message size, max chunk count, URL string.
    body = struct.pack("<IIIII", 0, 0x10000, 0x10000, 0, 0)
    body += struct.pack("<I", len(url)) + url
    # Message header: 3-byte type + chunk type 'F' (final) + 4-byte total message size.
    return b"HELF" + struct.pack("<I", 8 + len(body)) + body


def parse_opcua_response(data: bytes) -> dict[str, str]:
    """Read an OPC-UA Acknowledge/Error header; ``{}`` when not OPC-UA."""
    try:
        if len(data) < 8:
            return {}
        msg_type = data[:3].decode("ascii", "replace")
        if msg_type not in _OPCUA_MESSAGE_TYPES:
            return {}
        info: dict[str, str] = {"message_type": msg_type}
        body = data[8:]
        if msg_type == "ACK" and len(body) >= 20:
            ver, recv_buf, send_buf, max_msg, max_chunk = struct.unpack("<IIIII", body[:20])
            info["protocol_version"] = str(ver)
            info["receive_buffer"] = str(recv_buf)
            info["send_buffer"] = str(send_buf)
            info["max_message_size"] = str(max_msg)
            info["max_chunk_count"] = str(max_chunk)
        elif msg_type == "ERR" and len(body) >= 8:
            err_code = struct.unpack("<I", body[:4])[0]
            reason_len = struct.unpack("<i", body[4:8])[0]  # signed: -1 encodes a null string
            info["error_code"] = f"0x{err_code:08x}"
            if reason_len > 0:
                info["reason"] = body[8:8 + reason_len].decode("utf-8", "replace")
        return info
    except (struct.error, IndexError, UnicodeDecodeError):
        return {}


async def probe_opcua(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Detect an OPC-UA server via a Hello / Acknowledge exchange."""
    try:
        payload = build_opcua_request(f"opc.tcp://{host}:{port}")
        data = await tcp_request(host, port, payload, timeout)
        if not data:
            return None
        info = parse_opcua_response(data)
    except Exception:
        return None
    if not info:
        return None
    return ProbeResult(
        protocol="opcua",
        port=port,
        transport="tcp",
        is_ot=True,
        device_info=info,
        banner=info.get("message_type", ""),
    )


# Registry

SPECS: list[ProbeSpec] = [
    ProbeSpec("modbus", MODBUS_PORT, "tcp", True, probe_modbus),
    ProbeSpec("s7comm", S7COMM_PORT, "tcp", True, probe_s7),
    ProbeSpec("ethernetip", ETHERNETIP_PORT, "tcp", True, probe_enip),
    ProbeSpec("ethernetip-udp", ETHERNETIP_PORT, "udp", True, probe_enip_udp),
    ProbeSpec("bacnet", BACNET_PORT, "udp", True, probe_bacnet),
    ProbeSpec("dnp3", DNP3_PORT, "tcp", True, probe_dnp3),
    ProbeSpec("opcua", OPCUA_PORT, "tcp", True, probe_opcua),
]
