"""OT/ICS read-only protocol identification probes.

Every prober is strictly read-only: it sends a single identification request
(device identification, list-identity, read-property, link-status, hello) and
parses the reply. No write, control, or configuration function codes are ever used.

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
    read_framed,
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


# Public Modbus function codes, used to reject non-Modbus binary replies.
_MODBUS_FUNCTION_CODES = frozenset(
    {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C,
     0x0F, 0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x18, 0x2B}
)


def modbus_frame_length(data: bytes) -> int | None:
    """Total Modbus/TCP frame size: 6-byte MBAP prefix plus its length field."""
    if len(data) < 6:
        return None
    return 6 + int.from_bytes(data[4:6], "big")


def build_modbus_request(unit_id: int = 0xFF, transaction_id: int = 1) -> bytes:
    """Read Device Identification request (FC 0x2B / MEI 0x0E, basic category).

    Unit id 0xFF is what the MODBUS Messaging Implementation Guide specifies for a
    device addressed directly over TCP; 0x00 is the broadcast convention and a
    TCP-to-RTU gateway may relay it onto the serial line.
    """
    pdu = bytes((0x2B, 0x0E, 0x01, 0x00))  # FC, MEI type, read-id code=basic, object id 0
    length = len(pdu) + 1  # +1 accounts for the unit-id byte
    header = struct.pack(">HHHB", transaction_id, 0x0000, length, unit_id)  # MBAP header
    return header + pdu


def parse_modbus_response(data: bytes) -> dict[str, str]:
    """Extract device info from a Modbus reply; ``{}`` when it is not Modbus."""
    try:
        if len(data) < 8:
            return {}
        _tid, proto, length, _unit = struct.unpack(">HHHB", data[:7])
        if proto != 0x0000:  # MBAP protocol id must be 0 for Modbus
            return {}
        # MBAP length counts the unit id and PDU, so it must cover at least the
        # function code and cannot claim more bytes than arrived. This rejects the
        # all-zero frame that any 8-byte reply would otherwise pass.
        if length < 2 or length > len(data) - 6:
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
        if fc in _MODBUS_FUNCTION_CODES:
            return {"function_code": f"0x{fc:02x}"}
        return {}
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
        data = await tcp_request(
            host, port, build_modbus_request(), timeout, frame_length=modbus_frame_length
        )
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


def tpkt_frame_length(data: bytes) -> int | None:
    """Total TPKT frame size, read from its 16-bit length field."""
    if len(data) < 4:
        return None
    return int.from_bytes(data[2:4], "big")


def build_cotp_disconnect(dst_ref: int = 0x0000, src_ref: int = 0x0001) -> bytes:
    """COTP Disconnect Request (TPDU type 0x80), reason 0 = not specified.

    A transport-layer teardown, not an S7 control function: S7-300/400 CPUs have a
    small fixed connection pool and a bare TCP FIN can leave the slot allocated.
    """
    body = struct.pack(">BHHB", 0x80, dst_ref, src_ref, 0x00)
    return _tpkt(bytes((len(body),)) + body)


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
    peer_ref = 0
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout
        )
    except (TimeoutError, ConnectionError, OSError):
        return (False, None)
    try:
        writer.write(build_s7_cotp_cr())
        await writer.drain()
        cc = await read_framed(reader, timeout, tpkt_frame_length)
        # TPKT version 3 must be present too, or any binary service on 102 passes.
        if len(cc) < 6 or cc[0] != 0x03 or (cc[5] & 0xF0) != 0xD0:  # CC TPDU type 0xD0
            return (False, None)
        cotp_ok = True
        # The DR must name the PLC's SRC-REF from the CC, or a strict stack discards it.
        peer_ref = int.from_bytes(cc[8:10], "big") if len(cc) >= 10 else 0
        writer.write(build_s7_setup_communication())
        await writer.drain()
        await read_framed(reader, timeout, tpkt_frame_length)
        writer.write(build_s7_szl_request())
        await writer.drain()
        szl = await read_framed(reader, timeout, tpkt_frame_length)
        return (cotp_ok, szl)
    except (TimeoutError, ConnectionError, OSError):
        return (cotp_ok, None)
    finally:
        if cotp_ok:  # release the PLC's connection slot; close() flushes it
            with contextlib.suppress(ConnectionError, OSError):
                writer.write(build_cotp_disconnect(dst_ref=peer_ref))
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


def enip_frame_length(data: bytes) -> int | None:
    """Total ENIP frame size: 24-byte encapsulation header plus its length field."""
    if len(data) < 4:
        return None
    return 24 + int.from_bytes(data[2:4], "little")


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
        request = build_enip_request()
        if transport == "udp":
            data = await udp_request(host, port, request, timeout)
        else:
            data = await tcp_request(
                host, port, request, timeout, frame_length=enip_frame_length
            )
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

_BACNET_INVOKE_ID = 0x01
_BACNET_VENDOR_INVOKE_ID = 0x02  # distinct, so a late first reply is not taken as the vendor
_BACNET_READ_PROPERTY = 0x0C  # confirmed service choice 12
_BACNET_WILDCARD_INSTANCE = 0x3FFFFF  # Device instance 4194303 means "whoever receives this"
_BACNET_PROP_OBJECT_IDENTIFIER = 75
_BACNET_PROP_VENDOR_IDENTIFIER = 120
_BACNET_COMPLEX_ACK = 0x3
_BACNET_ERROR = 0x5
_BACNET_REJECT = 0x6
_BACNET_ABORT = 0x7


def build_bacnet_request(
    instance: int = _BACNET_WILDCARD_INSTANCE,
    prop: int = _BACNET_PROP_OBJECT_IDENTIFIER,
    invoke_id: int = _BACNET_INVOKE_ID,
) -> bytes:
    """Confirmed ReadProperty of one Device property, by default the Object_Identifier.

    Unicast with no DNET, and confirmed rather than a Who-Is: many stacks answer a
    Who-Is with a broadcast I-Am that BBMDs redistribute site-wide, whereas a
    ReadProperty is answered with a unicast ComplexACK to the requester.
    """
    obj = (8 << 22) | (instance & 0x3FFFFF)  # object type 8 = Device
    prop_bytes = prop.to_bytes(max(1, (prop.bit_length() + 7) // 8), "big")
    # Confirmed-Request, max APDU 1476, invoke id, ReadProperty.
    apdu = bytes((0x00, 0x05, invoke_id, _BACNET_READ_PROPERTY))
    apdu += b"\x0c" + struct.pack(">I", obj)  # context tag 0: object id
    apdu += bytes((0x18 | len(prop_bytes),)) + prop_bytes  # context tag 1: property id
    npdu = bytes((0x01, 0x04))  # version 1, expecting reply, no routing
    body = npdu + apdu
    # BVLC: type 0x81 (BACnet/IP), function 0x0A (Original-Unicast-NPDU), total length
    return struct.pack(">BBH", 0x81, 0x0A, len(body) + 4) + body


def parse_bacnet_response(data: bytes) -> dict[str, str]:
    """Read the device instance from the first ReadProperty's ComplexACK.

    An Error, Reject or Abort for the same invoke id still proves a BACnet stack and
    is reported as such; anything else, including an unsolicited I-Am, is ignored.
    """
    try:
        apdu = _bacnet_reply_apdu(data, _BACNET_INVOKE_ID)
        if apdu is None:
            return {}
        pdu_type = apdu[0] >> 4
        if pdu_type == _BACNET_COMPLEX_ACK:
            if not _is_read_property_ack(apdu):
                return {}
            info = {"response": "complex-ack"}
            value = _read_property_value(apdu[3:])
            if value is not None and value[0] == 12 and len(value[1]) == 4:  # object id
                obj = int.from_bytes(value[1], "big")
                info["object_id"] = f"{obj >> 22}:{obj & 0x3FFFFF}"
                info["device_instance"] = str(obj & 0x3FFFFF)
            return info
        if pdu_type == _BACNET_ERROR:
            info = {"response": "error"}
            error_class, off = _read_bacnet_app_tag(apdu, 3)  # after the service choice
            error_code, _ = _read_bacnet_app_tag(apdu, off)
            if error_class:
                info["error_class"] = str(int.from_bytes(error_class, "big"))
            if error_code:
                info["error_code"] = str(int.from_bytes(error_code, "big"))
            return info
        if pdu_type == _BACNET_REJECT:
            return {"response": "reject", "reject_reason": str(apdu[2])}
        if pdu_type == _BACNET_ABORT:
            return {"response": "abort", "abort_reason": str(apdu[2])}
        return {}
    except (struct.error, IndexError):
        return {}


def parse_bacnet_vendor_response(data: bytes) -> str | None:
    """Vendor identifier from the follow-up ReadProperty's ComplexACK, else None."""
    try:
        apdu = _bacnet_reply_apdu(data, _BACNET_VENDOR_INVOKE_ID)
        if apdu is None or not _is_read_property_ack(apdu):
            return None
        value = _read_property_value(apdu[3:])
        if value is None or value[0] != 2:  # application tag 2 = Unsigned
            return None
        return str(int.from_bytes(value[1], "big"))
    except (struct.error, IndexError):
        return None


def _bacnet_reply_apdu(data: bytes, invoke_id: int) -> bytes | None:
    # The APDU of a BACnet/IP reply, provided it answers ``invoke_id``.
    if len(data) < 6 or data[0] != 0x81:  # BVLC type = BACnet/IP
        return None
    apdu = _bacnet_apdu(data)
    if apdu is None or len(apdu) < 3 or apdu[1] != invoke_id:
        return None
    return apdu


def _is_read_property_ack(apdu: bytes) -> bool:
    # Unsegmented ComplexACK whose service ACK choice is ReadProperty.
    return (
        apdu[0] >> 4 == _BACNET_COMPLEX_ACK
        and not apdu[0] & 0x08
        and apdu[2] == _BACNET_READ_PROPERTY
    )


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


def _read_property_value(body: bytes) -> tuple[int, bytes] | None:
    # Skip the echoed object id, property id and any array index up to opening tag 3,
    # then return the application tag number and bytes of the value it wraps.
    off = 0
    while off < len(body) and body[off] != 0x3E:
        _, off = _read_bacnet_app_tag(body, off)
    off += 1
    if off >= len(body) or body[off] & 0x08:  # a context tag, not an application value
        return None
    value, _ = _read_bacnet_app_tag(body, off)
    return (body[off] >> 4, value) if value else None


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


async def _read_bacnet_vendor_id(
    host: str, port: int, instance: int, timeout: float
) -> str | None:
    request = build_bacnet_request(
        instance, _BACNET_PROP_VENDOR_IDENTIFIER, _BACNET_VENDOR_INVOKE_ID
    )
    reply = await udp_request(host, port, request, timeout)
    return parse_bacnet_vendor_response(reply) if reply else None


async def probe_bacnet(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify a BACnet/IP device via unicast ReadProperty requests.

    The first reads the Object_Identifier; once the instance is known a second reads
    its Vendor_Identifier in what is left of ``timeout``, and if that read fails the
    first result is kept.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    try:
        data = await udp_request(host, port, build_bacnet_request(), timeout)
        if not data:
            return None
        info = parse_bacnet_response(data)
    except Exception:
        return None
    if not info:
        return None
    instance = info.get("device_instance")
    remaining = deadline - loop.time()
    if instance is not None and remaining > 0:
        with contextlib.suppress(Exception):
            async with asyncio.timeout(remaining):
                vendor_id = await _read_bacnet_vendor_id(host, port, int(instance), remaining)
            if vendor_id is not None:
                info["vendor_id"] = vendor_id
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


_DNP3_HEADER_LEN = 10  # start(2) length(1) control(1) dst(2) src(2) crc(2)

# Outstations silently discard frames addressed elsewhere and 0 is not a broadcast
# address (0xFFFD/0xFFFE/0xFFFF are), so a single dst=0 attempt misses almost every
# real device. These are the common defaults across vendors and demo configurations.
_DNP3_LINK_ADDRESSES = (0, 1, 3, 4, 10, 1024)


def dnp3_frame_length(data: bytes) -> int | None:
    """The link header is all this probe parses, so that is the frame it waits for."""
    return _DNP3_HEADER_LEN


def build_dnp3_request(dst: int = 0, src: int = 0) -> bytes:
    """Data-link Request Link Status frame (function 0x09)."""
    # Header: start 0x0564, length 5, control 0xC9 (DIR|PRM, FC 9), dest/src little-endian.
    header = struct.pack("<BBBBHH", 0x05, 0x64, 0x05, 0xC9, dst, src)
    return header + struct.pack("<H", dnp3_crc(header))


def parse_dnp3_response(data: bytes) -> dict[str, str]:
    """Detect a DNP3 frame (0x05 0x64) and read its CRC-validated link header."""
    try:
        if len(data) < _DNP3_HEADER_LEN or data[0] != 0x05 or data[1] != 0x64:
            return {}
        # Without the CRC check any service whose reply starts 05 64 is fingerprinted
        # as an outstation and flagged is_ot.
        if dnp3_crc(data[:8]) != struct.unpack("<H", data[8:10])[0]:
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


async def _dnp3_exchange(host: str, port: int, timeout: float) -> dict[str, str]:
    # One session for the whole sweep: outstations often accept a single master
    # connection, so reconnecting per address could contend with the SCADA master.
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout
        )
    except (TimeoutError, ConnectionError, OSError):
        return {}
    per_try = timeout / len(_DNP3_LINK_ADDRESSES)
    try:
        for dst in _DNP3_LINK_ADDRESSES:
            writer.write(build_dnp3_request(dst=dst))
            await writer.drain()
            reply = await read_framed(reader, per_try, dnp3_frame_length)
            info = parse_dnp3_response(reply) if reply else {}
            if info:
                return info
            if reader.at_eof():  # the outstation hung up, so later frames go nowhere
                break
        return {}
    except (TimeoutError, ConnectionError, OSError):
        return {}
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError, OSError):
            await writer.wait_closed()


async def probe_dnp3(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Detect a DNP3 outstation via Request Link Status frames on one connection.

    Each candidate link address gets an equal slice of ``timeout`` to answer, and
    the sweep stops at the first valid reply.
    """
    try:
        info = await _dnp3_exchange(host, port, timeout)
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


def opcua_frame_length(data: bytes) -> int | None:
    """Total OPC-UA message size, read from the 4-byte MessageSize field."""
    if len(data) < 8:
        return None
    return int.from_bytes(data[4:8], "little")


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
        data = await tcp_request(
            host, port, payload, timeout, frame_length=opcua_frame_length
        )
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
