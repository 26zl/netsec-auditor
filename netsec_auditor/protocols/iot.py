"""IoT read-only protocol identification probes.

Covers MQTT, CoAP, UPnP/SSDP, mDNS/DNS-SD and RTSP. Every prober only sends the
minimal identification request (no writes, no PUBLISH/SUBSCRIBE, no session set-up
beyond the initial handshake) and returns ``None`` instead of raising on failure.
Each protocol exposes pure ``build_*``/``parse_*`` helpers that are unit-testable
without a live device.
"""

from __future__ import annotations

import re
import struct

from netsec_auditor.protocols.base import (
    ProbeResult,
    ProbeSpec,
    tcp_request,
    udp_request,
)

# Shared HTTP-style header parsing (SSDP + RTSP)


def _parse_http_message(data: bytes) -> tuple[str, dict[str, str]]:
    """Split an HTTP/RTSP/SSDP message into its status line and header dict."""
    text = data.decode("utf-8", "replace")
    lines = text.replace("\r\n", "\n").split("\n")
    status = lines[0].strip() if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            break  # a blank line terminates the header block
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return status, headers


# MQTT (RFC / MQTT 3.1.1, protocol level 4) — TCP 1883 / 8883

_MQTT_PROTOCOL_NAME = b"MQTT"
_MQTT_RETURN_CODES: dict[int, str] = {
    0x00: "accepted",
    0x01: "unacceptable protocol version",
    0x02: "identifier rejected",
    0x03: "server unavailable",
    0x04: "bad username or password",
    0x05: "not authorized",
}


def _mqtt_remaining_length(length: int) -> bytes:
    """Encode an MQTT "remaining length" varint: 7 bits/byte, high bit = continue."""
    out = bytearray()
    while True:
        byte = length & 0x7F
        length >>= 7
        if length:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def build_mqtt_request(client_id: str = "netsec-auditor", keepalive: int = 60) -> bytes:
    """Build a read-only MQTT CONNECT packet (clean session, no credentials)."""
    cid = client_id.encode("utf-8")
    # Variable header: protocol name, level 4, connect flags (0x02 = clean session),
    # then the 16-bit keep-alive.
    var_header = (
        struct.pack("!H", len(_MQTT_PROTOCOL_NAME))
        + _MQTT_PROTOCOL_NAME
        + bytes([0x04, 0x02])
        + struct.pack("!H", keepalive)
    )
    # Payload: length-prefixed client identifier only (no will/username/password).
    payload = struct.pack("!H", len(cid)) + cid
    body = var_header + payload
    # Fixed header: 0x10 = CONNECT (type 1 << 4, flags 0) + remaining length.
    return bytes([0x10]) + _mqtt_remaining_length(len(body)) + body


def parse_mqtt_response(data: bytes) -> dict[str, str]:
    """Parse an MQTT CONNACK; return {} unless the packet is a CONNACK (0x20)."""
    # CONNACK layout: 0x20, remaining length 0x02, ack flags, return/reason code.
    if len(data) < 4 or data[0] != 0x20:
        return {}
    ack_flags = data[2]
    return_code = data[3]
    accepted = return_code == 0x00
    return {
        "packet": "CONNACK",
        "return_code": f"0x{return_code:02x}",
        "return_code_desc": _MQTT_RETURN_CODES.get(return_code, "unknown"),
        "anonymous_accepted": "true" if accepted else "false",
        "session_present": "true" if ack_flags & 0x01 else "false",
    }


async def probe_mqtt(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify an MQTT broker by sending CONNECT and reading the CONNACK."""
    try:
        data = await tcp_request(host, port, build_mqtt_request(), timeout)
        if not data:
            return None
        info = parse_mqtt_response(data)
        if not info:
            return None
        result = ProbeResult(
            protocol="mqtt",
            port=port,
            transport="tcp",
            device_info=info,
            banner=f"MQTT broker (CONNACK {info['return_code']})",
        )
        result.extra["anonymous_accepted"] = info["anonymous_accepted"] == "true"
        if port == 8883:  # 8883 is MQTT-over-TLS; we probe in the clear and note it
            result.extra["tls"] = True
        return result
    except Exception:
        return None


# CoAP (RFC 7252) — UDP 5683

_COAP_URI_PATH = 11  # CoAP option number for Uri-Path
_COAP_LINK_RE = re.compile(r"<([^>]*)>")  # link-format resources: <path>;attrs


def _coap_nibble(value: int, ext: bytearray) -> int:
    """Return a CoAP option delta/length nibble, appending extension bytes if >= 13."""
    if value < 13:
        return value
    if value < 269:  # 13..268 -> nibble 13 + one extension byte (value - 13)
        ext.append(value - 13)
        return 13
    ext.extend(struct.pack("!H", value - 269))  # 269+ -> nibble 14 + two bytes
    return 14


def _coap_encode_option(delta: int, value: bytes) -> bytes:
    """Encode one CoAP option: delta/length header byte, extensions, then value."""
    ext = bytearray()
    nib_delta = _coap_nibble(delta, ext)
    nib_len = _coap_nibble(len(value), ext)
    return bytes([(nib_delta << 4) | nib_len]) + bytes(ext) + value


def _coap_ext_value(data: bytes, idx: int, nibble: int) -> tuple[int, int]:
    """Resolve a CoAP option nibble to its value, consuming any extension bytes."""
    if nibble == 13:  # one extension byte, value = byte + 13
        return idx + 1, data[idx] + 13
    if nibble == 14:  # two extension bytes, value = uint16 + 269
        return idx + 2, struct.unpack_from("!H", data, idx)[0] + 269
    return idx, nibble


def _coap_payload(data: bytes, idx: int) -> str:
    """Walk CoAP options from idx and return the text payload after the 0xFF marker."""
    while idx < len(data):
        byte = data[idx]
        if byte == 0xFF:  # payload marker separates options from the payload
            return data[idx + 1 :].decode("utf-8", "replace")
        idx += 1
        idx, _ = _coap_ext_value(data, idx, byte >> 4)  # option delta (skipped)
        idx, length = _coap_ext_value(data, idx, byte & 0x0F)  # option length
        idx += length  # skip the option value
    return ""


def _coap_link_resources(payload: str) -> str:
    """Join the <resource> URIs from a link-format (RFC 6690) payload."""
    return ", ".join(_COAP_LINK_RE.findall(payload))


def build_coap_request(path: str = ".well-known/core", message_id: int = 1) -> bytes:
    """Build a confirmable CoAP GET for ``path`` using Uri-Path options."""
    # Byte 0 = 0x40: version 1 (01), type CON (00), token length 0 (0000).
    # Byte 1 = 0x01: code 0.01 (GET). Bytes 2-3: message id.
    header = bytes([0x40, 0x01]) + struct.pack("!H", message_id)
    options = b""
    prev = 0
    for segment in path.split("/"):
        if not segment:
            continue
        options += _coap_encode_option(_COAP_URI_PATH - prev, segment.encode("utf-8"))
        prev = _COAP_URI_PATH  # subsequent Uri-Path options have delta 0
    return header + options


def parse_coap_response(data: bytes) -> dict[str, str]:
    """Parse a CoAP response code and (link-format) payload; return {} if not CoAP."""
    if len(data) < 4 or data[0] >> 6 != 1:  # first two bits are the version (must be 1)
        return {}
    tkl = data[0] & 0x0F
    code = data[1]
    # Response code is class.detail, e.g. 2.05 Content = (2 << 5) | 5 = 0x45.
    info: dict[str, str] = {"code": f"{code >> 5}.{code & 0x1F:02d}"}
    try:
        payload = _coap_payload(data, 4 + tkl)  # options/payload follow header + token
    except (struct.error, IndexError):
        return info  # header is valid even if the options were malformed
    if payload:
        info["payload"] = payload
        resources = _coap_link_resources(payload)
        if resources:
            info["resources"] = resources
    return info


async def probe_coap(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify a CoAP server by requesting the ``.well-known/core`` resource list."""
    try:
        data = await udp_request(host, port, build_coap_request(), timeout)
        if not data:
            return None
        info = parse_coap_response(data)
        if not info:
            return None
        return ProbeResult(
            protocol="coap",
            port=port,
            transport="udp",
            device_info=info,
            banner=f"CoAP {info.get('code', '')}".strip(),
        )
    except Exception:
        return None


# UPnP / SSDP — UDP 1900


def build_ssdp_request(
    host: str = "239.255.255.250",
    port: int = 1900,
    st: str = "ssdp:all",
    mx: int = 1,
) -> bytes:
    """Build an HTTP-over-UDP SSDP ``M-SEARCH`` discovery request."""
    lines = [
        "M-SEARCH * HTTP/1.1",
        f"HOST: {host}:{port}",
        'MAN: "ssdp:discover"',
        f"MX: {mx}",
        f"ST: {st}",
        "",
        "",  # second blank line yields the trailing CRLF CRLF
    ]
    return "\r\n".join(lines).encode("ascii")


def parse_ssdp_response(data: bytes) -> dict[str, str]:
    """Extract SERVER/ST/LOCATION/USN from an SSDP response; return {} if not HTTP."""
    status, headers = _parse_http_message(data)
    if "http/" not in status.lower():  # SSDP replies start with an HTTP status line
        return {}
    info: dict[str, str] = {}
    for key in ("server", "location", "usn", "st"):
        if key in headers:
            info[key] = headers[key]
    return info


async def probe_ssdp(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify a UPnP device via a unicast SSDP ``M-SEARCH``."""
    try:
        data = await udp_request(host, port, build_ssdp_request(host, port), timeout)
        if not data:
            return None
        info = parse_ssdp_response(data)
        if not info:
            return None
        return ProbeResult(
            protocol="ssdp",
            port=port,
            transport="udp",
            device_info=info,
            banner=info.get("server", ""),
        )
    except Exception:
        return None


# mDNS / DNS-SD — UDP 5353

_DNS_SD_SERVICES = "_services._dns-sd._udp.local"


def _dns_encode_name(name: str) -> bytes:
    """Encode a dotted DNS name as length-prefixed labels ending in a zero byte."""
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        raw = label.encode("ascii")
        out.append(len(raw))  # single-byte label length prefix
        out.extend(raw)
    out.append(0)  # root label terminates the name
    return bytes(out)


def _dns_read_name(data: bytes, offset: int) -> tuple[int, str]:
    """Decode a DNS name, following compression pointers; return (next_offset, name)."""
    labels: list[str] = []
    next_offset: int | None = None
    jumps = 0
    while 0 <= offset < len(data):
        length = data[offset]
        if length == 0:  # zero-length label ends the name
            offset += 1
            if next_offset is None:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:  # 0xC0 mask marks a 14-bit compression pointer
            if offset + 1 >= len(data):
                break
            if next_offset is None:
                next_offset = offset + 2  # resume after the 2-byte pointer
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            jumps += 1
            if jumps > 128:  # guard against pointer loops in hostile input
                break
            continue
        offset += 1
        labels.append(data[offset : offset + length].decode("ascii", "replace"))
        offset += length
    if next_offset is None:
        next_offset = offset
    return next_offset, ".".join(labels)


def build_mdns_request(name: str = _DNS_SD_SERVICES, qtype: int = 12) -> bytes:
    """Build a DNS-SD PTR query (default: enumerate all service types)."""
    # Header: id 0, flags 0 (mDNS query), QDCOUNT 1, AN/NS/AR counts 0.
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    # Question: QNAME, then QTYPE (PTR = 12) and QCLASS (IN = 1).
    return header + _dns_encode_name(name) + struct.pack("!HH", qtype, 0x0001)


def _mdns_services(data: bytes) -> list[str]:
    """Return the PTR-record target names (service names) from a DNS/mDNS response."""
    _, _, qd, an, _, _ = struct.unpack_from("!HHHHHH", data, 0)
    if an == 0:
        return []
    offset = 12
    for _ in range(qd):  # skip the question section
        offset, _ = _dns_read_name(data, offset)
        offset += 4  # QTYPE (2) + QCLASS (2)
    services: list[str] = []
    for _ in range(an):
        offset, _ = _dns_read_name(data, offset)  # record owner name
        if offset + 10 > len(data):
            break
        rtype, _, _, rdlen = struct.unpack_from("!HHIH", data, offset)
        offset += 10  # type (2) + class (2) + ttl (4) + rdlength (2)
        if rtype == 12:  # PTR record: RDATA is a (possibly compressed) name
            _, target = _dns_read_name(data, offset)
            if target:
                services.append(target)
        offset += rdlen
    return services


def parse_mdns_response(data: bytes) -> dict[str, str]:
    """Parse advertised service names from a DNS-SD PTR response; return {} if none."""
    if len(data) < 12:
        return {}
    try:
        services = _mdns_services(data)
    except (struct.error, IndexError, UnicodeDecodeError):
        return {}
    if not services:
        return {}
    return {"services": ", ".join(services), "service_count": str(len(services))}


async def probe_mdns(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify an mDNS/DNS-SD responder by enumerating advertised service types."""
    try:
        data = await udp_request(host, port, build_mdns_request(), timeout)
        if not data:
            return None
        info = parse_mdns_response(data)
        if not info:
            return None
        return ProbeResult(
            protocol="mdns",
            port=port,
            transport="udp",
            device_info=info,
            banner=info.get("services", ""),
        )
    except Exception:
        return None


# RTSP (RFC 2326) — TCP 554 (common on IP cameras)


def build_rtsp_request(host: str, port: int = 554, cseq: int = 1) -> bytes:
    """Build a read-only RTSP ``OPTIONS`` request for the server root."""
    lines = [
        f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0",
        f"CSeq: {cseq}",
        "",
        "",  # second blank line yields the trailing CRLF CRLF
    ]
    return "\r\n".join(lines).encode("ascii")


def parse_rtsp_response(data: bytes) -> dict[str, str]:
    """Extract the status line, allowed methods (Public) and Server from RTSP OPTIONS."""
    status, headers = _parse_http_message(data)
    if not status.upper().startswith("RTSP/"):
        return {}
    info: dict[str, str] = {"status": status}
    for key in ("server", "public"):  # Public lists supported methods (OPTIONS, ...)
        if key in headers:
            info[key] = headers[key]
    return info


async def probe_rtsp(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify an RTSP server (often an IP camera) via an OPTIONS request."""
    try:
        data = await tcp_request(host, port, build_rtsp_request(host, port), timeout)
        if not data:
            return None
        info = parse_rtsp_response(data)
        if not info:
            return None
        return ProbeResult(
            protocol="rtsp",
            port=port,
            transport="tcp",
            device_info=info,
            banner=info.get("server", ""),
        )
    except Exception:
        return None


# Registry — all IoT probes are read-only identification (is_ot=False).

SPECS: list[ProbeSpec] = [
    ProbeSpec("mqtt", 1883, "tcp", False, probe_mqtt),
    ProbeSpec("mqtt-tls", 8883, "tcp", False, probe_mqtt),
    ProbeSpec("coap", 5683, "udp", False, probe_coap),
    ProbeSpec("ssdp", 1900, "udp", False, probe_ssdp),
    ProbeSpec("mdns", 5353, "udp", False, probe_mdns),
    ProbeSpec("rtsp", 554, "tcp", False, probe_rtsp),
]
