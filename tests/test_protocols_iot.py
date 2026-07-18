"""Unit tests for read-only IoT protocol identification probes.

All assertions use known byte vectors — the ``build_*``/``parse_*`` helpers are
pure, and the ``probe_*`` coroutines are exercised with monkeypatched transports,
so no test performs any real network I/O.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from netsec_auditor.protocols import iot
from netsec_auditor.protocols.iot import (
    SPECS,
    build_coap_request,
    build_mdns_request,
    build_mqtt_request,
    build_rtsp_request,
    build_ssdp_request,
    parse_coap_response,
    parse_mdns_response,
    parse_mqtt_response,
    parse_rtsp_response,
    parse_ssdp_response,
)


def _dns_name(name: str) -> bytes:
    """Encode a dotted name as length-prefixed DNS labels (test-local helper)."""
    out = bytearray()
    for label in name.split("."):
        out.append(len(label))
        out.extend(label.encode("ascii"))
    out.append(0)
    return bytes(out)


# MQTT


def test_build_mqtt_connect_layout() -> None:
    pkt = build_mqtt_request()
    assert pkt[0] == 0x10  # CONNECT fixed header (type 1 << 4)
    assert b"MQTT" in pkt
    assert pkt[1] == len(pkt) - 2  # single-byte remaining length
    assert pkt[2:8] == b"\x00\x04MQTT"  # 2-byte length + protocol name
    assert pkt[8] == 0x04  # protocol level 4
    assert pkt[9] == 0x02  # connect flags: clean session
    assert b"netsec-auditor" in pkt


def test_parse_mqtt_connack_accepted() -> None:
    info = parse_mqtt_response(b"\x20\x02\x00\x00")
    assert info["packet"] == "CONNACK"
    assert info["return_code"] == "0x00"
    assert info["return_code_desc"] == "accepted"
    assert info["anonymous_accepted"] == "true"


def test_parse_mqtt_connack_not_authorized() -> None:
    info = parse_mqtt_response(b"\x20\x02\x00\x05")
    assert info["return_code"] == "0x05"
    assert info["return_code_desc"] == "not authorized"
    assert info["anonymous_accepted"] == "false"


def test_parse_mqtt_rejects_non_connack() -> None:
    assert parse_mqtt_response(b"\x30\x02\x00\x00") == {}  # PUBLISH, not CONNACK
    assert parse_mqtt_response(b"") == {}
    assert parse_mqtt_response(b"\x20\x02") == {}  # truncated


# CoAP


def test_build_coap_get_layout() -> None:
    pkt = build_coap_request()
    assert pkt[0] == 0x40  # version 1, type CON, token length 0
    assert pkt[1] == 0x01  # code 0.01 GET
    assert pkt[2:4] == b"\x00\x01"  # default message id
    assert b"\xbb.well-known" in pkt  # Uri-Path option: delta 11, length 11
    assert b"\x04core" in pkt  # Uri-Path option: delta 0, length 4
    assert b".well-known" in pkt
    assert b"core" in pkt


def test_parse_coap_content_and_resources() -> None:
    # 0x60 = ver1/type ACK/TKL0, 0x45 = 2.05 Content, msg id, 0xFF payload marker.
    resp = bytes([0x60, 0x45, 0x00, 0x01, 0xFF]) + b'</sensors/temp>;rt="temperature"'
    info = parse_coap_response(resp)
    assert info["code"] == "2.05"
    assert "sensors" in info["payload"]
    assert info["resources"] == "/sensors/temp"


def test_parse_coap_skips_content_format_option() -> None:
    # Option 0xC1 (delta 12 Content-Format, length 1) + value, then payload.
    resp = bytes([0x60, 0x45, 0x00, 0x02, 0xC1, 0x28, 0xFF]) + b"</a>,</b>"
    info = parse_coap_response(resp)
    assert info["code"] == "2.05"
    assert info["resources"] == "/a, /b"


def test_parse_coap_rejects_non_coap() -> None:
    assert parse_coap_response(b"\x00") == {}  # too short
    assert parse_coap_response(b"\xff\xff\xff\xff") == {}  # version bits != 1


# SSDP


def test_build_ssdp_msearch() -> None:
    req = build_ssdp_request()
    assert req.startswith(b"M-SEARCH * HTTP/1.1\r\n")
    assert b'MAN: "ssdp:discover"' in req
    assert b"ST: ssdp:all" in req
    assert b"MX: 1" in req
    assert b"HOST: 239.255.255.250:1900" in req
    assert req.endswith(b"\r\n\r\n")


def test_parse_ssdp_response_headers() -> None:
    resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"CACHE-CONTROL: max-age=1800\r\n"
        b"LOCATION: http://192.168.1.10:80/desc.xml\r\n"
        b"SERVER: Linux/3.14 UPnP/1.0 Router/1.0\r\n"
        b"ST: ssdp:all\r\n"
        b"USN: uuid:abcd::upnp:rootdevice\r\n"
        b"\r\n"
    )
    info = parse_ssdp_response(resp)
    assert info["server"] == "Linux/3.14 UPnP/1.0 Router/1.0"
    assert info["location"] == "http://192.168.1.10:80/desc.xml"
    assert info["st"] == "ssdp:all"
    assert info["usn"].startswith("uuid:abcd")


def test_parse_ssdp_rejects_non_http() -> None:
    assert parse_ssdp_response(b"garbage payload without a status line") == {}


# mDNS


def test_build_mdns_query_layout() -> None:
    pkt = build_mdns_request()
    # DNS header: id 0, flags 0, QDCOUNT 1, AN/NS/AR 0.
    assert pkt[:12] == b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    assert b"\x09_services" in pkt
    assert b"\x07_dns-sd" in pkt
    assert b"\x04_udp" in pkt
    assert b"\x05local" in pkt
    # QNAME terminator + QTYPE PTR (12) + QCLASS IN (1).
    assert pkt.endswith(b"\x05local\x00\x00\x0c\x00\x01")


def test_parse_mdns_ptr_answer() -> None:
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)  # response, 1 answer
    owner = _dns_name("_services._dns-sd._udp.local")
    target = _dns_name("_http._tcp.local")
    answer = owner + struct.pack("!HHIH", 12, 1, 4500, len(target)) + target
    info = parse_mdns_response(header + answer)
    assert info["services"] == "_http._tcp.local"
    assert info["service_count"] == "1"


def test_parse_mdns_follows_compression_pointer() -> None:
    header = struct.pack("!HHHHHH", 0, 0x8400, 1, 1, 0, 0)  # 1 question, 1 answer
    question = _dns_name("_services._dns-sd._udp.local") + struct.pack("!HH", 12, 1)
    target = _dns_name("_ipp._tcp.local")
    # Answer owner is a compression pointer (0xC0 | offset 12) back to the question.
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 120, len(target)) + target
    info = parse_mdns_response(header + question + answer)
    assert "_ipp._tcp.local" in info["services"]


def test_parse_mdns_rejects_empty_and_no_answers() -> None:
    assert parse_mdns_response(b"\x00\x00") == {}  # too short
    assert parse_mdns_response(struct.pack("!HHHHHH", 0, 0, 0, 0, 0, 0)) == {}


# RTSP


def test_build_rtsp_options() -> None:
    req = build_rtsp_request("10.0.0.5", 554)
    assert req.startswith(b"OPTIONS rtsp://10.0.0.5:554/ RTSP/1.0\r\n")
    assert b"CSeq: 1\r\n" in req
    assert req.endswith(b"\r\n\r\n")


def test_parse_rtsp_options_response() -> None:
    resp = (
        b"RTSP/1.0 200 OK\r\n"
        b"CSeq: 1\r\n"
        b"Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\n"
        b"Server: GStreamer RTSP server 1.20\r\n"
        b"\r\n"
    )
    info = parse_rtsp_response(resp)
    assert info["status"].startswith("RTSP/1.0 200")
    assert info["public"] == "OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE"
    assert info["server"] == "GStreamer RTSP server 1.20"


def test_parse_rtsp_rejects_non_rtsp() -> None:
    assert parse_rtsp_response(b"HTTP/1.1 200 OK\r\n\r\n") == {}


# SPECS


def test_specs_are_iot_safe_and_registered() -> None:
    assert len(SPECS) >= 4
    assert all(s.is_ot is False for s in SPECS)  # IoT probes are never flagged OT
    assert all(s.is_safe for s in SPECS)  # read-only identification only
    names = {s.name for s in SPECS}
    assert {"coap", "ssdp", "mdns", "rtsp"} <= names
    assert any(s.name.startswith("mqtt") for s in SPECS)
    for s in SPECS:
        assert s.transport in {"tcp", "udp"}
        assert 0 < s.default_port < 65536
        assert callable(s.probe)


# probers (patched I/O)


def test_probe_mqtt_wires_build_and_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_tcp(host: str, port: int, payload: bytes, timeout: float,
                       recv_size: int = 4096) -> bytes:
        assert payload[0] == 0x10  # our CONNECT reached the transport
        return b"\x20\x02\x00\x00"  # CONNACK accepted

    monkeypatch.setattr(iot, "tcp_request", fake_tcp)
    result = asyncio.run(iot.probe_mqtt("10.0.0.1", 1883, 0.1))
    assert result is not None
    assert result.protocol == "mqtt"
    assert result.is_ot is False
    assert result.device_info["anonymous_accepted"] == "true"
    assert result.extra["anonymous_accepted"] is True
    assert "tls" not in result.extra


def test_probe_mqtt_marks_tls_on_8883(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_tcp(host: str, port: int, payload: bytes, timeout: float,
                       recv_size: int = 4096) -> bytes:
        return b"\x20\x02\x00\x00"

    monkeypatch.setattr(iot, "tcp_request", fake_tcp)
    result = asyncio.run(iot.probe_mqtt("10.0.0.1", 8883, 0.1))
    assert result is not None
    assert result.extra.get("tls") is True


def test_probe_returns_none_without_data(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_udp(host: str, port: int, payload: bytes, timeout: float) -> None:
        return None

    monkeypatch.setattr(iot, "udp_request", fake_udp)
    assert asyncio.run(iot.probe_coap("10.0.0.1", 5683, 0.1)) is None


def test_probe_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom(host: str, port: int, payload: bytes, timeout: float) -> bytes:
        raise OSError("transport blew up")

    monkeypatch.setattr(iot, "udp_request", boom)
    # A prober must swallow transport errors and return None, never propagate.
    assert asyncio.run(iot.probe_ssdp("10.0.0.1", 1900, 0.1)) is None
