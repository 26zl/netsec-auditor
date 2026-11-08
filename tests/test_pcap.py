"""Tests for offline pcap analysis.

The credential scanner is tested on raw payload bytes. Capture-file tests build
small pcap/pcapng files byte by byte and only read them back with scapy, so no
packet is ever constructed or sent.
"""

from __future__ import annotations

import gzip
import socket
import struct

import pytest

from netsec_auditor.capture import pcap
from netsec_auditor.capture.pcap import analyze_pcap, load_pcap, scan_cleartext_credentials


def test_http_basic_redacts_password() -> None:
    # base64("admin:secret") == "YWRtaW46c2VjcmV0"
    payload = b"GET / HTTP/1.1\r\nAuthorization: Basic YWRtaW46c2VjcmV0\r\n\r\n"
    findings = scan_cleartext_credentials([("10.0.0.5", "10.0.0.1", 80, payload)])
    assert findings
    ev = findings[0]["evidence"]
    assert "admin" in ev
    assert "secret" not in ev
    assert findings[0]["severity"] == "high"


def test_ftp_user_pass_redacted() -> None:
    records = [
        ("10.0.0.5", "10.0.0.1", 21, b"USER admin\r\n"),
        ("10.0.0.5", "10.0.0.1", 21, b"PASS hunter2\r\n"),
    ]
    findings = scan_cleartext_credentials(records)
    joined = " ".join(f["evidence"] for f in findings)
    assert "admin" in joined
    assert "hunter2" not in joined  # password must be redacted


def test_snmp_default_community_flagged() -> None:
    # Minimal SNMP v2c message: SEQ { INTEGER version=1, OCTET STRING "public", ... }
    payload = bytes([0x30, 0x0b, 0x02, 0x01, 0x01, 0x04, 0x06]) + b"public"
    findings = scan_cleartext_credentials([("10.0.0.5", "10.0.0.1", 161, payload)])
    assert any("public" in f["evidence"] for f in findings)


def test_no_secret_no_findings() -> None:
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    assert scan_cleartext_credentials([("10.0.0.5", "10.0.0.1", 80, payload)]) == []


def test_malformed_records_skipped() -> None:
    assert scan_cleartext_credentials([("bad",), None]) == []  # type: ignore[list-item]


def test_telnet_prompt_is_detected_and_attributed_to_the_server() -> None:
    # Records are oriented at the server (second element), so a login prompt
    # travelling server -> client is still attributed to the telnet server.
    from netsec_auditor.capture.pcap import _CREDENTIAL_PORTS, scan_cleartext_credentials

    assert 23 in _CREDENTIAL_PORTS
    findings = scan_cleartext_credentials([("10.0.0.9", "10.0.0.5", 23, b"\r\nlogin: ")])
    assert [f["protocol"] for f in findings] == ["telnet"]
    assert findings[0]["host"] == "10.0.0.5"


# Capture files


def _frame(dst_port: int, payload: bytes, src: str = "10.0.0.5", dst: str = "10.0.0.1") -> bytes:
    """An Ethernet/IPv4/TCP frame (checksums left at zero; scapy does not verify them)."""
    tcp = struct.pack("!HHIIBBHHH", 40000, dst_port, 0, 0, 5 << 4, 0x18, 65535, 0, 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 0, 0, 64, 6, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    ether = bytes.fromhex("020000000001020000000002") + b"\x08\x00"
    return ether + ip + tcp + payload


def _pcap(frames: list[bytes]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for frame in frames:
        out += struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    return out


def test_analyze_pcap_reports_each_distinct_credential_once(tmp_path) -> None:
    path = tmp_path / "ftp.pcap"
    path.write_bytes(_pcap([_frame(21, b"USER alice\r\n")] * 3 + [_frame(80, b"GET /\r\n\r\n")]))
    result = analyze_pcap(path)
    assert result["packet_count"] == 4
    assert [h["ip"] for h in result["hosts"]] == ["10.0.0.1", "10.0.0.5"]
    assert [c["evidence"] for c in result["credentials"]] == ["FTP USER alice"]


def test_analyze_pcap_bounds_the_credential_list(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(pcap, "_MAX_CREDENTIAL_FINDINGS", 2)
    path = tmp_path / "many.pcap"
    path.write_bytes(_pcap([_frame(21, f"USER user{n}\r\n".encode()) for n in range(5)]))
    result = analyze_pcap(path)
    assert result["packet_count"] == 5
    assert [c["evidence"] for c in result["credentials"]] == ["FTP USER user0", "FTP USER user1"]


def test_capture_readers_refuse_gzip_compressed_files(tmp_path) -> None:
    # scapy would inflate it transparently: a few MiB can expand to a 4 GiB record.
    path = tmp_path / "capture.pcap"
    path.write_bytes(gzip.compress(_pcap([_frame(21, b"USER alice\r\n")])))
    for reader in (analyze_pcap, load_pcap):
        with pytest.raises(pcap.CaptureFormatError, match="gzip"):
            reader(path)


def test_capture_readers_refuse_an_oversized_pcapng_block(tmp_path) -> None:
    section = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    forged = struct.pack("<II", 6, 64 * 1024 * 1024 + 12) + b"\0" * 16  # claims a 64 MiB packet
    path = tmp_path / "capture.pcapng"
    path.write_bytes(section + forged)
    for reader in (analyze_pcap, load_pcap):
        with pytest.raises(pcap.CaptureFormatError, match="exceeds"):
            reader(path)


@pytest.mark.parametrize(
    ("name", "content", "reason"),
    [
        ("missing.pcap", None, "not found"),
        ("empty.pcap", b"", "not a pcap/pcapng capture"),
        ("notes.pcap", b"this is not a capture file\n", "not a pcap/pcapng capture"),
    ],
)
def test_capture_readers_raise_for_files_that_are_not_captures(
    tmp_path, name, content, reason
) -> None:
    path = tmp_path / name
    if content is not None:
        path.write_bytes(content)
    for reader in (analyze_pcap, load_pcap):
        with pytest.raises(pcap.CaptureFormatError, match=reason):
            reader(path)


def test_capture_readers_raise_for_a_directory(tmp_path) -> None:
    with pytest.raises(pcap.CaptureFormatError, match="not a regular file"):
        analyze_pcap(tmp_path)


def test_truncated_capture_yields_the_packets_before_the_cut(tmp_path) -> None:
    path = tmp_path / "cut.pcap"
    path.write_bytes(_pcap([_frame(21, b"USER alice\r\n")] * 2) + b"\x00\x00\x00")
    assert analyze_pcap(path)["packet_count"] == 2


def test_load_pcap_closes_the_capture_file(tmp_path, monkeypatch) -> None:
    closed: list[bool] = []
    original = pcap._BoundedReader.close

    def tracking_close(self: pcap._BoundedReader) -> None:
        closed.append(True)
        original(self)

    monkeypatch.setattr(pcap._BoundedReader, "close", tracking_close)
    path = tmp_path / "ok.pcap"
    path.write_bytes(_pcap([_frame(502, b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01")]))
    inventory = load_pcap(path)
    assert closed == [True]
    assert {h["ip"]: h["is_ot"] for h in inventory.hosts()} == {"10.0.0.1": True, "10.0.0.5": False}


def _l2_frame(src: str, dst: str, ethertype: int, payload: bytes) -> bytes:
    """A raw Ethernet frame behind a priority-tagged 802.1Q header."""
    macs = bytes.fromhex(dst.replace(":", "") + src.replace(":", ""))
    return macs + struct.pack("!HHH", 0x8100, 6 << 13, ethertype) + payload


def test_analyze_and_load_pcap_name_industrial_protocols(tmp_path) -> None:
    identity = struct.pack("!BBHH", 2, 2, 2 + 6, 0) + b"plc-01"  # NameOfStation: BlockInfo + name
    dcp_reply = struct.pack("!HBBIHH", 0xFEFF, 5, 1, 1, 0, len(identity)) + identity
    path = tmp_path / "ot.pcap"
    path.write_bytes(_pcap([
        _frame(502, b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"),  # Modbus/TCP
        _l2_frame("00:0e:8c:00:00:01", "00:1b:1b:00:00:02", 0x8892, dcp_reply),
        _l2_frame("00:50:c2:00:00:07", "01:0c:cd:04:00:01", 0x88BA, b"\x40\x00" * 8),  # SV
    ]))
    hosts = analyze_pcap(path)["hosts"]
    assert {h["ip"]: h["protocols"] for h in hosts if h["ip"]} == {
        "10.0.0.1": ["modbus"],
        "10.0.0.5": ["modbus"],
    }
    stations = {h["mac"]: (h["protocols"], h["is_ot"], h["device"]) for h in hosts if not h["ip"]}
    assert stations == {
        "00:0e:8c:00:00:01": (["profinet"], True, {"name_of_station": "plc-01"}),
        "00:1b:1b:00:00:02": (["profinet"], True, {}),
        "00:50:c2:00:00:07": (["iec61850-sv"], True, {}),
    }
    assert load_pcap(path).hosts() == hosts
