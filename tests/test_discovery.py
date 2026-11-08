"""Tests for passive and fast network discovery (no network).

Frames are built as raw bytes and, where a test needs a real scapy packet, only
dissected with scapy, so no packet is ever constructed or sent.
"""

from __future__ import annotations

import asyncio
import random
import struct
import threading
import time
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest

from netsec_auditor.discovery import passive
from netsec_auditor.discovery.fast import TargetLimitError, batched, expand_targets, fast_discover
from netsec_auditor.discovery.passive import PassiveInventory, PassiveSniffer, handle_packet
from netsec_auditor.profiles import OT_ETHERTYPE_NAMES


def test_add_observation_merges_and_flags() -> None:
    inv = PassiveInventory()
    # Two flows toward the same host: one on Modbus (OT), one on HTTP.
    inv.add_observation(
        "10.0.0.1", "10.0.0.2", "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", 502, "tcp"
    )
    inv.add_observation(
        "10.0.0.9", "10.0.0.2", "cc:cc:cc:cc:cc:cc", "bb:bb:bb:bb:bb:bb", 80, "tcp"
    )
    # A separate host reached on MQTT (IoT).
    inv.add_observation("10.0.0.1", "10.0.0.3", None, "dd:dd:dd:dd:dd:dd", 1883, "tcp")

    hosts = {h["ip"]: h for h in inv.hosts()}

    ot = hosts["10.0.0.2"]
    assert ot["is_ot"] is True
    assert ot["is_iot"] is False
    assert ot["mac"] == "bb:bb:bb:bb:bb:bb"
    assert ot["ports"] == [80, 502]  # merged and sorted
    assert ot["protocols"] == ["modbus", "tcp"]  # the OT port is named, HTTP stays tcp

    iot = hosts["10.0.0.3"]
    assert iot["is_iot"] is True
    assert iot["is_ot"] is False
    assert iot["ports"] == [1883]

    # A host only ever seen as a source keeps its MAC but has no service ports.
    src = hosts["10.0.0.1"]
    assert src["mac"] == "aa:aa:aa:aa:aa:aa"
    assert src["ports"] == []
    assert src["is_ot"] is False


def test_hosts_snapshot_is_sorted_and_serializable() -> None:
    inv = PassiveInventory()
    inv.add_observation("10.0.0.20", "10.0.0.2", None, None, 443, "tcp")
    inv.add_observation("10.0.0.3", "10.0.0.2", None, None, 22, "tcp")

    snapshot = inv.hosts()
    ips = [h["ip"] for h in snapshot]
    assert ips == ["10.0.0.2", "10.0.0.3", "10.0.0.20"]  # numeric IP ordering
    for host in snapshot:
        assert isinstance(host["ports"], list)
        assert isinstance(host["protocols"], list)


def test_handle_packet_with_flat_object_no_scapy() -> None:
    inv = PassiveInventory()
    pkt = SimpleNamespace(
        src_ip="192.168.0.10",
        dst_ip="192.168.0.20",
        src_mac="aa:bb:cc:dd:ee:ff",
        dst_mac="11:22:33:44:55:66",
        dst_port=502,
        protocol="tcp",
    )
    handle_packet(inv, pkt)

    hosts = {h["ip"]: h for h in inv.hosts()}
    assert hosts["192.168.0.20"]["is_ot"] is True
    assert hosts["192.168.0.20"]["ports"] == [502]
    assert hosts["192.168.0.20"]["mac"] == "11:22:33:44:55:66"
    assert hosts["192.168.0.10"]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_handle_packet_with_mapping() -> None:
    inv = PassiveInventory()
    handle_packet(
        inv,
        {
            "src_ip": "192.168.0.10",
            "dst_ip": "192.168.0.30",
            "dst_port": 1883,
            "protocol": "tcp",
        },
    )
    hosts = {h["ip"]: h for h in inv.hosts()}
    assert hosts["192.168.0.30"]["is_iot"] is True


def test_handle_packet_ignores_non_ip() -> None:
    inv = PassiveInventory()
    handle_packet(inv, SimpleNamespace())  # nothing usable to read
    handle_packet(inv, {"protocol": "arp"})  # no IP endpoints
    assert inv.hosts() == []


def test_expand_targets_usable_hosts() -> None:
    assert expand_targets(["192.168.1.0/30"]) == ["192.168.1.1", "192.168.1.2"]


def test_expand_targets_dedupes_sorts_and_skips_invalid() -> None:
    result = expand_targets(["10.0.0.2", "10.0.0.1", "10.0.0.1", "not-a-cidr", ""])
    assert result == ["10.0.0.1", "10.0.0.2"]


def test_expand_targets_rejects_unsafe_size() -> None:
    with pytest.raises(TargetLimitError):
        expand_targets(["10.0.0.0/24"], max_targets=10)


def test_batched_chunks() -> None:
    assert list(batched(range(10), 4)) == [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9]]


def test_batched_exact_multiple() -> None:
    assert list(batched(range(6), 3)) == [[0, 1, 2], [3, 4, 5]]


def test_batched_rejects_bad_size() -> None:
    with pytest.raises(ValueError):
        list(batched(range(3), 0))


async def test_fast_discover_no_targets_returns_empty() -> None:
    # Invalid/empty ranges expand to nothing, so no network I/O occurs.
    assert await fast_discover(["not-a-cidr"]) == []
    assert await fast_discover([]) == []


def test_passive_inventory_caps_distinct_hosts() -> None:
    inv = PassiveInventory(max_hosts=2)
    inv.add_observation("10.0.0.1", "10.0.0.2", dst_port=80, protocol="tcp")
    inv.add_observation("10.0.0.3", "10.0.0.2", dst_port=502, protocol="tcp")  # 10.0.0.3 dropped
    assert [h["ip"] for h in inv.hosts()] == ["10.0.0.1", "10.0.0.2"]
    assert inv.hosts()[1]["ports"] == [80, 502]  # known hosts keep updating
    assert inv.dropped_hosts == 1


class _FakeSniffer:
    """Stand-in for scapy's AsyncSniffer, driven by a daemon thread."""

    def __init__(self, behaviour: Callable[[_FakeSniffer], None], **options: Any) -> None:
        self.options = options
        self.stop_requested = threading.Event()
        self.exception: Exception | None = None
        self.thread = threading.Thread(target=self._run, args=(behaviour,), daemon=True)

    def _run(self, behaviour: Callable[[_FakeSniffer], None]) -> None:
        try:
            behaviour(self)
        except Exception as exc:  # scapy keeps the error and re-raises it from join()
            self.exception = exc

    def start(self) -> None:
        self.thread.start()

    def stop(self, join: bool = True) -> None:
        self.stop_requested.set()

    def join(self, timeout: float | None = None) -> None:
        self.thread.join(timeout)
        if self.exception is not None:
            raise self.exception


def _install_sniffer(
    monkeypatch: pytest.MonkeyPatch, behaviour: Callable[[_FakeSniffer], None]
) -> list[_FakeSniffer]:
    sniffers: list[_FakeSniffer] = []

    def factory(**options: Any) -> _FakeSniffer:
        sniffers.append(_FakeSniffer(behaviour, **options))
        return sniffers[-1]

    monkeypatch.setattr(passive, "_async_sniffer", factory)
    monkeypatch.setattr(passive, "_is_root", lambda: True)
    return sniffers


async def test_sniff_for_stops_promptly_when_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    sniffers = _install_sniffer(monkeypatch, lambda s: s.stop_requested.wait(30))
    task = asyncio.create_task(PassiveSniffer(bpf_filter="tcp").sniff_for(30.0, iface="eth0"))
    await asyncio.sleep(0.2)
    cancelled_at = time.monotonic()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert time.monotonic() - cancelled_at < 1.0
    assert sniffers[0].stop_requested.is_set()
    assert not sniffers[0].thread.is_alive()
    assert sniffers[0].options["filter"] == "tcp"
    assert sniffers[0].options["iface"] == "eth0"


async def test_sniff_for_reports_a_capture_failure_without_waiting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_sniffer: _FakeSniffer) -> None:
        raise OSError("No such device")

    _install_sniffer(monkeypatch, fail)
    started = time.monotonic()
    inventory = await PassiveSniffer().sniff_for(30.0, iface="nope0")
    assert time.monotonic() - started < 2.0
    assert inventory.hosts() == []


async def test_capture_for_delivers_packets_until_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deliver(sniffer: _FakeSniffer) -> None:
        prn = sniffer.options["prn"]
        prn({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 502, "protocol": "tcp"})
        sniffer.stop_requested.wait(30)
        prn({"src_ip": "10.0.0.9", "dst_ip": "10.0.0.8"})  # after stop: must be ignored

    sniffers = _install_sniffer(monkeypatch, deliver)
    inv = PassiveInventory()
    started = time.monotonic()
    await passive.capture_for(0.3, lambda pkt: handle_packet(inv, pkt), store=False)
    assert 0.25 <= time.monotonic() - started < 1.5
    sniffers[0].thread.join(1)
    assert [h["ip"] for h in inv.hosts()] == ["10.0.0.1", "10.0.0.2"]


async def test_capture_for_rejects_a_nan_duration(monkeypatch: pytest.MonkeyPatch) -> None:
    sniffers = _install_sniffer(monkeypatch, lambda s: s.stop_requested.wait(30))
    with pytest.raises(ValueError, match="non-negative"):
        await passive.capture_for(float("nan"), lambda _pkt: None)
    assert sniffers == []  # nothing was started


# Industrial protocols


PLC = "00:0e:8c:00:00:01"
CONTROLLER = "00:1b:1b:00:00:02"


def _ether(src: str, dst: str, ethertype: int, payload: bytes, vlan: int | None = None) -> bytes:
    """A raw Ethernet frame, optionally with an 802.1Q tag (priority 6, as PROFINET uses)."""
    tag = struct.pack("!HH", 0x8100, (6 << 13) | vlan) if vlan is not None else b""
    macs = bytes.fromhex(dst.replace(":", "") + src.replace(":", ""))
    return macs + tag + struct.pack("!H", ethertype) + payload


def _ipv4_tcp(src: str, dst: str, sport: int, dport: int) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x18, 65535, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0,
                     bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return _ether(PLC, CONTROLLER, 0x0800, ip + tcp)


def _dissect(frame: bytes) -> Any:
    from scapy.all import Ether

    return Ether(frame)


def _dcp_identify_response(
    name: bytes, station_type: bytes, vendor_id: int, device_id: int
) -> bytes:
    """A PROFINET DCP Identify response payload (FrameID 0xFEFF) with three device blocks."""

    def block(option: int, suboption: int, value: bytes) -> bytes:
        body = b"\x00\x00" + value  # BlockInfo, then the value
        return struct.pack("!BBH", option, suboption, len(body)) + body + b"\x00" * (len(body) & 1)

    blocks = (
        block(2, 1, station_type)
        + block(2, 2, name)
        + block(2, 3, struct.pack("!HH", vendor_id, device_id))
    )
    return struct.pack("!HBBIHH", 0xFEFF, 5, 1, 0x1234, 0, len(blocks)) + blocks


def _l2_host(mac: str, protocol: str, device: dict[str, str] | None = None) -> dict[str, Any]:
    return {"ip": "", "mac": mac, "ports": [], "protocols": [protocol], "is_ot": True,
            "is_iot": False, "device": device or {}}


def test_layer2_industrial_frames_become_ot_hosts_keyed_by_mac() -> None:
    ethercat = struct.pack("<H", 14 | (1 << 12)) + struct.pack(
        "<BBHHHH", 0x07, 0, 0, 0x0130, 2, 0
    ) + b"\x00" * 4  # one BRD datagram
    inv = PassiveInventory()
    for frame in (
        _ether(CONTROLLER, PLC, 0x8892, b"\x80\x00" + b"\x00" * 40),  # PROFINET RT, unicast
        _ether("00:50:c2:00:00:03", "01:0c:cd:01:00:01", 0x88B8, b"\x00\x01" * 8, vlan=0),
        _ether("02:00:00:00:00:04", "ff:ff:ff:ff:ff:ff", 0x88A4, ethercat),
        _ether("02:00:00:00:00:05", "01:80:c2:00:00:0e", 0x88CC, b"\x02\x07" * 8),  # LLDP
    ):
        handle_packet(inv, _dissect(frame))
    assert inv.hosts() == [
        _l2_host(PLC, "profinet"),
        _l2_host(CONTROLLER, "profinet"),
        _l2_host("00:50:c2:00:00:03", "iec61850-goose"),  # multicast destination skipped
        _l2_host("02:00:00:00:00:04", "ethercat"),  # broadcast destination skipped
    ]


@pytest.mark.parametrize(("ethertype", "name"), sorted(OT_ETHERTYPE_NAMES.items()))
def test_each_industrial_ethertype_is_recognised(ethertype: int, name: str) -> None:
    inv = PassiveInventory()
    handle_packet(inv, {"src_mac": "02:00:00:00:00:01", "dst_mac": "FF:FF:FF:FF:FF:FF",
                        "ethertype": ethertype})
    assert inv.hosts() == [_l2_host("02:00:00:00:00:01", name)]


def test_layer2_stations_share_the_host_cap() -> None:
    inv = PassiveInventory(max_hosts=2)
    inv.add_observation("10.0.0.1", None)
    for n in range(3):
        handle_packet(inv, {"src_mac": f"02:00:00:00:00:0{n}", "dst_mac": "01:0c:cd:01:00:01",
                            "ethertype": 0x88B8})
    assert [(h["ip"], h["mac"]) for h in inv.hosts()] == [
        ("10.0.0.1", ""),
        ("", "02:00:00:00:00:00"),
    ]
    assert inv.dropped_hosts == 2


def test_ip_flows_on_ot_ports_are_labelled_with_the_protocol_name() -> None:
    inv = PassiveInventory()
    inv.add_observation("10.0.0.9", "10.0.0.2", dst_port=502, protocol="tcp")
    inv.add_observation("10.0.0.9", "10.0.0.3", dst_port=2404, protocol="tcp")
    inv.add_observation("10.0.0.9", "10.0.0.4", dst_port=47808, protocol="udp")
    inv.add_observation("10.0.0.9", "10.0.0.5", dst_port=443, protocol="tcp")
    assert {h["ip"]: h["protocols"] for h in inv.hosts()} == {
        "10.0.0.2": ["modbus"],
        "10.0.0.3": ["iec-104"],
        "10.0.0.4": ["bacnet"],
        "10.0.0.5": ["tcp"],
        "10.0.0.9": ["bacnet", "iec-104", "modbus", "tcp"],
    }


def test_reply_from_an_ot_server_is_credited_to_the_server() -> None:
    # Only the PLC's Modbus reply was captured: port 502 belongs to the PLC, and
    # the HMI's ephemeral port is not a service.
    inv = PassiveInventory()
    handle_packet(inv, _dissect(_ipv4_tcp("10.0.0.2", "10.0.0.9", sport=502, dport=50123)))
    hosts = {h["ip"]: h for h in inv.hosts()}
    assert (hosts["10.0.0.2"]["ports"], hosts["10.0.0.2"]["is_ot"]) == ([502], True)
    assert (hosts["10.0.0.2"]["mac"], hosts["10.0.0.9"]["mac"]) == (PLC, CONTROLLER)
    assert (hosts["10.0.0.9"]["ports"], hosts["10.0.0.9"]["protocols"]) == ([], ["modbus"])


def test_profinet_dcp_identify_response_names_the_station() -> None:
    inv = PassiveInventory()
    hostile_name = b"plc-line-1\x1b[2J" + b"x" * 200
    reply = _dcp_identify_response(hostile_name, b"S7-1500", vendor_id=0x002A, device_id=0x010E)
    handle_packet(inv, _dissect(_ether(PLC, CONTROLLER, 0x8892, reply, vlan=0)))
    hosts = {h["mac"]: h for h in inv.hosts()}
    assert hosts[PLC]["device"] == {
        "device_type": "S7-1500",
        "name_of_station": ("plc-line-1[2J" + "x" * 200)[:64],
        "vendor_id": "0x002a",
        "device_id": "0x010e",
    }
    assert hosts[CONTROLLER] == _l2_host(CONTROLLER, "profinet")  # identity is the sender's


def test_parse_dcp_identify_response_ignores_other_and_malformed_frames() -> None:
    parse = passive.parse_dcp_identify_response
    good = _dcp_identify_response(b"plc-1", b"ET 200SP", vendor_id=0x002A, device_id=0x0313)
    assert parse(good)["name_of_station"] == "plc-1"
    assert parse(b"") == {}
    assert parse(b"\xfe\xfe\x05\x00" + good[4:]) == {}  # an Identify request
    for cut in range(len(good)):  # every truncation is handled
        parse(good[:cut])
    oversized = good[:10] + b"\xff\xff" + good[12:] + struct.pack("!BBH", 2, 2, 0xFFFF)
    assert parse(oversized)["vendor_id"] == "0x002a"
    rng = random.Random(7)
    for _ in range(500):
        parse(good[:12] + rng.randbytes(rng.randrange(64)))
