"""Tests for passive and fast network discovery (no network, no scapy)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from netsec_auditor.discovery.fast import TargetLimitError, batched, expand_targets, fast_discover
from netsec_auditor.discovery.passive import PassiveInventory, handle_packet


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
    assert ot["protocols"] == ["tcp"]

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
