"""Tests for wireless inventory types and security assessment."""

from __future__ import annotations

from netsec_auditor.wireless.base import (
    AccessPoint,
    BleDevice,
    WirelessInventory,
    assess_access_point,
    assess_ble_device,
    detect_evil_twins,
)


def test_assess_open_and_wep_and_wps() -> None:
    open_ap = AccessPoint(bssid="00:11:22:33:44:55", ssid="Free", encryption="open")
    issues = assess_access_point(open_ap)
    assert any("Open network" in i for i in issues)

    wep_ap = AccessPoint(bssid="00:11:22:33:44:66", ssid="Old", encryption="wep", wps=True)
    issues = assess_access_point(wep_ap)
    assert any("WEP" in i for i in issues)
    assert any("WPS" in i for i in issues)


def test_wpa2_suggests_wpa3() -> None:
    ap = AccessPoint(bssid="a", ssid="Corp", encryption="wpa2", auth="psk")
    assert any("WPA3" in i for i in assess_access_point(ap))


def test_inventory_merges_and_sorts_by_signal() -> None:
    inv = WirelessInventory()
    inv.add_ap(AccessPoint(bssid="AA:BB:CC:00:00:01", ssid="X", signal_dbm=-70))
    inv.add_ap(AccessPoint(bssid="aa:bb:cc:00:00:01", ssid="X", signal_dbm=-40))  # same, stronger
    inv.add_ap(AccessPoint(bssid="AA:BB:CC:00:00:02", ssid="Y", signal_dbm=-55))
    aps = inv.aps()
    assert len(aps) == 2  # merged by BSSID (case-insensitive)
    assert aps[0].signal_dbm == -40  # strongest first


def test_detect_evil_twins() -> None:
    aps = [
        AccessPoint(bssid="00:00:00:00:00:01", ssid="Guest", encryption="wpa2"),
        AccessPoint(bssid="00:00:00:00:00:02", ssid="Guest", encryption="open"),
    ]
    detect_evil_twins(aps)
    assert any("evil-twin" in i for i in aps[0].issues)
    assert any("differing encryption" in i for i in aps[1].issues)


def test_assess_ble_device() -> None:
    dev = BleDevice(address="DE:AD:BE:EF:00:01", name="", connectable=True, services=[])
    assert any("Connectable BLE" in i for i in assess_ble_device(dev))
