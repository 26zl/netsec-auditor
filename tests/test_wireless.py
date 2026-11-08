"""Tests for wireless inventory types and security assessment."""

from __future__ import annotations

from typing import Any

from netsec_auditor.wireless import base
from netsec_auditor.wireless.base import (
    AccessPoint,
    BleDevice,
    WirelessInventory,
    assess_access_point,
    assess_ble_device,
    band_for_channel,
    detect_evil_twins,
    sanitize_name,
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


def test_inventory_merge_fills_gaps_and_reassesses() -> None:
    inv = WirelessInventory()
    inv.add_ap(AccessPoint(bssid="AA:BB:CC:00:00:03", signal_dbm=-70))
    inv.add_ap(AccessPoint(
        bssid="AA:BB:CC:00:00:03", ssid="Netgear-Guest", channel=11, band="2.4GHz",
        encryption="wpa2", cipher="CCMP+TKIP", auth="PSK", wps=True,
        latitude=59.91, longitude=10.75, signal_dbm=-80,
    ))
    ap = inv.aps()[0]
    assert ap.channel == 11
    assert ap.band == "2.4GHz"
    assert ap.encryption == "wpa2"
    assert ap.cipher == "CCMP+TKIP"
    assert (ap.latitude, ap.longitude) == (59.91, 10.75)
    assert ap.signal_dbm == -70  # strongest sighting wins
    # The assessment must be re-run against the merged record.
    assert any("TKIP" in i for i in ap.issues)
    assert any("WPS" in i for i in ap.issues)
    assert any("guessable SSID" in i for i in ap.issues)


def test_inventory_keys_bssid_less_aps_by_ssid() -> None:
    inv = WirelessInventory()
    inv.add_ap(AccessPoint(bssid="", ssid="MacOnly", signal_dbm=-50))
    inv.add_ap(AccessPoint(bssid="", ssid="MacOnly", signal_dbm=-40))
    inv.add_ap(AccessPoint(bssid="", ssid="Other", signal_dbm=-60))
    assert len(inv.aps()) == 2
    assert inv.aps()[0].signal_dbm == -40


def test_detect_evil_twins_on_differing_encryption() -> None:
    aps = [
        AccessPoint(bssid="00:00:00:00:00:01", ssid="Guest", encryption="wpa2"),
        AccessPoint(bssid="00:00:00:00:00:02", ssid="Guest", encryption="open"),
    ]
    detect_evil_twins(aps)
    assert any("evil-twin" in i for i in aps[0].issues)
    assert any("differing encryption" in i for i in aps[1].issues)


def test_detect_evil_twins_on_differing_vendor() -> None:
    aps = [
        AccessPoint(bssid="00:00:00:00:00:01", ssid="Corp", encryption="wpa2"),
        AccessPoint(bssid="AA:BB:CC:00:00:02", ssid="Corp", encryption="wpa2"),
    ]
    detect_evil_twins(aps)
    assert any("different vendors" in i for i in aps[0].issues)


def test_detect_evil_twins_ignores_ordinary_dual_band_router() -> None:
    # Same SSID, same vendor, same encryption on 2.4 and 5 GHz: normal, not rogue.
    aps = [
        AccessPoint(bssid="00:00:00:00:00:01", ssid="Home", encryption="wpa2", band="2.4GHz"),
        AccessPoint(bssid="00:00:00:00:00:02", ssid="Home", encryption="wpa2", band="5GHz"),
    ]
    detect_evil_twins(aps)
    assert all(not ap.issues for ap in aps)


def test_detect_evil_twins_skips_aps_without_a_bssid() -> None:
    # macOS can withhold BSSIDs; those APs cannot be told apart, so they must
    # not be grouped into a finding.
    aps = [
        AccessPoint(bssid="", ssid="Cafe", encryption="wpa2"),
        AccessPoint(bssid="", ssid="Cafe", encryption="open"),
    ]
    detect_evil_twins(aps)
    assert all(not ap.issues for ap in aps)


def test_wpa3_is_not_told_to_consider_wpa3() -> None:
    ap = AccessPoint(bssid="00:11:22:33:44:77", ssid="Modern", encryption="wpa3", auth="SAE")
    assert all("consider WPA3" not in i for i in assess_access_point(ap))


def test_owe_is_not_reported_as_an_open_network() -> None:
    ap = AccessPoint(bssid="00:11:22:33:44:88", ssid="EnhancedOpen",
                     encryption="owe", cipher="CCMP", auth="OWE")
    assert assess_access_point(ap) == []


def test_mixed_mode_cipher_string_still_flags_tkip() -> None:
    ap = AccessPoint(bssid="00:11:22:33:44:99", encryption="wpa2", cipher="CCMP+TKIP")
    assert ap.ciphers == ["CCMP", "TKIP"]
    assert any("TKIP" in i for i in assess_access_point(ap))


def test_sanitize_name_drops_control_characters_and_truncates() -> None:
    assert sanitize_name("Net\x1b[31mWork\x00\n") == "Net[31mWork"
    assert len(sanitize_name("A" * 200)) == 64
    assert sanitize_name("") == ""


def test_band_for_channel_is_unambiguous_or_empty() -> None:
    assert band_for_channel(6) == "2.4GHz"
    assert band_for_channel(36) == "5GHz"
    # 15-31 are unassigned in 2.4 GHz and 6 GHz reuses 5 GHz numbering.
    assert band_for_channel(20) == ""
    assert band_for_channel(233) == ""


def test_assess_ble_device() -> None:
    dev = BleDevice(address="DE:AD:BE:EF:00:01", name="", connectable=True, services=[])
    assert any("Connectable BLE" in i for i in assess_ble_device(dev))


def test_assess_ble_device_unknown_connectable_is_not_flagged() -> None:
    dev = BleDevice(address="DE:AD:BE:EF:00:02", name="", services=[])
    assert dev.connectable is None
    assert assess_ble_device(dev) == []


def test_anonymous_aps_are_not_merged_by_channel_and_encryption() -> None:
    # macOS hides both BSSID and SSID; two distinct neighbours that share a
    # channel and encryption must stay two rows, not collapse into one.
    inv = WirelessInventory()
    for _ in range(3):
        ap = AccessPoint(bssid="", ssid="", channel=6, encryption="wpa2")
        ap.issues = assess_access_point(ap)
        inv.add_ap(ap)
    assert len(inv.aps()) == 3


def test_identified_aps_still_deduplicate_by_bssid() -> None:
    inv = WirelessInventory()
    inv.add_ap(AccessPoint(bssid="AA:BB:CC:11:22:33", ssid="Home", signal_dbm=-70))
    inv.add_ap(AccessPoint(bssid="AA:BB:CC:11:22:33", ssid="Home", signal_dbm=-55))
    rows = inv.aps()
    assert len(rows) == 1
    assert rows[0].signal_dbm == -55  # strongest sighting wins


def _assessed(**fields: Any) -> AccessPoint:
    ap = AccessPoint(**fields)
    ap.issues = assess_access_point(ap)
    return ap


def _cloned_flags(ap: AccessPoint) -> list[str]:
    return [i for i in ap.issues if i.startswith("Possible cloned-BSSID evil twin")]


def test_inventory_keeps_a_cloned_bssid_apart_and_flags_both_sightings() -> None:
    # An open evil twin that copies the real AP's BSSID on another channel must
    # not be merged into (or hidden behind) the real WPA2 network.
    inv = WirelessInventory()
    inv.add_ap(_assessed(bssid="AA:BB:CC:00:00:01", ssid="CorpWiFi", channel=6,
                         encryption="wpa2", auth="PSK"))
    inv.add_ap(_assessed(bssid="aa:bb:cc:00:00:01", ssid="CorpWiFi", channel=11,
                         encryption="open"))
    rows = sorted(inv.aps(), key=lambda ap: ap.channel)
    assert [(ap.channel, ap.encryption) for ap in rows] == [(6, "wpa2"), (11, "open")]
    expected = (
        "Possible cloned-BSSID evil twin: one BSSID advertised with conflicting "
        "encryption (open, wpa2); channel (6, 11)"
    )
    assert all(_cloned_flags(ap) == [expected] for ap in rows)
    assert any("Open network" in i for i in rows[1].issues)
    assert all("AA:BB:CC" not in i.upper() for ap in rows for i in ap.issues)  # redaction-safe


def test_inventory_merges_a_sparse_sighting_without_flagging() -> None:
    # A hidden-SSID beacon (no SSID, no channel) is the same AP, not a clone.
    inv = WirelessInventory()
    inv.add_ap(_assessed(bssid="AA:BB:CC:00:00:02", ssid="Hidden", channel=6, encryption="wpa2"))
    inv.add_ap(_assessed(bssid="AA:BB:CC:00:00:02", encryption="wpa2", signal_dbm=-40))
    rows = inv.aps()
    assert len(rows) == 1
    assert rows[0].signal_dbm == -40
    assert _cloned_flags(rows[0]) == []


def test_inventory_bounds_sightings_and_clients_per_bssid() -> None:
    inv = WirelessInventory()
    for channel in range(1, 21):
        inv.add_ap(AccessPoint(bssid="AA:BB:CC:00:00:03", channel=channel, encryption="wpa2"))
    assert len(inv.aps()) == base.MAX_SIGHTINGS_PER_BSSID

    many = [f"02:00:00:00:{n // 256:02X}:{n % 256:02X}" for n in range(300)]
    inv.add_ap(AccessPoint(bssid="AA:BB:CC:00:00:04", encryption="wpa2", clients=[]))
    inv.add_ap(AccessPoint(bssid="AA:BB:CC:00:00:04", encryption="wpa2", clients=many))
    merged = next(ap for ap in inv.aps() if ap.bssid == "AA:BB:CC:00:00:04")
    assert len(merged.clients) == base.MAX_CLIENTS_PER_AP


def test_detect_evil_twins_flags_a_cloned_bssid() -> None:
    aps = [
        AccessPoint(bssid="00:00:00:00:00:01", ssid="Guest", channel=1, encryption="wpa2"),
        AccessPoint(bssid="00:00:00:00:00:01", ssid="Guest", channel=1, encryption="open"),
    ]
    detect_evil_twins(aps)
    for ap in aps:
        assert len(_cloned_flags(ap)) == 1
        assert "encryption (open, wpa2)" in _cloned_flags(ap)[0]


def test_detect_evil_twins_flags_lookalike_ssids_separately_from_duplicates() -> None:
    cyrillic_o = "C\u043erpWiFi"
    fullwidth = "\uff23\uff4f\uff52\uff50WiFi"
    aps = [
        AccessPoint(bssid="00:00:00:00:00:01", ssid="CorpWiFi", encryption="wpa2"),
        AccessPoint(bssid="00:00:00:00:00:02", ssid=cyrillic_o, encryption="wpa2"),
        AccessPoint(bssid="00:00:00:00:00:03", ssid=fullwidth, encryption="wpa2"),
        AccessPoint(bssid="00:00:00:00:00:04", ssid="Unrelated", encryption="wpa2"),
    ]
    detect_evil_twins(aps)
    lookalike = [[i for i in ap.issues if i.startswith("Lookalike SSID")] for ap in aps]
    assert [len(flags) for flags in lookalike] == [1, 1, 1, 0]
    assert "'CorpWiFi'" in lookalike[1][0]
    assert all(not i.startswith("Possible rogue/evil-twin") for ap in aps for i in ap.issues)


def test_ssid_skeleton_folds_case_width_and_homoglyphs() -> None:
    skeleton = base.ssid_skeleton
    assert skeleton("CorpWiFi") == skeleton("c\u043erpwifi") == skeleton("\uff23orp\uff37iFi")
    assert skeleton("\u0391\u0392\u0395") == skeleton("ABE")  # Greek capitals
    assert skeleton("\u0441\u0430f\u0435") == skeleton("cafe")  # Cyrillic lower-case
    assert skeleton("CorpWiFi") != skeleton("CorpWiFi2")
