"""Tests for passive Wi-Fi recon parsers (no radio, no root, no network).

Only the pure parsers and the read-only assessment are exercised; the scapy
monitor-mode path and OS-tool subprocesses are never invoked.
"""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

from netsec_auditor.wireless import wifi
from netsec_auditor.wireless.base import (
    AccessPoint,
    WirelessInventory,
    assess_access_point,
    detect_evil_twins,
)
from netsec_auditor.wireless.wifi import (
    parse_airport_json,
    parse_iw_scan,
    parse_nmcli,
    parse_rsn_information,
    scan_wifi,
)


def _terse_row(**fields: str) -> str:
    """Build one terse nmcli row in the explicitly requested field order.

    Values are escaped the way nmcli escapes them, so a ':' inside a value (the
    BSSID, or a crafted SSID) does not become a field separator.
    """
    order = (
        "SSID", "BSSID", "CHAN", "FREQ", "SIGNAL", "SECURITY", "WPA-FLAGS", "RSN-FLAGS",
    )
    return ":".join(fields.get(name, "").replace(":", r"\:") for name in order)


# Terse rows for the requested field list: open, WEP, WPA2-PSK, WPA3-SAE.
NMCLI_SAMPLE = "\n".join([
    _terse_row(SSID="CoffeeShop", BSSID="AA:BB:CC:00:00:01", CHAN="6",
               FREQ="2437 MHz", SIGNAL="70", SECURITY=""),
    _terse_row(SSID="OldRouter", BSSID="AA:BB:CC:00:00:02", CHAN="1",
               FREQ="2412 MHz", SIGNAL="55", SECURITY="WEP"),
    _terse_row(SSID="HomeNet", BSSID="AA:BB:CC:00:00:03", CHAN="11",
               FREQ="2462 MHz", SIGNAL="88", SECURITY="WPA2",
               **{"RSN-FLAGS": "pair_ccmp group_ccmp psk"}),
    _terse_row(SSID="SecureNet", BSSID="AA:BB:CC:00:00:04", CHAN="36",
               FREQ="5180 MHz", SIGNAL="77", SECURITY="WPA3",
               **{"RSN-FLAGS": "pair_ccmp group_ccmp sae"}),
])

# `iw dev wlan0 scan` output: WPA2-PSK + WPS, an open net, and a WEP net.
IW_SAMPLE = """BSS aa:bb:cc:11:22:33(on wlan0) -- associated
    freq: 2437
    signal: -52.00 dBm
    SSID: TestNet
    DS Parameter set: channel 6
    RSN:  * Version: 1
          * Group cipher: CCMP
          * Pairwise ciphers: CCMP
          * Authentication suites: PSK
          * Capabilities: 1-PTKSA-RC 1-GTKSA-RC (0x0000)
    WPS:  * Version: 2.0
          * Wi-Fi Protected Setup State: 2 (Configured)
BSS aa:bb:cc:11:22:44(on wlan0)
    freq: 2412
    signal: -80.00 dBm
    SSID: OpenGuest
    DS Parameter set: channel 1
    capability: ESS ShortSlotTime (0x0421)
BSS aa:bb:cc:11:22:55(on wlan0)
    freq: 2462
    signal: -60.00 dBm
    SSID: LegacyNet
    DS Parameter set: channel 11
    capability: ESS Privacy ShortSlotTime (0x0431)
"""

# Crafted `system_profiler -json SPAirPortDataType` structure.
AIRPORT_SAMPLE = {
    "SPAirPortDataType": [
        {
            "spairport_airport_interfaces": [
                {
                    "_name": "en0",
                    "spairport_airport_other_local_wireless_networks": [
                        {
                            "_name": "HomeWiFi",
                            "spairport_network_bssid": "aa:bb:cc:dd:ee:01",
                            "spairport_network_channel": "36 (5GHz, 80MHz)",
                            "spairport_security_mode": "spairport_security_mode_wpa2_personal",
                            "spairport_signal_noise": "-48 dBm / -92 dBm",
                        },
                        {
                            "_name": "GuestOpen",
                            "spairport_network_bssid": "aa:bb:cc:dd:ee:02",
                            "spairport_network_channel": "6 (2GHz, 20MHz)",
                            "spairport_security_mode": "spairport_security_mode_none",
                            "spairport_signal_noise": "-70 dBm / -90 dBm",
                        },
                    ],
                }
            ]
        }
    ]
}


def _by_bssid(aps: list[AccessPoint]) -> dict[str, AccessPoint]:
    return {ap.bssid: ap for ap in aps}


# parse_nmcli


def test_parse_nmcli_maps_encryption_and_auth() -> None:
    aps = _by_bssid(parse_nmcli(NMCLI_SAMPLE))
    assert len(aps) == 4

    open_net = aps["AA:BB:CC:00:00:01"]
    assert open_net.ssid == "CoffeeShop"
    assert open_net.channel == 6
    assert open_net.encryption == "open"
    assert open_net.auth == ""

    wep_net = aps["AA:BB:CC:00:00:02"]
    assert wep_net.encryption == "wep"

    wpa2 = aps["AA:BB:CC:00:00:03"]
    assert wpa2.encryption == "wpa2"
    assert wpa2.auth == "PSK"
    assert wpa2.cipher == "CCMP"
    assert wpa2.signal_dbm < 0  # 0-100 quality mapped into dBm range

    wpa3 = aps["AA:BB:CC:00:00:04"]
    assert wpa3.encryption == "wpa3"
    assert wpa3.auth == "SAE"
    assert wpa3.cipher == "CCMP"
    assert wpa3.band == "5GHz"


def test_parse_nmcli_ignores_blank_and_garbage_lines() -> None:
    assert parse_nmcli("") == []
    assert parse_nmcli("not-a-real-row\n\n") == []


def test_parse_nmcli_ssid_that_looks_like_a_mac_does_not_shift_columns() -> None:
    # A hostile AP can broadcast an SSID shaped like a BSSID; columns must stay
    # positional so its security posture is still read from the right field.
    row = _terse_row(SSID="AA:BB:CC:DD:EE:FF", BSSID="11:22:33:44:55:66", CHAN="11",
                     FREQ="2462 MHz", SIGNAL="80", SECURITY="WPA2",
                     **{"RSN-FLAGS": "pair_ccmp group_ccmp psk"})
    aps = parse_nmcli(row)
    assert len(aps) == 1
    ap = aps[0]
    assert ap.bssid == "11:22:33:44:55:66"
    assert ap.ssid == "AA:BB:CC:DD:EE:FF"
    assert ap.encryption == "wpa2"
    assert ap.cipher == "CCMP"
    assert -100 <= ap.signal_dbm < 0


def test_parse_nmcli_reports_every_cipher_in_mixed_mode() -> None:
    row = _terse_row(SSID="Mixed", BSSID="11:22:33:44:55:77", CHAN="6", SECURITY="WPA2",
                     **{"RSN-FLAGS": "pair_ccmp pair_tkip group_tkip psk"})
    ap = parse_nmcli(row)[0]
    assert "TKIP" in ap.ciphers
    assert any("TKIP" in issue for issue in assess_access_point(ap))


def test_parse_nmcli_owe_is_not_reported_as_open() -> None:
    row = _terse_row(SSID="EnhancedOpen", BSSID="11:22:33:44:55:88", CHAN="6",
                     SECURITY="OWE", **{"RSN-FLAGS": "pair_ccmp group_ccmp owe"})
    ap = parse_nmcli(row)[0]
    assert ap.encryption == "owe"
    assert all("Open network" not in issue for issue in assess_access_point(ap))


def test_parse_nmcli_ambiguous_channel_has_no_band() -> None:
    # Channel 20 is unassigned in 2.4 GHz and reused by 6 GHz, so with no
    # frequency to disambiguate the band must be left empty, not guessed.
    ap = parse_nmcli(_terse_row(SSID="X", BSSID="11:22:33:44:55:99", CHAN="20"))[0]
    assert ap.band == ""


async def test_scan_wifi_nmcli_argv_is_explicit_and_does_not_rescan(monkeypatch) -> None:
    seen: list[list[str]] = []

    async def fake_run(cmd: list[str], timeout: float = 20.0) -> str:
        seen.append(cmd)
        return ""

    monkeypatch.setattr("netsec_auditor.wireless.wifi.shutil.which",
                        lambda name: "/usr/bin/nmcli" if name == "nmcli" else None)
    monkeypatch.setattr("netsec_auditor.wireless.wifi._run_command", fake_run)
    await scan_wifi(iface=None, duration=0.0, use_scapy=False)

    assert len(seen) == 1
    argv = seen[0]
    assert argv[:4] == ["nmcli", "-t", "-f",
                        "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY,WPA-FLAGS,RSN-FLAGS"]
    assert argv[-2:] == ["--rescan", "no"]


# parse_iw_scan


def test_parse_iw_scan_reads_rsn_and_wps() -> None:
    aps = _by_bssid(parse_iw_scan(IW_SAMPLE))

    wpa2 = aps["AA:BB:CC:11:22:33"]
    assert wpa2.ssid == "TestNet"
    assert wpa2.channel == 6
    assert wpa2.signal_dbm == -52
    assert wpa2.encryption == "wpa2"
    assert wpa2.cipher == "CCMP"
    assert wpa2.auth == "PSK"
    assert wpa2.wps is True
    assert wpa2.band == "2.4GHz"

    open_net = aps["AA:BB:CC:11:22:44"]
    assert open_net.encryption == "open"
    assert open_net.wps is False

    wep_net = aps["AA:BB:CC:11:22:55"]
    assert wep_net.encryption == "wep"  # Privacy bit, no RSN/WPA section


def test_parse_iw_scan_empty() -> None:
    assert parse_iw_scan("") == []


def test_parse_iw_scan_keeps_every_cipher_in_mixed_mode() -> None:
    # WPA2 in CCMP+TKIP mixed mode: the weak cipher must survive parsing.
    text = """BSS aa:bb:cc:99:00:01(on wlan0)
    freq: 2437
    SSID: MixedMode
    RSN:  * Version: 1
          * Group cipher: TKIP
          * Pairwise ciphers: CCMP TKIP
          * Authentication suites: PSK
"""
    ap = parse_iw_scan(text)[0]
    assert set(ap.ciphers) == {"CCMP", "TKIP"}
    assert ap.cipher == "TKIP+CCMP"  # readable single-string form is preserved
    assert any("TKIP" in issue for issue in assess_access_point(ap))


def test_parse_iw_scan_ccmp_256_is_not_also_read_as_ccmp() -> None:
    text = """BSS aa:bb:cc:99:00:02(on wlan0)
    freq: 5180
    SSID: SuiteB
    RSN:  * Version: 1
          * Group cipher: CCMP-256
          * Pairwise ciphers: CCMP-256
          * Authentication suites: PSK
"""
    assert parse_iw_scan(text)[0].ciphers == ["CCMP-256"]


def test_parse_iw_scan_owe_is_not_reported_as_open() -> None:
    text = """BSS aa:bb:cc:99:00:03(on wlan0)
    freq: 2437
    SSID: EnhancedOpen
    RSN:  * Version: 1
          * Group cipher: CCMP
          * Pairwise ciphers: CCMP
          * Authentication suites: OWE
"""
    ap = parse_iw_scan(text)[0]
    assert ap.encryption == "owe"
    assert ap.auth == "OWE"
    assert all("Open network" not in issue for issue in assess_access_point(ap))


def test_parse_iw_scan_6ghz_frequency_yields_positive_channel() -> None:
    # 5935 MHz sits below the first 6 GHz centre frequency; the derived channel
    # must never go negative.
    text = """BSS aa:bb:cc:99:00:04(on wlan0)
    freq: 5935
    SSID: SixGig
    capability: ESS (0x0421)
BSS aa:bb:cc:99:00:05(on wlan0)
    freq: 5955
    SSID: SixGigOne
    capability: ESS (0x0421)
"""
    aps = _by_bssid(parse_iw_scan(text))
    low = aps["AA:BB:CC:99:00:04"]
    assert low.channel >= 1
    assert low.band == "6GHz"
    assert aps["AA:BB:CC:99:00:05"].channel == 1


# parse_airport_json


def test_parse_airport_json_maps_networks() -> None:
    aps = _by_bssid(parse_airport_json(AIRPORT_SAMPLE))
    assert len(aps) == 2

    home = aps["AA:BB:CC:DD:EE:01"]
    assert home.ssid == "HomeWiFi"
    assert home.encryption == "wpa2"
    assert home.cipher == "CCMP"
    assert home.auth == "PSK"
    assert home.channel == 36
    assert home.band == "5GHz"
    assert home.signal_dbm == -48

    guest = aps["AA:BB:CC:DD:EE:02"]
    assert guest.encryption == "open"
    assert guest.band == "2.4GHz"
    assert guest.signal_dbm == -70


def test_parse_airport_json_without_bssid_leaves_bssid_empty() -> None:
    # macOS withholds the BSSID without location permission; writing the SSID
    # there would fake a BSSID and break evil-twin detection.
    data = {
        "SPAirPortDataType": [
            {
                "spairport_airport_interfaces": [
                    {
                        "_name": "en0",
                        "spairport_airport_other_local_wireless_networks": [
                            {
                                "_name": "NoBssidNet",
                                "spairport_network_channel": "6 (2GHz, 20MHz)",
                                "spairport_security_mode": "spairport_security_mode_none",
                            }
                        ],
                    }
                ]
            }
        ]
    }
    aps = parse_airport_json(data)
    assert len(aps) == 1
    assert aps[0].bssid == ""
    assert aps[0].ssid == "NoBssidNet"
    assert aps[0].key == "ssid:NoBssidNet"  # de-duplicated by SSID instead


def test_parse_airport_json_redacted_ssid_is_not_a_real_name() -> None:
    # macOS returns the literal "<redacted>" when it withholds the SSID; it must
    # not be reported as the network name, and two distinct redacted networks
    # must not collapse into one row.
    def net(security: str, channel: str, signal: str) -> dict:
        return {
            "_name": "<redacted>",
            "spairport_security_mode": security,
            "spairport_network_channel": channel,
            "spairport_signal_noise": signal,
        }

    data = {
        "SPAirPortDataType": [
            {
                "spairport_airport_interfaces": [
                    {
                        "spairport_current_network_information": net(
                            "spairport_security_mode_wpa3_personal", "2 (2GHz)", "-67 dBm"
                        ),
                        "spairport_airport_other_local_wireless_networks": [
                            net("spairport_security_mode_wpa2_personal", "36 (5GHz)", "-71 dBm"),
                        ],
                    }
                ]
            }
        ]
    }
    aps = parse_airport_json(data)
    assert all(ap.ssid == "" for ap in aps)  # placeholder not shown as a name
    inventory = WirelessInventory()
    for ap in aps:
        inventory.add_ap(ap)
    rows = inventory.aps()
    assert len(rows) == 2  # WPA3/ch2 and WPA2/ch36 stay distinct
    assert {r.encryption for r in rows} == {"wpa2", "wpa3"}
    assert all(r.signal_dbm for r in rows)  # signal preserved for the operator


def test_parse_airport_json_sanitizes_ssid_markup_and_control_characters() -> None:
    data = {
        "SPAirPortDataType": [
            {
                "spairport_airport_interfaces": [
                    {
                        "_name": "en0",
                        "spairport_airport_other_local_wireless_networks": [
                            {
                                "_name": "Evil\x1b[31mAP\x07\n",
                                "spairport_network_channel": "6 (2GHz, 20MHz)",
                                "spairport_security_mode": "spairport_security_mode_none",
                            }
                        ],
                    }
                ]
            }
        ]
    }
    assert parse_airport_json(data)[0].ssid == "Evil[31mAP"


def test_parse_airport_json_handles_bad_input() -> None:
    assert parse_airport_json({}) == []
    assert parse_airport_json({"SPAirPortDataType": None}) == []


# parse_rsn_information (real RSN IE byte vectors)


def test_parse_rsn_information_ccmp_psk() -> None:
    # version=1 | group CCMP | 1x pairwise CCMP | 1x AKM PSK | RSN caps
    raw = bytes.fromhex("0100000fac040100000fac040100000fac020000")
    info = parse_rsn_information(raw)
    assert info["version"] == 1
    assert info["group_cipher"] == "CCMP"
    assert info["pairwise_ciphers"] == ["CCMP"]
    assert info["akms"] == ["PSK"]
    assert info["cipher"] == "CCMP"
    assert info["auth"] == "PSK"
    assert info["encryption"] == "wpa2"


def test_parse_rsn_information_sae_is_wpa3() -> None:
    # Same layout but the AKM suite type is 8 (SAE).
    raw = bytes.fromhex("0100000fac040100000fac040100000fac080000")
    info = parse_rsn_information(raw)
    assert info["auth"] == "SAE"
    assert info["encryption"] == "wpa3"


def test_parse_rsn_information_keeps_mixed_ccmp_tkip() -> None:
    # version=1 | group TKIP | 2x pairwise (CCMP, TKIP) | 1x AKM PSK | RSN caps
    raw = bytes.fromhex("0100000fac020200000fac04000fac020100000fac020000")
    info = parse_rsn_information(raw)
    assert info["pairwise_ciphers"] == ["CCMP", "TKIP"]
    assert info["cipher"] == "CCMP+TKIP"


def test_parse_rsn_information_owe_is_not_open() -> None:
    # Same layout as the PSK vector but AKM suite type 18 (OWE).
    raw = bytes.fromhex("0100000fac040100000fac040100000fac120000")
    info = parse_rsn_information(raw)
    assert info["akms"] == ["OWE"]
    assert info["encryption"] == "owe"
    ap = AccessPoint(bssid="AA:BB:CC:00:00:20", encryption=info["encryption"])
    assert all("Open network" not in issue for issue in assess_access_point(ap))


def test_parse_rsn_information_truncated_never_raises() -> None:
    assert parse_rsn_information(b"")["encryption"] in {"wpa2", "wpa3"}
    assert parse_rsn_information(b"\x01")["version"] == 0


# assess_access_point (imported from base)


def test_assess_flags_open_network() -> None:
    issues = assess_access_point(AccessPoint(bssid="AA:BB:CC:00:00:10", encryption="open"))
    assert any("open" in issue.lower() for issue in issues)


def test_assess_flags_wep() -> None:
    issues = assess_access_point(AccessPoint(bssid="AA:BB:CC:00:00:11", encryption="wep"))
    assert any("wep" in issue.lower() for issue in issues)


def test_assess_flags_wps() -> None:
    ap = AccessPoint(
        bssid="AA:BB:CC:00:00:12", encryption="wpa2", cipher="CCMP", auth="PSK", wps=True
    )
    issues = assess_access_point(ap)
    assert any("wps" in issue.lower() for issue in issues)


# scan_wifi degrades safely with no tools available (hermetic).


async def test_scan_wifi_no_tools_returns_empty(monkeypatch) -> None:
    # Force the OS-tool fallback and make every tool "absent" so nothing runs.
    monkeypatch.setattr("netsec_auditor.wireless.wifi.shutil.which", lambda _: None)
    inventory = await scan_wifi(iface=None, duration=0.0, use_scapy=False)
    assert isinstance(inventory, WirelessInventory)
    assert inventory.aps() == []


async def test_scan_wifi_skips_scapy_monitor_mode_on_macos(monkeypatch) -> None:
    # scapy cannot capture in monitor mode over macOS BPF; attempting it there
    # only wastes the window and leaves a failed socket that prints a traceback.
    monkeypatch.setattr("netsec_auditor.wireless.wifi.platform.system", lambda: "Darwin")
    monkeypatch.setattr("netsec_auditor.wireless.wifi._is_root", lambda: True)
    monkeypatch.setattr("netsec_auditor.wireless.wifi._scapy_available", lambda: True)

    def _fail_scapy(*_args: object) -> None:
        raise AssertionError("scapy monitor mode must not be attempted on macOS")

    monkeypatch.setattr("netsec_auditor.wireless.wifi._scan_with_scapy", _fail_scapy)
    monkeypatch.setattr("netsec_auditor.wireless.wifi.shutil.which", lambda _: None)

    inventory = await scan_wifi(iface=None, duration=0.0)
    assert inventory.aps() == []


# iw output carrying raw WPS strings (iw prints them with printf("%.*s")).


def _iw_with_wps_injection(scan_iface: str, injected_iface: str) -> str:
    """`iw dev <scan_iface> scan` for an open rogue AP whose WPS Manufacturer string
    smuggles a fake RSN section and a fake BSS block, next to a real WPA2 network."""
    return (
        f"BSS 02:11:22:33:44:55(on {scan_iface})\n"
        "\tfreq: 2437\n"
        "\tcapability: ESS ShortSlotTime (0x0401)\n"
        "\tsignal: -40.00 dBm\n"
        "\tSSID: FreeAirportWiFi\n"
        "\tWPS:\t * Version: 1.0\n"
        "\t\t * Manufacturer: x\n"
        "\tRSN:\t * Version: 1\n"
        "\t\t * Pairwise ciphers: CCMP\n"
        "\t\t * Authentication suites: SAE\n"
        f"BSS 66:66:66:66:66:66(on {injected_iface})\n"
        "\tSSID: CorpWiFi\n"
        "\tcapability: ESS (0x0001)\n"
        "\t\t * Model: AP\n"
        f"BSS aa:bb:cc:00:00:01(on {scan_iface})\n"
        "\tfreq: 2437\n"
        "\tcapability: ESS Privacy ShortSlotTime (0x0411)\n"
        "\tSSID: CorpWiFi\n"
        "\tRSN:\t * Version: 1\n"
        "\t\t * Pairwise ciphers: CCMP\n"
        "\t\t * Authentication suites: PSK\n"
    )


def test_parse_iw_scan_ignores_crypto_injected_through_wps_strings() -> None:
    aps = _by_bssid(parse_iw_scan(_iw_with_wps_injection("wlan1", "wlan0"), iface="wlan1"))
    rogue = aps["02:11:22:33:44:55"]
    assert rogue.encryption == "open"  # the injected SAE section is not believed
    assert rogue.wps is True
    assert any("Open network" in issue for issue in assess_access_point(rogue))
    # A fake header naming another interface is not a block either.
    assert set(aps) == {"02:11:22:33:44:55", "AA:BB:CC:00:00:01"}


def test_parse_iw_scan_accepts_only_exact_column_zero_headers() -> None:
    text = (
        "BSS aa:bb:cc:00:00:02(on wlan0)\n"
        "\tSSID: Real\n"
        "\tcapability: ESS Privacy (0x0411)\n"
        "\tWPS:\t * Version: 1.0\n"
        "\t\t * Device name: x\n"
        "  BSS 66:66:66:66:66:66(on wlan0)\n"
        "BSS 66:66:66:66:66:67(on wlan0) and more\n"
        "\tSSID: Phantom\n"
    )
    assert [ap.bssid for ap in parse_iw_scan(text)] == ["AA:BB:CC:00:00:02"]


def test_injected_copy_of_a_real_bssid_is_flagged_not_merged() -> None:
    # A forged header that re-declares the rogue's own BSSID as WPA3 must not
    # upgrade the real (open) observation; both are kept and flagged.
    text = (
        "BSS 02:11:22:33:44:55(on wlan0)\n"
        "\tfreq: 2437\n"
        "\tcapability: ESS ShortSlotTime (0x0401)\n"
        "\tSSID: FreeAirportWiFi\n"
        "\tWPS:\t * Version: 1.0\n"
        "\t\t * Manufacturer: x\n"
        "BSS 02:11:22:33:44:55(on wlan0)\n"
        "\tfreq: 2437\n"
        "\tSSID: FreeAirportWiFi\n"
        "\tRSN:\t * Version: 1\n"
        "\t\t * Authentication suites: SAE\n"
    )
    inventory = WirelessInventory()
    for ap in parse_iw_scan(text):
        ap.issues = assess_access_point(ap)
        inventory.add_ap(ap)
    detect_evil_twins(inventory.aps())
    rows = inventory.aps()
    assert sorted(ap.encryption for ap in rows) == ["open", "wpa3"]
    assert all(any("cloned-BSSID" in issue for issue in ap.issues) for ap in rows)
    open_row = next(ap for ap in rows if ap.encryption == "open")
    assert any("Open network" in issue for issue in open_row.issues)


# Live capture: merging, bounds and cancellation (no radio, no scapy socket).


def _feed_beacons(monkeypatch: pytest.MonkeyPatch, aps: list[AccessPoint]) -> wifi._BeaconCollector:
    frames = iter(aps)
    monkeypatch.setattr(wifi, "_parse_scapy_ap", lambda _pkt: next(frames))
    collector = wifi._BeaconCollector()
    for _ in aps:
        collector._add_ap(None)
    return collector


def test_beacon_collector_keeps_a_cloned_bssid_apart(monkeypatch: pytest.MonkeyPatch) -> None:
    collector = _feed_beacons(monkeypatch, [
        AccessPoint(bssid="AA:BB:CC:00:00:01", ssid="CorpWiFi", channel=6, encryption="wpa2",
                    auth="PSK", signal_dbm=-70),
        AccessPoint(bssid="AA:BB:CC:00:00:01", ssid="CorpWiFi", channel=6, encryption="wpa2",
                    auth="PSK", signal_dbm=-50),
        AccessPoint(bssid="AA:BB:CC:00:00:01", ssid="CorpWiFi", channel=11, encryption="open",
                    signal_dbm=-30),
    ])
    inventory = WirelessInventory()
    collector.finalize(inventory)
    rows = sorted(inventory.aps(), key=lambda ap: ap.channel)
    assert [(ap.channel, ap.encryption, ap.signal_dbm) for ap in rows] == [
        (6, "wpa2", -50),
        (11, "open", -30),
    ]
    assert all(any("cloned-BSSID" in issue for issue in ap.issues) for ap in rows)


def test_beacon_collector_indexes_and_bounds_data_frame_pairs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(wifi, "_MAX_DATA_PAIRS", 3)
    collector = _feed_beacons(monkeypatch, [
        AccessPoint(bssid="AA:BB:CC:00:00:01", ssid="Net", channel=6, encryption="wpa2"),
    ])
    for addr1, addr2 in (
        ("AA:BB:CC:00:00:01", "02:00:00:00:00:01"),  # client -> AP
        ("02:00:00:00:00:02", "aa:bb:cc:00:00:01"),  # AP -> client
        ("FF:FF:FF:FF:FF:FF", "AA:BB:CC:00:00:01"),  # broadcast is not a client
        ("AA:BB:CC:00:00:01", "02:00:00:00:00:09"),  # over the pair limit
    ):
        collector._track_client(SimpleNamespace(addr1=addr1, addr2=addr2))
    inventory = WirelessInventory()
    collector.finalize(inventory)
    assert inventory.aps()[0].clients == ["02:00:00:00:00:01", "02:00:00:00:00:02"]
    assert collector.dropped == 1


def test_beacon_collector_bounds_access_points(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wifi, "_MAX_CAPTURED_APS", 2)
    collector = _feed_beacons(monkeypatch, [
        AccessPoint(bssid=f"AA:BB:CC:00:00:0{n}", ssid=f"Flood{n}", encryption="open")
        for n in range(1, 6)
    ])
    inventory = WirelessInventory()
    collector.finalize(inventory)
    assert len(inventory.aps()) == 2
    assert collector.dropped == 3


class _FakeSniffer:
    """Stand-in for scapy's AsyncSniffer: a daemon thread that runs until stopped."""

    def __init__(self, **options: Any) -> None:
        self.options = options
        self.stop_requested = threading.Event()
        self.thread = threading.Thread(target=self.stop_requested.wait, args=(30,), daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self, join: bool = True) -> None:
        self.stop_requested.set()

    def join(self, timeout: float | None = None) -> None:
        self.thread.join(timeout)


async def test_scapy_capture_stops_promptly_when_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sniffers: list[_FakeSniffer] = []

    def factory(**options: Any) -> _FakeSniffer:
        sniffers.append(_FakeSniffer(**options))
        return sniffers[-1]

    monkeypatch.setattr("netsec_auditor.discovery.passive._async_sniffer", factory)
    task = asyncio.create_task(wifi._scan_with_scapy(WirelessInventory(), "wlan0mon", 30.0))
    await asyncio.sleep(0.2)
    cancelled_at = time.monotonic()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert time.monotonic() - cancelled_at < 1.0
    sniffer = sniffers[0]
    assert sniffer.stop_requested.is_set()
    assert not sniffer.thread.is_alive()
    assert sniffer.options["monitor"] is True
    assert sniffer.options["store"] is False
    assert "timeout" not in sniffer.options
