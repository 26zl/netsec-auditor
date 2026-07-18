"""Tests for passive Wi-Fi recon parsers (no radio, no root, no network).

Only the pure parsers and the read-only assessment are exercised; the scapy
monitor-mode path and OS-tool subprocesses are never invoked.
"""

from __future__ import annotations

from netsec_auditor.wireless.base import AccessPoint, WirelessInventory, assess_access_point
from netsec_auditor.wireless.wifi import (
    parse_airport_json,
    parse_iw_scan,
    parse_nmcli,
    parse_rsn_information,
    scan_wifi,
)


def _terse_row(**fields: str) -> str:
    """Build one `nmcli -t -f ALL` row, escaping ':' inside values (the BSSID)."""
    order = (
        "NAME", "SSID", "SSID-HEX", "BSSID", "MODE", "CHAN", "FREQ", "RATE",
        "SIGNAL", "BARS", "SECURITY", "WPA-FLAGS", "RSN-FLAGS", "DEVICE",
        "ACTIVE", "IN-USE", "DBUS-PATH",
    )
    values = {"NAME": "AP", "MODE": "Infra", "BARS": "**", "DEVICE": "wlan0", "ACTIVE": "no"}
    values.update(fields)
    return ":".join(values.get(name, "").replace(":", r"\:") for name in order)


# `nmcli -t -f ALL dev wifi list` terse rows: open, WEP, WPA2-PSK, WPA3-SAE.
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
