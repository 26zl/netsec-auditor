"""Tests for wardriving-data ingest — pure WiGLE/GPX/Kismet parsers, no network."""

from __future__ import annotations

from netsec_auditor.wireless.wigle import (
    load_wardrive,
    parse_gpx,
    parse_kismet_netxml,
    parse_wigle_csv,
)

# A WiGLE-1.6 style export: pre-header line, real header, then rows.
# Covers OPEN, WEP, WPA2-PSK-CCMP (+WPS) and WPA3-SAE, plus a BLE row to skip.
WIGLE_CSV = (
    "WigleWifi-1.6,appRelease=2.53,model=ESP32,release=1.0,device=flipper,"
    "display=,board=,brand=,star=Sol,body=0,subBody=0\n"
    "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,"
    "AltitudeMeters,AccuracyMeters,Type\n"
    "00:11:22:33:44:55,OpenCafe,[OPEN],2026-07-01 10:00:00,6,-40,59.9110,10.7500,"
    "12.0,5.0,WIFI\n"
    "AA:BB:CC:DD:EE:FF,OldWEP,[WEP][ESS],2026-07-01 10:01:00,11,-60,59.9120,10.7510,"
    "12.0,5.0,WIFI\n"
    "12:34:56:78:9A:BC,HomeNet,[WPA2-PSK-CCMP][WPS][ESS],2026-07-01 10:02:00,1,-55,"
    "59.9130,10.7520,12.0,5.0,WIFI\n"
    "DE:AD:BE:EF:00:01,SecureAP,[WPA3-SAE][ESS],2026-07-01 10:03:00,36,-70,59.9140,"
    "10.7530,12.0,5.0,WIFI\n"
    "99:99:99:99:99:99,MyEarbuds,Uncategorized,2026-07-01 10:04:00,0,-80,59.9150,"
    "10.7540,0.0,5.0,BLE\n"
)

GPX = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<gpx version="1.1" creator="Flipper" xmlns="http://www.topografix.com/GPX/1/1">\n'
    '  <wpt lat="59.9200" lon="10.7600">\n'
    "    <name>CoffeeWiFi</name>\n"
    "    <desc>BSSID=00:11:22:33:44:55 AuthMode=WPA2-PSK-CCMP RSSI=-52</desc>\n"
    "  </wpt>\n"
    '  <wpt lat="59.9210" lon="10.7610">\n'
    "    <name>NamedOnly</name>\n"
    "    <cmt>open hotspot, no encryption seen</cmt>\n"
    "  </wpt>\n"
    "</gpx>\n"
)

# ISO-8859-1 declaration exercises the str-with-encoding-declaration path.
NETXML = (
    '<?xml version="1.0" encoding="ISO-8859-1"?>\n'
    '<detection-run kismet-version="2016.07.R1" start-time="Wed Jul 1 10:00:00 2026">\n'
    '  <wireless-network number="1" type="infrastructure">\n'
    '    <SSID first-time="Wed Jul 1 10:00:00 2026">\n'
    "      <type>Beacon</type>\n"
    "      <encryption>WPA2</encryption>\n"
    "      <encryption>WPA+PSK</encryption>\n"
    "      <encryption>WPA+AES-CCM</encryption>\n"
    "      <ssid>KismetNet</ssid>\n"
    "    </SSID>\n"
    "    <BSSID>00:AA:BB:CC:DD:EE</BSSID>\n"
    "    <manuf>Netgear</manuf>\n"
    "    <channel>6</channel>\n"
    "    <gps-info>\n"
    "      <avg-lat>59.9300</avg-lat>\n"
    "      <avg-lon>10.7700</avg-lon>\n"
    "    </gps-info>\n"
    "  </wireless-network>\n"
    "</detection-run>\n"
)


def _by_bssid(aps: list) -> dict:
    return {ap.bssid.upper(): ap for ap in aps}


# WiGLE CSV


def test_parse_wigle_csv_counts_and_skips_non_wifi() -> None:
    aps = parse_wigle_csv(WIGLE_CSV)
    # Four WIFI rows; the BLE row is dropped.
    assert len(aps) == 4
    assert all(ap.source == "wigle" for ap in aps)
    assert "99:99:99:99:99:99" not in _by_bssid(aps)


def test_parse_wigle_csv_open_row() -> None:
    ap = _by_bssid(parse_wigle_csv(WIGLE_CSV))["00:11:22:33:44:55"]
    assert ap.ssid == "OpenCafe"
    assert ap.encryption == "open"
    assert ap.auth == ""
    assert ap.wps is False
    assert ap.channel == 6
    assert ap.signal_dbm == -40
    assert ap.latitude == 59.9110
    assert ap.longitude == 10.7500
    # Issues must be populated: an open network is flagged.
    assert any("Open network" in issue for issue in ap.issues)


def test_parse_wigle_csv_wep_row() -> None:
    ap = _by_bssid(parse_wigle_csv(WIGLE_CSV))["AA:BB:CC:DD:EE:FF"]
    assert ap.encryption == "wep"
    assert any("WEP" in issue for issue in ap.issues)


def test_parse_wigle_csv_wpa2_psk_ccmp_with_wps() -> None:
    ap = _by_bssid(parse_wigle_csv(WIGLE_CSV))["12:34:56:78:9A:BC"]
    assert ap.encryption == "wpa2"
    assert ap.cipher == "CCMP"
    assert ap.auth == "PSK"
    assert ap.wps is True
    assert ap.channel == 1
    assert ap.signal_dbm == -55
    assert ap.latitude == 59.9130
    assert ap.longitude == 10.7520
    assert any("WPS" in issue for issue in ap.issues)


def test_parse_wigle_csv_wpa3_sae_row() -> None:
    ap = _by_bssid(parse_wigle_csv(WIGLE_CSV))["DE:AD:BE:EF:00:01"]
    assert ap.encryption == "wpa3"
    assert ap.auth == "SAE"
    assert ap.wps is False
    assert ap.channel == 36
    assert ap.band == "5GHz"


def test_parse_wigle_csv_ess_only_is_open() -> None:
    text = (
        "WigleWifi-1.6,appRelease=2.53\n"
        "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,"
        "CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
        "00:00:00:00:00:11,BareEss,[ESS],2026-07-01 10:00:00,1,-50,1.0,2.0,0,0,WIFI\n"
    )
    aps = parse_wigle_csv(text)
    assert len(aps) == 1
    assert aps[0].encryption == "open"


def test_parse_wigle_csv_authmode_variants() -> None:
    text = (
        "WigleWifi-1.6\n"
        "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,"
        "CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
        "00:00:00:00:00:01,A,[WPA-PSK-TKIP][ESS],t,6,-50,1,2,0,0,WIFI\n"
        "00:00:00:00:00:02,B,[WPA2-EAP-CCMP][ESS],t,6,-50,1,2,0,0,WIFI\n"
    )
    aps = _by_bssid(parse_wigle_csv(text))
    wpa1 = aps["00:00:00:00:00:01"]
    assert wpa1.encryption == "wpa"
    assert wpa1.cipher == "TKIP"
    assert wpa1.auth == "PSK"
    assert any("TKIP" in issue for issue in wpa1.issues)
    ent = aps["00:00:00:00:00:02"]
    assert ent.encryption == "wpa2"
    assert ent.auth == "EAP"


def test_parse_wigle_csv_tolerates_malformed() -> None:
    text = (
        "WigleWifi-1.6\n"
        "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,"
        "CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
        "short,row\n"
        ",NoMac,[OPEN],t,6,-50,1,2,0,0,WIFI\n"
        "00:00:00:00:00:0A,Good,[OPEN],t,x,not-a-number,bad,lat,0,0,WIFI\n"
    )
    aps = parse_wigle_csv(text)
    # Only the last row is usable; bad numeric fields fall back to defaults.
    assert len(aps) == 1
    ap = aps[0]
    assert ap.bssid == "00:00:00:00:00:0A"
    assert ap.channel == 0
    assert ap.signal_dbm == 0
    assert ap.latitude is None
    assert ap.longitude is None


def test_parse_wigle_csv_garbage_returns_empty() -> None:
    assert parse_wigle_csv("") == []
    assert parse_wigle_csv("just some text\nwith no header") == []


# GPX


def test_parse_gpx_two_waypoints() -> None:
    aps = parse_gpx(GPX)
    assert len(aps) == 2
    assert all(ap.source == "gpx" for ap in aps)
    by_id = _by_bssid(aps)

    # Waypoint whose BSSID lives in <desc>.
    wpa2 = by_id["00:11:22:33:44:55"]
    assert wpa2.ssid == "CoffeeWiFi"
    assert wpa2.encryption == "wpa2"
    assert wpa2.cipher == "CCMP"
    assert wpa2.auth == "PSK"
    assert wpa2.latitude == 59.9200
    assert wpa2.longitude == 10.7600

    # Waypoint with no MAC falls back to the name as the key.
    named = by_id["NAMEDONLY"]
    assert named.bssid == "NamedOnly"
    assert named.ssid == "NamedOnly"
    assert named.encryption == "open"
    assert any("Open network" in issue for issue in named.issues)


def test_parse_gpx_garbage_returns_empty() -> None:
    assert parse_gpx("") == []
    assert parse_gpx("<gpx><wpt lat=") == []


# Kismet netxml


def test_parse_kismet_netxml_one_network() -> None:
    aps = parse_kismet_netxml(NETXML)
    assert len(aps) == 1
    ap = aps[0]
    assert ap.source == "kismet"
    assert ap.bssid == "00:AA:BB:CC:DD:EE"
    assert ap.ssid == "KismetNet"
    assert ap.encryption == "wpa2"
    assert ap.cipher == "CCMP"
    assert ap.auth == "PSK"
    assert ap.channel == 6
    assert ap.vendor == "Netgear"
    assert ap.latitude == 59.9300
    assert ap.longitude == 10.7700
    # WPA2-only networks earn a "consider WPA3" advisory.
    assert any("WPA2" in issue for issue in ap.issues)


def test_parse_kismet_netxml_garbage_returns_empty() -> None:
    assert parse_kismet_netxml("") == []
    assert parse_kismet_netxml("<broken") == []


# load_wardrive dispatch


def test_load_wardrive_csv(tmp_path) -> None:
    path = tmp_path / "capture.csv"
    path.write_text(WIGLE_CSV)
    aps = load_wardrive(path)
    assert len(aps) == 4
    assert all(ap.source == "wigle" for ap in aps)


def test_load_wardrive_gpx(tmp_path) -> None:
    path = tmp_path / "capture.gpx"
    path.write_text(GPX)
    aps = load_wardrive(path)
    assert len(aps) == 2
    assert all(ap.source == "gpx" for ap in aps)


def test_load_wardrive_netxml(tmp_path) -> None:
    path = tmp_path / "capture.netxml"
    path.write_text(NETXML)
    aps = load_wardrive(path)
    assert len(aps) == 1
    assert aps[0].source == "kismet"


def test_load_wardrive_sniffs_unknown_extension(tmp_path) -> None:
    # No recognized suffix: dispatch must fall back to a content sniff.
    path = tmp_path / "capture.dat"
    path.write_text(WIGLE_CSV)
    aps = load_wardrive(path)
    assert len(aps) == 4
    assert aps[0].source == "wigle"


def test_load_wardrive_missing_file_returns_empty(tmp_path) -> None:
    assert load_wardrive(tmp_path / "nope.csv") == []
