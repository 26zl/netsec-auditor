"""Wardriving-data ingest — WiGLE CSV, GPX and Kismet netxml.

These parsers turn Wi-Fi captures exported by ESP32/Flipper-style gadgets (and
Kismet) into :class:`AccessPoint` records so netsec-auditor can report on them.
Every parser is pure and tolerant: it takes text, returns a list, skips
malformed rows and never raises. All work here is read-only inventory — no
attacks, deauth or handshake capture.
"""

from __future__ import annotations

import csv
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from netsec_auditor.wireless.base import AccessPoint, assess_access_point

# A colon- or dash-separated 48-bit MAC/BSSID.
_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")

# Leading XML declaration / DOCTYPE — stripped before parsing (see _parse_xml).
_XML_DECL_RE = re.compile(r"<\?xml[^>]*\?>", re.IGNORECASE)
_DOCTYPE_RE = re.compile(r"<!DOCTYPE[^>]*>", re.IGNORECASE)


def parse_wigle_csv(text: str) -> list[AccessPoint]:
    """Parse a WiGLE CSV export (pre-header + header + rows). WIFI rows only."""
    aps: list[AccessPoint] = []
    rows = list(csv.reader(text.splitlines()))
    header_idx = _find_wigle_header(rows)
    if header_idx < 0:
        return aps
    header = [cell.strip() for cell in rows[header_idx]]
    for raw in rows[header_idx + 1:]:
        ap = _wigle_row_to_ap(header, raw)
        if ap is not None:
            aps.append(ap)
    return aps


def parse_gpx(text: str) -> list[AccessPoint]:
    """Parse GPX ``<wpt>`` waypoints, reading BSSID/security from desc/cmt."""
    aps: list[AccessPoint] = []
    root = _parse_xml(text)
    if root is None:
        return aps
    for wpt in root.iter():
        if _localname(wpt.tag) != "wpt":
            continue
        ap = _gpx_waypoint_to_ap(wpt)
        if ap is not None:
            aps.append(ap)
    return aps


def parse_kismet_netxml(text: str) -> list[AccessPoint]:
    """Parse Kismet ``.netxml`` ``<wireless-network>`` elements."""
    aps: list[AccessPoint] = []
    root = _parse_xml(text)
    if root is None:
        return aps
    for net in root.iter():
        if _localname(net.tag) != "wireless-network":
            continue
        ap = _kismet_network_to_ap(net)
        if ap is not None:
            aps.append(ap)
    return aps


def load_wardrive(path: Path) -> list[AccessPoint]:
    """Read a capture file and dispatch by extension, sniffing content if unknown."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return parse_wigle_csv(text)
    if suffix == ".gpx":
        return parse_gpx(text)
    if suffix in (".netxml", ".xml"):
        return parse_kismet_netxml(text)
    return _sniff_and_parse(text)


# WiGLE helpers


def _find_wigle_header(rows: list[list[str]]) -> int:
    """Return the index of the real column header row, or -1 if absent."""
    for i, row in enumerate(rows):
        cells = {cell.strip().upper() for cell in row}
        if {"MAC", "SSID", "AUTHMODE"} <= cells:
            return i
    return -1


def _wigle_row_to_ap(header: list[str], raw: list[str]) -> AccessPoint | None:
    """Build an AccessPoint from one WiGLE data row, or None to skip it."""
    row = {k.strip().upper(): (v or "").strip() for k, v in zip(header, raw, strict=False)}
    if row.get("TYPE", "").upper() != "WIFI":
        return None
    bssid = row.get("MAC", "")
    if not bssid:
        return None
    enc, cipher, auth, wps = _classify_security(row.get("AUTHMODE", ""))
    channel = _to_int(row.get("CHANNEL", ""))
    ap = AccessPoint(
        bssid=bssid,
        ssid=row.get("SSID", ""),
        channel=channel,
        band=_band_for_channel(channel),
        encryption=enc,
        cipher=cipher,
        auth=auth,
        wps=wps,
        signal_dbm=_to_int(row.get("RSSI", "")),
        latitude=_to_float(row.get("CURRENTLATITUDE", "")),
        longitude=_to_float(row.get("CURRENTLONGITUDE", "")),
        source="wigle",
    )
    ap.issues = assess_access_point(ap)
    return ap


# GPX / Kismet helpers


def _gpx_waypoint_to_ap(wpt: ET.Element) -> AccessPoint | None:
    """Convert a GPX waypoint into an AccessPoint keyed by BSSID or name."""
    name = desc = cmt = ""
    for child in wpt:
        value = (child.text or "").strip()
        local = _localname(child.tag)
        if local == "name":
            name = value
        elif local == "desc":
            desc = value
        elif local == "cmt":
            cmt = value
    meta = " ".join(part for part in (desc, cmt) if part)
    match = _MAC_RE.search(meta)
    bssid = match.group(0) if match else name
    if not bssid:
        return None
    enc, cipher, auth, wps = _classify_security(meta)
    ap = AccessPoint(
        bssid=bssid,
        ssid=name,
        encryption=enc,
        cipher=cipher,
        auth=auth,
        wps=wps,
        latitude=_to_float(wpt.get("lat")),
        longitude=_to_float(wpt.get("lon")),
        source="gpx",
    )
    ap.issues = assess_access_point(ap)
    return ap


def _kismet_network_to_ap(net: ET.Element) -> AccessPoint | None:
    """Convert a Kismet ``<wireless-network>`` element into an AccessPoint."""
    bssid = _child_text(net, "BSSID")
    if not bssid:
        return None
    ssid = ""
    enc_tokens: list[str] = []
    ssid_block = _first_child(net, "SSID")
    if ssid_block is not None:
        ssid = _child_text(ssid_block, "ssid")
        enc_tokens = [
            (e.text or "").strip() for e in ssid_block if _localname(e.tag) == "encryption"
        ]
    channel = _to_int(_child_text(net, "channel"))
    gps = _first_child(net, "gps-info")
    lat = _to_float(_child_text(gps, "avg-lat")) if gps is not None else None
    lon = _to_float(_child_text(gps, "avg-lon")) if gps is not None else None
    enc, cipher, auth, wps = _classify_security(" ".join(enc_tokens))
    ap = AccessPoint(
        bssid=bssid,
        ssid=ssid,
        channel=channel,
        band=_band_for_channel(channel),
        encryption=enc,
        cipher=cipher,
        auth=auth,
        wps=wps,
        vendor=_child_text(net, "manuf"),
        latitude=lat,
        longitude=lon,
        source="kismet",
    )
    ap.issues = assess_access_point(ap)
    return ap


def _sniff_and_parse(text: str) -> list[AccessPoint]:
    """Fallback dispatch by inspecting the first lines / prefix of the content."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for line in lines[:10]:
        low = line.lower()
        if line.startswith("WigleWifi") or (line.startswith("MAC,") and "authmode" in low):
            return parse_wigle_csv(text)
        if low.startswith("<gpx"):
            return parse_gpx(text)
        if low.startswith(("<detection-run", "<wireless-network")):
            return parse_kismet_netxml(text)
    head = text[:512].lower()
    if "<gpx" in head:
        return parse_gpx(text)
    if "<detection-run" in head or "<wireless-network" in head:
        return parse_kismet_netxml(text)
    return []


# Shared parsing primitives


def _classify_security(raw: str) -> tuple[str, str, str, bool]:
    """Map an AuthMode/encryption string to (encryption, cipher, auth, wps)."""
    s = raw.upper()
    wps = "WPS" in s
    has_wpa3 = "WPA3" in s or "SAE" in s
    has_wpa2 = "WPA2" in s or "RSN" in s
    if has_wpa3 and has_wpa2:
        encryption = "wpa2/wpa3"
    elif has_wpa3:
        encryption = "wpa3"
    elif has_wpa2:
        encryption = "wpa2"
    elif "WPA" in s:
        encryption = "wpa"
    elif "WEP" in s:
        encryption = "wep"
    else:
        encryption = "open"
    ciphers = []
    if "CCM" in s or "AES" in s:
        ciphers.append("CCMP")
    if "GCM" in s:
        ciphers.append("GCMP")
    if "TKIP" in s:
        ciphers.append("TKIP")
    cipher = "+".join(ciphers)
    if "SAE" in s:
        auth = "SAE"
    elif "EAP" in s:
        auth = "EAP"
    elif "PSK" in s:
        auth = "PSK"
    else:
        auth = ""
    return encryption, cipher, auth, wps


def _band_for_channel(channel: int) -> str:
    """Best-effort 2.4/5 GHz band label from a channel number."""
    if 1 <= channel <= 14:
        return "2.4GHz"
    if 32 <= channel <= 196:
        return "5GHz"
    return ""


def _parse_xml(text: str) -> ET.Element | None:
    """Parse XML text, stripping any declaration/DOCTYPE; None on failure."""
    cleaned = text.lstrip("\ufeff")  # drop a leading UTF-8 BOM if present
    cleaned = _XML_DECL_RE.sub("", cleaned, count=1)
    cleaned = _DOCTYPE_RE.sub("", cleaned, count=1)
    cleaned = cleaned.strip()
    if not cleaned:
        return None
    try:
        return ET.fromstring(cleaned)
    except ET.ParseError:
        return None


def _localname(tag: object) -> str:
    """Return an element's namespace-stripped local name."""
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _first_child(parent: ET.Element, name: str) -> ET.Element | None:
    """Return the first direct child with the given local name, or None."""
    for child in parent:
        if _localname(child.tag) == name:
            return child
    return None


def _child_text(parent: ET.Element | None, name: str) -> str:
    """Return the stripped text of the first matching direct child, or ''."""
    if parent is None:
        return ""
    child = _first_child(parent, name)
    if child is None or child.text is None:
        return ""
    return child.text.strip()


def _to_int(value: str | None) -> int:
    """Parse an int (via float, tolerating decimals); 0 on failure."""
    try:
        return int(float(value))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _to_float(value: str | None) -> float | None:
    """Parse a float; None on failure (used for optional lat/lon)."""
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
