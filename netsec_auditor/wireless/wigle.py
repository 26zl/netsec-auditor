"""Wardriving-data ingest — WiGLE CSV, GPX and Kismet netxml.

These parsers turn Wi-Fi captures exported by ESP32/Flipper-style gadgets (and
Kismet) into :class:`AccessPoint` records so netsec-auditor can report on them.
The text parsers (:func:`parse_wigle_csv`, :func:`parse_gpx`,
:func:`parse_kismet_netxml`) are pure and tolerant: they skip malformed rows and
return an empty list for unparsable input. :func:`load_wardrive` streams a file
from disk and raises :class:`WardriveFormatError` when it cannot be read or is
not one of those formats. All work here is read-only inventory — no attacks,
deauth or handshake capture.
"""

from __future__ import annotations

import codecs
import csv
import io
import math
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path
from typing import IO

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import iterparse as safe_iterparse

from netsec_auditor.utils.logging import get_logger
from netsec_auditor.wireless.base import (
    AccessPoint,
    assess_access_point,
    band_for_channel,
    sanitize_name,
)

logger = get_logger(__name__)


class WardriveFormatError(ValueError):
    """A wardrive file cannot be read or is not a WiGLE CSV, GPX or Kismet netxml file."""


# A colon- or dash-separated 48-bit MAC/BSSID.
_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")

# The encoding named by a leading XML declaration.
_XML_ENCODING_RE = re.compile(rb"""\s*<\?xml[^>]*?encoding\s*=\s*["']([A-Za-z0-9._-]{1,40})["']""")

# Characters XML 1.0 forbids: one raw control byte copied from an SSID would
# otherwise make an entire GPX/Kismet export unparsable.
_XML_INVALID_CHARS: dict[int, None] = dict.fromkeys(
    [*range(0x00, 0x09), 0x0B, 0x0C, *range(0x0E, 0x20), 0xFFFE, 0xFFFF]
)

# OWE as a whole token, so free-text descriptions ("tower", "power") do not match.
_OWE_RE = re.compile(r"\bOWE\b")

# Rows searched for the WiGLE column header (normally the second line).
_HEADER_SEARCH_ROWS = 16
# Bytes read up front to recognise a file whose extension says nothing.
_SNIFF_BYTES = 4096


def parse_wigle_csv(text: str) -> list[AccessPoint]:
    """Parse a WiGLE CSV export (pre-header + header + rows). WIFI rows only.

    Never raises: text that is not a WiGLE CSV yields ``[]``.
    """
    try:
        # splitlines() also splits on \x1c, \x0b and U+2028, letting a crafted SSID hide its row.
        return _read_wigle_csv(io.StringIO(text, newline=""))
    except WardriveFormatError as exc:
        logger.debug("wardrive_unparsable", format="wigle-csv", error=str(exc))
        return []


def parse_gpx(text: str) -> list[AccessPoint]:
    """Parse GPX ``<wpt>`` waypoints, reading BSSID/security from desc/cmt.

    Never raises: text that is not a GPX document yields ``[]``.
    """
    try:
        return _read_gpx(_XmlText(io.StringIO(text)))
    except WardriveFormatError as exc:
        logger.debug("wardrive_unparsable", format="gpx", error=str(exc))
        return []


def parse_kismet_netxml(text: str) -> list[AccessPoint]:
    """Parse Kismet ``.netxml`` ``<wireless-network>`` elements.

    Never raises: text that is not a Kismet netxml document yields ``[]``.
    """
    try:
        return _read_kismet(_XmlText(io.StringIO(text)))
    except WardriveFormatError as exc:
        logger.debug("wardrive_unparsable", format="kismet", error=str(exc))
        return []


def load_wardrive(path: Path) -> list[AccessPoint]:
    """Stream a wardrive file, dispatching by extension or, failing that, by content.

    The file is parsed incrementally, so memory tracks the access points found
    rather than the file size. Returns ``[]`` for a valid file that holds no
    access points. Raises :class:`WardriveFormatError` when the file cannot be
    read or is not a WiGLE CSV, GPX or Kismet netxml file.
    """
    path = Path(path)
    try:
        if not path.exists():
            raise WardriveFormatError("file not found")
        if not path.is_file():  # a FIFO or device could block or never end
            raise WardriveFormatError("not a regular file")
        with path.open("rb") as raw:
            head = raw.read(_SNIFF_BYTES)
            raw.seek(0)
            kind = _format_for(path.suffix.lower(), head)
            if kind == "csv":
                return _read_wigle_csv(_text_stream(raw, head, xml=False))
            if kind == "gpx":
                return _read_gpx(_XmlText(_text_stream(raw, head, xml=True)))
            if kind == "kismet":
                return _read_kismet(_XmlText(_text_stream(raw, head, xml=True)))
    except OSError as exc:
        raise WardriveFormatError(f"cannot read file: {exc.strerror or exc}") from exc
    raise WardriveFormatError("unrecognised format: expected WiGLE CSV, GPX or Kismet netxml")


# Streaming readers


def _read_wigle_csv(stream: IO[str]) -> list[AccessPoint]:
    """Read WiGLE CSV rows one at a time, skipping malformed ones."""
    reader = csv.reader(stream)
    header: list[str] | None = None
    aps: list[AccessPoint] = []
    try:
        for index, raw in enumerate(reader):
            if header is None:
                if _is_wigle_header(raw):
                    header = [cell.strip() for cell in raw]
                elif index >= _HEADER_SEARCH_ROWS:
                    break
                continue
            ap = _wigle_row_to_ap(header, raw)
            if ap is not None:
                aps.append(ap)
    except csv.Error as exc:  # e.g. a field beyond csv's 128 KiB limit
        raise WardriveFormatError(f"unparsable CSV: {exc}") from exc
    if header is None:
        raise WardriveFormatError("no WiGLE CSV header (MAC, SSID, AuthMode) found")
    return aps


def _read_gpx(source: _XmlText) -> list[AccessPoint]:
    """Convert each GPX waypoint as soon as it has been parsed."""
    aps: list[AccessPoint] = []
    for wpt in _iter_elements(source, roots=("gpx",), target="wpt"):
        ap = _gpx_waypoint_to_ap(wpt)
        if ap is not None:
            aps.append(ap)
    return aps


def _read_kismet(source: _XmlText) -> list[AccessPoint]:
    """Convert each Kismet ``<wireless-network>`` as soon as it has been parsed."""
    aps: list[AccessPoint] = []
    roots = ("detection-run", "wireless-network")
    for net in _iter_elements(source, roots=roots, target="wireless-network"):
        ap = _kismet_network_to_ap(net)
        if ap is not None:
            aps.append(ap)
    return aps


class _XmlText:
    """Text source for ``iterparse`` that drops characters XML 1.0 forbids.

    Leading whitespace and a BOM are skipped so the XML declaration, if any,
    starts the document as expat requires.
    """

    def __init__(self, stream: IO[str]) -> None:
        self._stream = stream
        self._started = False

    def read(self, size: int = -1) -> str:
        data = self._stream.read(size)
        while not self._started and data:
            data = data.lstrip("\ufeff \t\r\n")
            if data:
                self._started = True
            else:
                data = self._stream.read(size)
        return data.translate(_XML_INVALID_CHARS)


def _iter_elements(
    source: _XmlText, roots: tuple[str, ...], target: str
) -> Iterator[ET.Element]:
    """Yield each complete ``target`` element and drop every finished subtree.

    defusedxml rejects entity declarations and external references (XXE,
    billion laughs); a bare DOCTYPE is accepted but never fetched.
    """
    stack: list[ET.Element] = []
    inside = 0  # open ``target`` elements around the current position
    try:
        for event, elem in safe_iterparse(source, events=("start", "end")):
            name = _localname(elem.tag)
            if event == "start":
                if not stack and name not in roots:
                    raise WardriveFormatError(f"unexpected root element <{name}>")
                stack.append(elem)
                if name == target:
                    inside += 1
                continue
            stack.pop()
            if name == target:
                inside -= 1
                yield elem
            if inside == 0 and stack:
                stack[-1].remove(elem)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise WardriveFormatError(f"malformed XML: {exc}") from exc


def _text_stream(raw: io.BufferedReader, head: bytes, *, xml: bool) -> IO[str]:
    """Decode ``raw`` leniently: UTF-8, UTF-16 with a BOM, or the declared XML encoding."""
    encoding = "utf-8-sig"
    if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding = "utf-16"
    elif xml and (declared := _XML_ENCODING_RE.match(head)):
        encoding = declared.group(1).decode("ascii")
    try:
        return io.TextIOWrapper(raw, encoding=encoding, errors="replace", newline="")
    except LookupError:  # unknown or non-text codec named by the file
        return io.TextIOWrapper(raw, encoding="utf-8-sig", errors="replace", newline="")


def _format_for(suffix: str, head: bytes) -> str | None:
    """Pick the parser from the extension, else from the first bytes of content."""
    if suffix == ".csv":
        return "csv"
    if suffix == ".gpx":
        return "gpx"
    if suffix in (".netxml", ".xml"):
        return "kismet"
    is_utf16 = head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE))
    text = head.decode("utf-16" if is_utf16 else "utf-8-sig", "replace")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for line in lines[:10]:
        low = line.lower()
        if line.startswith("WigleWifi") or (line.startswith("MAC,") and "authmode" in low):
            return "csv"
        if low.startswith("<gpx"):
            return "gpx"
        if low.startswith(("<detection-run", "<wireless-network")):
            return "kismet"
    start = text[:512].lower()
    if "<gpx" in start:
        return "gpx"
    if "<detection-run" in start or "<wireless-network" in start:
        return "kismet"
    return None


# WiGLE helpers


def _is_wigle_header(row: list[str]) -> bool:
    """True for the real column header row."""
    return {"MAC", "SSID", "AUTHMODE"} <= {cell.strip().upper() for cell in row}


def _normalize_mac(value: str) -> str:
    """Return ``value`` as an upper-case colon-separated MAC, or '' if it is not one."""
    candidate = value.strip()
    if not _MAC_RE.fullmatch(candidate):
        return ""
    return candidate.replace("-", ":").upper()


def _wigle_row_to_ap(header: list[str], raw: list[str]) -> AccessPoint | None:
    """Build an AccessPoint from one WiGLE data row, or None to skip it."""
    row = {k.strip().upper(): (v or "").strip() for k, v in zip(header, raw, strict=False)}
    if row.get("TYPE", "").upper() != "WIFI":
        return None
    bssid = _normalize_mac(row.get("MAC", ""))
    if not bssid:
        return None
    enc, cipher, auth, wps = _classify_security(row.get("AUTHMODE", ""))
    channel = _to_int(row.get("CHANNEL", ""))
    ap = AccessPoint(
        bssid=bssid,
        ssid=sanitize_name(row.get("SSID", "")),
        channel=channel,
        band=band_for_channel(channel),
        encryption=enc,
        cipher=cipher,
        auth=auth,
        wps=wps,
        signal_dbm=_to_int(row.get("RSSI", "")),
        latitude=_to_coord(row.get("CURRENTLATITUDE", ""), 90.0),
        longitude=_to_coord(row.get("CURRENTLONGITUDE", ""), 180.0),
        source="wigle",
    )
    ap.issues = assess_access_point(ap)
    return ap


# GPX / Kismet helpers


def _gpx_waypoint_to_ap(wpt: ET.Element) -> AccessPoint | None:
    """Convert a GPX waypoint into an AccessPoint.

    The BSSID comes only from a MAC address in ``<desc>``/``<cmt>``; a waypoint
    without one keeps an empty BSSID rather than borrowing its (SSID) name.
    """
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
    bssid = _normalize_mac(match.group(0)) if match else ""
    ssid = sanitize_name(name)
    if not bssid and not ssid:
        return None
    enc, cipher, auth, wps = _classify_security(meta)
    ap = AccessPoint(
        bssid=bssid,
        ssid=ssid,
        encryption=enc,
        cipher=cipher,
        auth=auth,
        wps=wps,
        latitude=_to_coord(wpt.get("lat"), 90.0),
        longitude=_to_coord(wpt.get("lon"), 180.0),
        source="gpx",
    )
    ap.issues = assess_access_point(ap)
    return ap


def _kismet_network_to_ap(net: ET.Element) -> AccessPoint | None:
    """Convert a Kismet ``<wireless-network>`` element into an AccessPoint."""
    bssid = _normalize_mac(_child_text(net, "BSSID"))
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
    lat = _to_coord(_child_text(gps, "avg-lat"), 90.0) if gps is not None else None
    lon = _to_coord(_child_text(gps, "avg-lon"), 180.0) if gps is not None else None
    enc, cipher, auth, wps = _classify_security(" ".join(enc_tokens))
    ap = AccessPoint(
        bssid=bssid,
        ssid=sanitize_name(ssid),
        channel=channel,
        band=band_for_channel(channel),
        encryption=enc,
        cipher=cipher,
        auth=auth,
        wps=wps,
        vendor=sanitize_name(_child_text(net, "manuf")),
        latitude=lat,
        longitude=lon,
        source="kismet",
    )
    ap.issues = assess_access_point(ap)
    return ap


# Shared parsing primitives


def _classify_security(raw: str) -> tuple[str, str, str, bool]:
    """Map an AuthMode/encryption string to (encryption, cipher, auth, wps)."""
    s = raw.upper()
    wps = "WPS" in s
    has_wpa3 = "WPA3" in s or "SAE" in s
    has_wpa2 = "WPA2" in s or "RSN" in s
    if _OWE_RE.search(s):
        encryption = "owe"      # Enhanced Open: encrypted, unauthenticated
    elif has_wpa3 and has_wpa2:
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
    elif _OWE_RE.search(s):
        auth = "OWE"
    elif "EAP" in s:
        auth = "EAP"
    elif "PSK" in s:
        auth = "PSK"
    else:
        auth = ""
    return encryption, cipher, auth, wps


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
    except (TypeError, ValueError, OverflowError):  # OverflowError: "inf", "1e999"
        return 0


def _to_float(value: str | None) -> float | None:
    """Parse a finite float; None on failure (used for optional lat/lon)."""
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _to_coord(value: str | None, limit: float) -> float | None:
    """Parse a latitude/longitude, dropping values outside +/- ``limit``.

    An unquoted comma in an SSID shifts every later CSV column, so an
    out-of-range coordinate means the row is misaligned, not merely odd.
    """
    coord = _to_float(value)
    if coord is None:
        return None
    if not -limit <= coord <= limit:
        logger.debug("wardrive_coordinate_out_of_range", value=value, limit=limit)
        return None
    return coord
