"""Passive / read-only Wi-Fi reconnaissance.

Two capture strategies, both strictly observational — no deauth, no handshake
capture, no injection:

* **scapy monitor mode** (primary): sniffs 802.11 Beacon/ProbeResp management
  frames and passively watches data frames to attribute clients to their AP.
  Needs scapy, root, and an adapter in monitor mode (e.g. Kali NetHunter with an
  external adapter). scapy is imported lazily so this module loads without it.
* **OS scan tools** (fallback): parses the output of ``nmcli`` / ``iw`` on Linux
  and ``system_profiler`` on macOS. Used whenever scapy is missing or the process
  is not root.

The tool-output parsers (:func:`parse_nmcli`, :func:`parse_iw_scan`,
:func:`parse_airport_json`) and the RSN decoder (:func:`parse_rsn_information`)
are pure functions so they are fully unit-testable without a radio, root, or a
network. :func:`scan_wifi` never raises: on any failure it returns whatever
inventory was gathered and logs a debug/warning.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import json
import os
import re
import shutil
from typing import Any

from netsec_auditor.utils.logging import get_logger
from netsec_auditor.wireless.base import (
    AccessPoint,
    WirelessInventory,
    assess_access_point,
)

logger = get_logger(__name__)

# IEEE 802.11 suite-selector maps, keyed by the final type byte. The OUI
# (00-0F-AC for RSN, 00-50-F2 for WPA) is checked before lookup; the type
# numbers coincide between RSN and WPA so one table serves both.
_RSN_CIPHERS = {
    0: "",          # use group cipher
    1: "WEP-40",
    2: "TKIP",
    4: "CCMP",
    5: "WEP-104",
    6: "BIP",
    8: "GCMP",
    9: "GCMP-256",
    10: "CCMP-256",
}
_RSN_AKMS = {
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    8: "SAE",
    9: "FT-SAE",
    11: "802.1X-SuiteB",
    12: "802.1X-SuiteB-192",
    18: "OWE",
}

# Vendor-specific (id 221) element signatures.
_WPA1_OUI_TYPE = b"\x00\x50\xf2\x01"    # Microsoft WPA (v1) information element
_WPS_OUI_TYPE = b"\x00\x50\xf2\x04"     # Wi-Fi Protected Setup element

# Field order of `nmcli -t -f ALL dev wifi list` (NetworkManager's
# nmc_fields_dev_wifi_list); every terse row is prefixed with the group "AP".
_NMCLI_FIELDS = (
    "NAME", "SSID", "SSID-HEX", "BSSID", "MODE", "CHAN", "FREQ", "RATE",
    "SIGNAL", "BARS", "SECURITY", "WPA-FLAGS", "RSN-FLAGS", "DEVICE",
    "ACTIVE", "IN-USE", "DBUS-PATH",
)

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
_IW_BSS_RE = re.compile(r"^BSS\s+([0-9a-fA-F:]{17})")


async def scan_wifi(
    iface: str | None = None, duration: float = 15.0, use_scapy: bool = True
) -> WirelessInventory:
    """Passively inventory nearby Wi-Fi access points (read-only).

    Prefers scapy monitor-mode sniffing (requires scapy, root, and a monitor-mode
    adapter); otherwise, or if that yields nothing, falls back to parsing OS scan
    tools (``nmcli`` / ``iw`` on Linux, ``system_profiler`` on macOS). Never
    raises — partial results are returned on any error.
    """
    inventory = WirelessInventory()

    if use_scapy and _scapy_available() and _is_root():
        try:
            await _scan_with_scapy(inventory, iface, duration)
        except Exception as exc:  # a capture error must not crash the caller
            logger.warning("wifi_scapy_scan_failed", error=str(exc))
        if inventory.access_points:
            logger.info("wifi_scan_complete", source="scapy",
                        aps=len(inventory.access_points))
            return inventory
        logger.debug("wifi_scapy_no_results", hint="verify monitor mode")

    try:
        await _scan_with_os_tools(inventory, iface)
    except Exception as exc:  # tool invocation / parse errors degrade to partial
        logger.warning("wifi_os_scan_failed", error=str(exc))

    logger.info("wifi_scan_complete", source="os-tools",
                aps=len(inventory.access_points))
    return inventory


# Primary path: scapy monitor-mode sniffing (lazy import, never in tests).


async def _scan_with_scapy(
    inventory: WirelessInventory, iface: str | None, duration: float
) -> None:
    """Sniff 802.11 frames for ``duration`` seconds and fold them in."""
    loop = asyncio.get_running_loop()
    collector = _BeaconCollector()
    await loop.run_in_executor(None, collector.sniff, iface, duration)
    collector.finalize(inventory)


class _BeaconCollector:
    """Accumulates APs and client associations from sniffed 802.11 frames."""

    def __init__(self) -> None:
        self._aps: dict[str, AccessPoint] = {}
        self._data_pairs: set[tuple[str, str]] = set()

    def sniff(self, iface: str | None, duration: float) -> None:
        """Blocking scapy monitor-mode capture; runs in a thread executor."""
        from scapy.all import Dot11
        from scapy.all import sniff as scapy_sniff

        scapy_sniff(
            iface=iface,
            timeout=duration,
            store=False,
            monitor=True,
            prn=self._handle,
            lfilter=lambda pkt: pkt.haslayer(Dot11),
        )

    def _handle(self, pkt: Any) -> None:
        """Route one frame, never raising — a bad frame must not stop capture."""
        try:
            self._process(pkt)
        except Exception as exc:
            logger.debug("wifi_frame_skipped", error=str(exc))

    def _process(self, pkt: Any) -> None:
        """Dispatch a frame to beacon parsing or client tracking."""
        from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp

        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            self._add_ap(pkt)
            return
        dot11 = pkt.getlayer(Dot11)
        if dot11 is not None and getattr(dot11, "type", None) == 2:  # data frame
            self._track_client(dot11)

    def _add_ap(self, pkt: Any) -> None:
        """Parse a Beacon/ProbeResp and merge it, keeping the strongest signal."""
        ap = _parse_scapy_ap(pkt)
        if ap is None:
            return
        existing = self._aps.get(ap.bssid)
        if existing is None:
            self._aps[ap.bssid] = ap
            return
        if ap.signal_dbm and (existing.signal_dbm == 0 or ap.signal_dbm > existing.signal_dbm):
            existing.signal_dbm = ap.signal_dbm
        existing.ssid = existing.ssid or ap.ssid

    def _track_client(self, dot11: Any) -> None:
        """Record an (addr1, addr2) pair from a data frame for later matching."""
        addr1 = _norm_mac(getattr(dot11, "addr1", None))
        addr2 = _norm_mac(getattr(dot11, "addr2", None))
        if addr1 and addr2 and addr1 != addr2:
            self._data_pairs.add((addr1, addr2))

    def finalize(self, inventory: WirelessInventory) -> None:
        """Attribute clients to known APs, assess each, and add to inventory."""
        for bssid, ap in self._aps.items():
            for addr1, addr2 in self._data_pairs:
                client = _client_for_bssid(bssid, addr1, addr2)
                if client and client not in ap.clients:
                    ap.clients.append(client)
            ap.issues = assess_access_point(ap)
            inventory.add_ap(ap)


def _parse_scapy_ap(pkt: Any) -> AccessPoint | None:
    """Build an :class:`AccessPoint` from a scapy Beacon/ProbeResp frame."""
    from scapy.all import Dot11, Dot11Elt

    dot11 = pkt.getlayer(Dot11)
    if dot11 is None or not getattr(dot11, "addr3", None):
        return None
    ap = AccessPoint(bssid=str(dot11.addr3).upper(), source="scan")
    ap.signal_dbm = _scapy_signal(pkt)

    rsn: dict[str, Any] = {}
    wpa: dict[str, Any] = {}
    wps = False
    elt = pkt.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        eid = int(getattr(elt, "ID", -1))
        info = bytes(getattr(elt, "info", b"") or b"")
        if eid == 0:                                # SSID
            ap.ssid = _decode_ssid(info)
        elif eid == 3 and info:                     # DS Parameter Set -> channel
            ap.channel = info[0]
        elif eid == 48:                             # RSN -> WPA2 / WPA3
            rsn = parse_rsn_information(info)
        elif eid == 221:                            # vendor-specific
            if info.startswith(_WPA1_OUI_TYPE):
                wpa = _parse_suite_body(info[4:])
            if info.startswith(_WPS_OUI_TYPE):
                wps = True
        elt = elt.payload.getlayer(Dot11Elt)

    _apply_scapy_crypto(ap, pkt, rsn, wpa)
    ap.wps = wps
    ap.band = _band_from_channel(ap.channel)
    return ap


def _apply_scapy_crypto(
    ap: AccessPoint, pkt: Any, rsn: dict[str, Any], wpa: dict[str, Any]
) -> None:
    """Set encryption/cipher/auth from the parsed RSN or WPA IE (or privacy bit)."""
    if rsn:
        ap.encryption = rsn.get("encryption", "wpa2")
        ap.cipher = rsn.get("cipher", "")
        ap.auth = rsn.get("auth", "")
    elif wpa:
        ap.encryption = "wpa"
        ap.cipher = wpa.get("cipher", "")
        ap.auth = wpa.get("auth", "")
    elif _privacy_enabled(pkt):
        ap.encryption = "wep"
    else:
        ap.encryption = "open"


def _scapy_signal(pkt: Any) -> int:
    """Extract dBm antenna signal from the RadioTap header, if present."""
    from scapy.all import RadioTap

    radiotap = pkt.getlayer(RadioTap)
    if radiotap is None:
        return 0
    signal = getattr(radiotap, "dBm_AntSignal", None)
    if signal is None:
        return 0
    try:
        return int(signal)
    except (TypeError, ValueError):
        return 0


def _privacy_enabled(pkt: Any) -> bool:
    """True when the Beacon/ProbeResp capability Privacy bit is set."""
    from scapy.all import Dot11Beacon, Dot11ProbeResp

    layer = pkt.getlayer(Dot11Beacon) or pkt.getlayer(Dot11ProbeResp)
    if layer is None:
        return False
    try:
        return bool(int(layer.cap) & 0x10)
    except (TypeError, ValueError):
        return False


def _client_for_bssid(bssid: str, addr1: str, addr2: str) -> str:
    """Return the unicast client from a data-frame pair whose peer is ``bssid``."""
    if addr1 == bssid and _is_unicast(addr2):
        return addr2
    if addr2 == bssid and _is_unicast(addr1):
        return addr1
    return ""


# Fallback path: OS scan tools.


async def _scan_with_os_tools(inventory: WirelessInventory, iface: str | None) -> None:
    """Populate ``inventory`` from the first available OS Wi-Fi scan tool."""
    aps: list[AccessPoint] = []

    if shutil.which("nmcli"):
        text = await _run_command(["nmcli", "-t", "-f", "ALL", "dev", "wifi", "list"])
        if text:
            aps = parse_nmcli(text)

    if not aps and shutil.which("iw") and _is_root():
        target = iface or _default_wifi_iface()
        if target:
            text = await _run_command(["iw", "dev", target, "scan"])
            if text:
                aps = parse_iw_scan(text)

    if not aps and shutil.which("system_profiler"):
        text = await _run_command(["system_profiler", "-json", "SPAirPortDataType"])
        if text:
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                logger.debug("wifi_airport_json_invalid", error=str(exc))
                data = {}
            aps = parse_airport_json(data)

    for ap in aps:
        ap.issues = assess_access_point(ap)
        inventory.add_ap(ap)


async def _run_command(cmd: list[str], timeout: float = 20.0) -> str:
    """Run a read-only command and return its stdout, or '' on any failure."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except (OSError, ValueError) as exc:
        logger.debug("wifi_command_failed", cmd=cmd[0], error=str(exc))
        return ""
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(Exception):
            await proc.wait()
        logger.debug("wifi_command_timeout", cmd=cmd[0])
        return ""
    return stdout.decode("utf-8", "replace")


def _default_wifi_iface() -> str | None:
    """Best-effort: first Linux interface exposing a wireless directory."""
    net = "/sys/class/net"
    try:
        names = sorted(os.listdir(net))
    except OSError:
        return None
    for name in names:
        if os.path.isdir(os.path.join(net, name, "wireless")):
            return name
    return None


# Pure parser: `nmcli -t -f ALL dev wifi list`.


def parse_nmcli(text: str) -> list[AccessPoint]:
    """Parse `nmcli -t -f ALL dev wifi list` terse output into access points.

    Terse mode separates fields with ``:`` and backslash-escapes ``:`` inside
    values (notably the BSSID), so each line is split on unescaped colons and
    unescaped. Columns follow NetworkManager's ALL field order; the BSSID column
    is located by MAC pattern so minor column-count differences degrade
    gracefully. Unparseable lines are skipped. Never raises.
    """
    aps: list[AccessPoint] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        row = _nmcli_row(_split_terse(line))
        if row is None:
            continue
        ap = _ap_from_nmcli_row(row)
        if ap is not None:
            aps.append(ap)
    return aps


def _split_terse(line: str) -> list[str]:
    """Split an nmcli terse line on unescaped ':' and unescape each field."""
    fields: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(line):
        char = line[i]
        if char == "\\" and i + 1 < len(line):
            current.append(line[i + 1])
            i += 2
        elif char == ":":
            fields.append("".join(current))
            current = []
            i += 1
        else:
            current.append(char)
            i += 1
    fields.append("".join(current))
    return fields


def _nmcli_row(fields: list[str]) -> dict[str, str] | None:
    """Map terse fields to named columns, anchored on the BSSID column."""
    bssid_idx = next((i for i, f in enumerate(fields) if _MAC_RE.match(f)), None)
    if bssid_idx is None:
        return None
    base = bssid_idx - _NMCLI_FIELDS.index("BSSID")

    def get(name: str) -> str:
        idx = base + _NMCLI_FIELDS.index(name)
        return fields[idx] if 0 <= idx < len(fields) else ""

    return {name: get(name) for name in _NMCLI_FIELDS}


def _ap_from_nmcli_row(row: dict[str, str]) -> AccessPoint | None:
    """Build an :class:`AccessPoint` from a mapped nmcli row."""
    bssid = row.get("BSSID", "").upper()
    if not _MAC_RE.match(bssid):
        return None
    ap = AccessPoint(bssid=bssid, source="scan")
    ap.ssid = row.get("SSID", "")
    ap.channel = _to_int(row.get("CHAN", ""))
    ap.signal_dbm = _nmcli_signal_to_dbm(row.get("SIGNAL", ""))
    ap.band = _band_from_freq(_to_int(row.get("FREQ", ""))) or _band_from_channel(ap.channel)
    sec = _security_from_nmcli(row)
    ap.encryption = sec["encryption"]
    ap.cipher = sec["cipher"]
    ap.auth = sec["auth"]
    ap.wps = sec["wps"]
    return ap


def _security_from_nmcli(row: dict[str, str]) -> dict[str, Any]:
    """Map an nmcli SECURITY column plus RSN/WPA flags to crypto attributes."""
    sec = row.get("SECURITY", "").strip()
    tokens = sec.upper().replace("/", " ").split()
    flags = f"{row.get('WPA-FLAGS', '')} {row.get('RSN-FLAGS', '')}".lower()
    result = _blank_security()
    if not tokens or sec == "--":
        return result  # open network
    if "WEP" in tokens:
        result["encryption"] = "wep"
    elif "WPA3" in tokens or "SAE" in tokens or "sae" in flags:
        result["encryption"] = "wpa3"
    elif "WPA2" in tokens or "RSN" in tokens:
        result["encryption"] = "wpa2"
    elif any(t.startswith("WPA") for t in tokens):
        result["encryption"] = "wpa"
    result["cipher"] = _cipher_from_flags(flags)
    result["auth"] = _auth_from_flags(flags, tokens)
    result["wps"] = "wps" in flags
    return result


def _nmcli_signal_to_dbm(value: str) -> int:
    """Convert nmcli's 0-100 signal quality to an approximate dBm value."""
    quality = _to_int(value)
    if quality <= 0:
        return 0
    return int(quality / 2) - 100


# Pure parser: `iw dev <iface> scan`.


def parse_iw_scan(text: str) -> list[AccessPoint]:
    """Parse `iw dev <iface> scan` output into access points.

    The report is split into per-BSS blocks; each block yields SSID, channel /
    frequency, signal and the RSN/WPA/WPS sections. An RSN section implies WPA2
    (or WPA3 when SAE is an authentication suite); a lone WPA section implies
    WPA1; the Privacy capability with neither implies WEP. Never raises.
    """
    aps: list[AccessPoint] = []
    for block in _split_iw_blocks(text):
        ap = _ap_from_iw_block(block)
        if ap is not None:
            aps.append(ap)
    return aps


def _split_iw_blocks(text: str) -> list[list[str]]:
    """Group `iw scan` lines into one list of lines per BSS."""
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in text.splitlines():
        if _IW_BSS_RE.match(line.strip()):
            current = [line]
            blocks.append(current)
        elif current is not None:
            current.append(line)
    return blocks


def _ap_from_iw_block(block: list[str]) -> AccessPoint | None:
    """Build an :class:`AccessPoint` from one BSS block of `iw scan` output."""
    match = _IW_BSS_RE.match(block[0].strip())
    if match is None:
        return None
    ap = AccessPoint(bssid=match.group(1).upper(), source="scan")
    section = ""                       # "rsn" | "wpa" | "wps" | ""
    has_rsn = has_wpa = has_wps = privacy = False
    freq = 0
    ciphers: list[str] = []
    auths: list[str] = []

    for raw in block[1:]:
        line = raw.strip()
        low = line.lower()
        if low.startswith("ssid:"):
            ap.ssid = line.split(":", 1)[1].strip()
        elif low.startswith("freq:"):
            freq = _to_int(low.split(":", 1)[1])
        elif low.startswith("signal:"):
            ap.signal_dbm = _iw_signal_to_dbm(line)
        elif low.startswith("ds parameter set:"):
            ap.channel = _to_int(low.rsplit("channel", 1)[-1])
        elif "* primary channel:" in low:
            ap.channel = _to_int(low.split(":", 1)[1])
        elif low.startswith("rsn:"):
            section, has_rsn = "rsn", True
        elif low.startswith("wpa:"):
            section, has_wpa = "wpa", True
        elif low.startswith("wps:"):
            section, has_wps = "wps", True
        elif "capability:" in low:
            privacy = "privacy" in low
            section = ""
        elif section in ("rsn", "wpa"):
            _collect_iw_crypto(low, ciphers, auths)

    ap.channel = ap.channel or _channel_from_freq(freq)
    ap.band = _band_from_freq(freq) or _band_from_channel(ap.channel)
    ap.cipher = _primary_cipher(ciphers)
    ap.auth = _first_auth(auths)
    if has_rsn:
        ap.encryption = "wpa3" if "SAE" in auths else "wpa2"
    elif has_wpa:
        ap.encryption = "wpa"
    elif privacy:
        ap.encryption = "wep"
    else:
        ap.encryption = "open"
    ap.wps = has_wps
    return ap


def _collect_iw_crypto(low: str, ciphers: list[str], auths: list[str]) -> None:
    """Read cipher / authentication-suite names from a line inside an RSN/WPA block."""
    if "cipher" in low:  # "Group cipher:" or "Pairwise ciphers:"
        for name in ("ccmp-256", "gcmp-256", "ccmp", "gcmp", "tkip", "wep-104",
                     "wep-40", "wep"):
            if name in low:
                ciphers.append(name.upper())
                break
    elif "authentication suites:" in low or "akm:" in low:
        if "sae" in low:
            auths.append("SAE")
        if "psk" in low:
            auths.append("PSK")
        if "802.1x" in low or "eap" in low:
            auths.append("802.1X")


def _iw_signal_to_dbm(line: str) -> int:
    """Extract the dBm value from an `iw` ``signal:`` line."""
    match = re.search(r"(-?\d+(?:\.\d+)?)", line)
    return int(float(match.group(1))) if match else 0


# Pure parser: macOS `system_profiler -json SPAirPortDataType`.


def parse_airport_json(data: dict[str, Any]) -> list[AccessPoint]:
    """Parse `system_profiler -json SPAirPortDataType` into access points.

    Walks each Wi-Fi interface's discovered networks (and the currently
    associated one) and maps macOS security-mode strings to
    encryption/cipher/auth. BSSID is used when present, otherwise the SSID keys
    the entry (recent macOS omits BSSID without location permission). Never
    raises.
    """
    aps: list[AccessPoint] = []
    if not isinstance(data, dict):
        return aps
    for entry in _as_list(data.get("SPAirPortDataType")):
        if not isinstance(entry, dict):
            continue
        for iface in _as_list(entry.get("spairport_airport_interfaces")):
            aps.extend(_airport_networks(iface))
    return aps


def _airport_networks(iface: Any) -> list[AccessPoint]:
    """Extract access points from a single Wi-Fi interface record."""
    if not isinstance(iface, dict):
        return []
    nets = list(_as_list(iface.get("spairport_airport_other_local_wireless_networks")))
    current = iface.get("spairport_current_network_information")
    if isinstance(current, dict):
        nets.append(current)
    result: list[AccessPoint] = []
    for net in nets:
        ap = _ap_from_airport_net(net)
        if ap is not None:
            result.append(ap)
    return result


def _ap_from_airport_net(net: Any) -> AccessPoint | None:
    """Build an :class:`AccessPoint` from one macOS network dict."""
    if not isinstance(net, dict):
        return None
    name = str(net.get("_name", "") or "")
    bssid = str(net.get("spairport_network_bssid", "") or "").upper()
    identifier = bssid or name
    if not identifier:
        return None
    ap = AccessPoint(bssid=identifier, source="scan")
    ap.ssid = name
    channel_raw = str(net.get("spairport_network_channel", "") or "")
    ap.channel = _to_int(channel_raw)
    ap.band = _airport_band(channel_raw) or _band_from_channel(ap.channel)
    ap.signal_dbm = _airport_signal(net.get("spairport_signal_noise", ""))
    sec = _airport_security(str(net.get("spairport_security_mode", "") or ""))
    ap.encryption = sec["encryption"]
    ap.cipher = sec["cipher"]
    ap.auth = sec["auth"]
    ap.wps = sec["wps"]
    return ap


def _airport_security(mode: str) -> dict[str, Any]:
    """Map a macOS ``spairport_security_mode`` string to crypto attributes."""
    low = mode.lower()
    result = _blank_security()
    if not low or "none" in low or "open" in low:
        return result
    if "wep" in low:
        result["encryption"] = "wep"
        return result
    if "wpa3" in low:
        result["encryption"] = "wpa3"
        result["cipher"] = "CCMP"
        result["auth"] = "802.1X" if "enterprise" in low else "SAE"
    elif "wpa2" in low:
        result["encryption"] = "wpa2"
        result["cipher"] = "CCMP"
        result["auth"] = "802.1X" if "enterprise" in low else "PSK"
    elif "wpa" in low:
        result["encryption"] = "wpa"
        result["cipher"] = "TKIP"
        result["auth"] = "802.1X" if "enterprise" in low else "PSK"
    return result


def _airport_band(raw: str) -> str:
    """Derive the band from a macOS channel string like ``36 (5GHz, 80MHz)``."""
    low = raw.lower()
    if "6ghz" in low:
        return "6GHz"
    if "5ghz" in low:
        return "5GHz"
    if "2ghz" in low or "2.4ghz" in low:
        return "2.4GHz"
    return ""


def _airport_signal(raw: Any) -> int:
    """Extract the signal dBm from a macOS ``-45 dBm / -90 dBm`` string."""
    match = re.search(r"(-?\d+)", str(raw or ""))
    return int(match.group(1)) if match else 0


# Pure RSN / WPA information-element decoding.


def parse_rsn_information(raw: bytes) -> dict[str, Any]:
    """Parse the body of an RSN information element (802.11 id 48).

    ``raw`` is the element payload (scapy ``Dot11Elt.info``) beginning at the
    2-byte version field — id and length are already stripped. Returns the
    version, group/pairwise ciphers, AKM suites and the derived
    encryption/cipher/auth (WPA3 when an SAE AKM is present, else WPA2).
    Truncated or malformed input yields whatever could be read; never raises.
    """
    info = _parse_suite_body(raw)
    info["encryption"] = "wpa3" if any("SAE" in a for a in info["akms"]) else "wpa2"
    return info


def _parse_suite_body(raw: bytes) -> dict[str, Any]:
    """Parse the version/group/pairwise/AKM structure shared by RSN and WPA IEs."""
    result: dict[str, Any] = {
        "version": 0, "group_cipher": "", "pairwise_ciphers": [],
        "akms": [], "cipher": "", "auth": "",
    }
    if len(raw) < 2:
        return result
    result["version"] = int.from_bytes(raw[:2], "little")
    pos = 2
    if len(raw) >= pos + 4:
        result["group_cipher"] = _suite_name(raw[pos:pos + 4], _RSN_CIPHERS)
        pos += 4
    pairwise, pos = _read_suite_list(raw, pos, _RSN_CIPHERS)
    akms, pos = _read_suite_list(raw, pos, _RSN_AKMS)
    result["pairwise_ciphers"] = pairwise
    result["akms"] = akms
    result["cipher"] = _primary_cipher(pairwise) or result["group_cipher"]
    result["auth"] = akms[0] if akms else ""
    return result


def _read_suite_list(
    raw: bytes, pos: int, table: dict[int, str]
) -> tuple[list[str], int]:
    """Read a 2-byte count followed by that many 4-byte suite selectors."""
    if len(raw) < pos + 2:
        return [], pos
    count = int.from_bytes(raw[pos:pos + 2], "little")
    pos += 2
    names: list[str] = []
    for _ in range(count):
        if len(raw) < pos + 4:
            break
        name = _suite_name(raw[pos:pos + 4], table)
        if name:
            names.append(name)
        pos += 4
    return names, pos


def _suite_name(selector: bytes, table: dict[int, str]) -> str:
    """Map a 4-byte suite selector to a name via its final type byte."""
    if len(selector) < 4:
        return ""
    return table.get(selector[3], "")


def _primary_cipher(ciphers: list[str]) -> str:
    """Prefer a strong pairwise cipher; otherwise the first one present."""
    for strong in ("CCMP", "GCMP", "GCMP-256", "CCMP-256"):
        if strong in ciphers:
            return strong
    return ciphers[0] if ciphers else ""


def _first_auth(auths: list[str]) -> str:
    """Return the most notable authentication suite (SAE > 802.1X > PSK)."""
    for pref in ("SAE", "802.1X", "PSK"):
        if pref in auths:
            return pref
    return auths[0] if auths else ""


# Shared helpers.


def _blank_security() -> dict[str, Any]:
    """A fresh open-network security mapping."""
    return {"encryption": "open", "cipher": "", "auth": "", "wps": False}


def _cipher_from_flags(flags: str) -> str:
    """Pick a cipher name from lowercased nmcli WPA/RSN flag text."""
    if "ccmp" in flags:
        return "CCMP"
    if "gcmp" in flags:
        return "GCMP"
    if "tkip" in flags:
        return "TKIP"
    return ""


def _auth_from_flags(flags: str, tokens: list[str]) -> str:
    """Pick an auth name from nmcli flag text / SECURITY tokens."""
    if "sae" in flags or "SAE" in tokens:
        return "SAE"
    if "802.1x" in flags or "802.1X" in tokens or "eap" in flags:
        return "802.1X"
    if "psk" in flags:
        return "PSK"
    if any(t.startswith("WPA") for t in tokens):
        return "PSK"  # WPA/WPA2 with no explicit AKM flags is almost always PSK
    return ""


def _band_from_channel(channel: int) -> str:
    """Approximate the band from a channel number (2.4GHz vs 5GHz)."""
    if 1 <= channel <= 14:
        return "2.4GHz"
    if channel >= 15:
        return "5GHz"
    return ""


def _band_from_freq(freq: int) -> str:
    """Derive the band from a centre frequency in MHz."""
    if 2400 <= freq < 2500:
        return "2.4GHz"
    if 4900 <= freq < 5900:
        return "5GHz"
    if 5900 <= freq <= 7125:
        return "6GHz"
    return ""


def _channel_from_freq(freq: int) -> int:
    """Convert a centre frequency in MHz to a channel number."""
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 5000 <= freq < 5900:
        return (freq - 5000) // 5
    if 5900 <= freq <= 7125:
        return (freq - 5950) // 5
    return 0


def _to_int(value: str) -> int:
    """Parse a leading (optionally negative) integer from text; 0 when absent."""
    match = re.match(r"\s*(-?\d+)", value or "")
    return int(match.group(1)) if match else 0


def _decode_ssid(raw: bytes) -> str:
    """Decode an SSID element; hidden/empty SSIDs become ''."""
    return raw.decode("utf-8", "replace").rstrip("\x00") if raw else ""


def _norm_mac(mac: Any) -> str:
    """Normalise a MAC to upper-case, or '' when unusable."""
    return mac.upper() if isinstance(mac, str) and mac else ""


def _is_unicast(mac: str) -> bool:
    """True for a real unicast MAC (not empty, broadcast, or multicast)."""
    if not mac or mac == "FF:FF:FF:FF:FF:FF":
        return False
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return not (first & 0x01)  # the I/G bit marks multicast/broadcast


def _as_list(value: Any) -> list[Any]:
    """Coerce a value to a list: a list stays, ``None`` -> [], else wrapped."""
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _is_root() -> bool:
    """True only when the process can be confirmed to run as root (POSIX)."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:  # non-POSIX (e.g. Windows): cannot be root here
        return False
    return geteuid() == 0


def _scapy_available() -> bool:
    """True when scapy can be imported, without importing it eagerly."""
    try:
        return importlib.util.find_spec("scapy") is not None
    except (ImportError, ValueError):
        return False
