"""Wireless inventory types and read-only security assessment.

Covers Wi-Fi access points / clients and BLE devices. All capabilities here are
read-only recon and audit — no deauth, handshake capture, or attacks.
The ``assess_*`` helpers are pure so they can be unit-tested without radios.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Any

_NAME_LIMIT = 64

# Sightings kept for one BSSID advertised with conflicting parameters.
MAX_SIGHTINGS_PER_BSSID = 8
# Clients attributed to a single access point.
MAX_CLIENTS_PER_AP = 256

# Issue prefixes for findings that compare access points with each other.
_EVIL_TWIN = "Possible rogue/evil-twin"
_CLONED_BSSID = "Possible cloned-BSSID evil twin"
_LOOKALIKE = "Lookalike SSID"
_CROSS_AP_PREFIXES = (_EVIL_TWIN, _CLONED_BSSID, _LOOKALIKE)
_LOOKALIKE_LISTED = 3

# Cyrillic and Greek letters that render like Latin ones, mapped case-preservingly.
_HOMOGLYPHS = str.maketrans({
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0423": "Y", "\u0425": "X", "\u0405": "S", "\u0406": "I", "\u0408": "J",
    "\u04ae": "Y", "\u04c0": "I", "\u051a": "Q", "\u051c": "W",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0455": "s", "\u0456": "i", "\u0458": "j",
    "\u04bb": "h", "\u04cf": "l", "\u0501": "d", "\u051b": "q", "\u051d": "w",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O",
    "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X", "\u03f9": "C",
    "\u03b1": "a", "\u03b9": "i", "\u03ba": "k", "\u03bd": "v", "\u03bf": "o",
    "\u03c1": "p", "\u03c5": "u", "\u03c7": "x", "\u03f2": "c", "\u03f3": "j",
})


def sanitize_name(text: str, limit: int = _NAME_LIMIT) -> str:
    """Reduce an attacker-controlled SSID / device name to a printable token.

    SSIDs and BLE names are broadcast by untrusted radios and end up in logs and
    terminal tables, so control characters are dropped and the length is capped.
    """
    cleaned = "".join(ch for ch in str(text or "") if ch.isprintable())
    return cleaned[:limit]


def ssid_skeleton(ssid: str) -> str:
    """Fold an SSID to a comparison key so visually confusable names collide.

    NFKC folds width and compatibility forms, the homoglyph table maps Cyrillic
    and Greek look-alikes to Latin, and casefolding removes case differences.
    """
    return unicodedata.normalize("NFKC", ssid).translate(_HOMOGLYPHS).casefold()


def band_for_channel(channel: int) -> str:
    """Best-effort band label from a channel number.

    6 GHz reuses 5 GHz channel numbers, so anything outside the unambiguous
    ranges returns "" and the caller falls back to the centre frequency.
    """
    if 1 <= channel <= 14:
        return "2.4GHz"
    if 32 <= channel <= 196:
        return "5GHz"
    return ""


@dataclass(slots=True)  # wardrive imports hold hundreds of thousands of these
class AccessPoint:
    """A Wi-Fi access point observed live or imported from wardriving data."""

    bssid: str
    ssid: str = ""
    channel: int = 0
    band: str = ""              # "2.4GHz" | "5GHz" | "6GHz"
    encryption: str = ""        # "" (unknown) | open | owe | wep | wpa | wpa2 | wpa3 | wpa2/wpa3
    cipher: str = ""            # "+"-joined: "CCMP" | "CCMP+TKIP" | ...
    auth: str = ""              # PSK | SAE | 802.1X | OWE | ...
    wps: bool = False
    signal_dbm: int = 0
    vendor: str = ""
    clients: list[str] = field(default_factory=list)
    latitude: float | None = None
    longitude: float | None = None
    source: str = "scan"        # scan | wigle | gpx | kismet
    issues: list[str] = field(default_factory=list)

    @property
    def ciphers(self) -> list[str]:
        """Every cipher advertised, split out of the joined :attr:`cipher` string."""
        return [part.strip().upper() for part in self.cipher.split("+") if part.strip()]

    @property
    def key(self) -> str:
        """De-duplication key: the BSSID when known, otherwise the SSID.

        An AP with neither is anonymous and is not de-duplicated at all (see
        :meth:`WirelessInventory.add_ap`), so it never reaches this fallback.
        Sightings that conflict with each other are kept apart even when they
        share this key.
        """
        return self.bssid.upper() if self.bssid else f"ssid:{self.ssid}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "band": self.band,
            "encryption": self.encryption,
            "cipher": self.cipher,
            "auth": self.auth,
            "wps": self.wps,
            "signal_dbm": self.signal_dbm,
            "vendor": self.vendor,
            "clients": self.clients,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "source": self.source,
            "issues": self.issues,
        }


@dataclass
class BleDevice:
    """A Bluetooth Low Energy device observed during a passive scan."""

    address: str
    name: str = ""
    rssi: int = 0
    vendor: str = ""
    services: list[str] = field(default_factory=list)
    appearance: str = ""
    connectable: bool | None = None   # None when the backend does not report it
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "name": self.name,
            "rssi": self.rssi,
            "vendor": self.vendor,
            "services": self.services,
            "appearance": self.appearance,
            "connectable": self.connectable,
            "issues": self.issues,
        }


@dataclass
class WirelessInventory:
    """Aggregated Wi-Fi and BLE observations, de-duplicated by identifier."""

    access_points: dict[str, AccessPoint] = field(default_factory=dict)
    ble_devices: dict[str, BleDevice] = field(default_factory=dict)
    _anon_seq: int = field(default=0, repr=False)

    def add_ap(self, ap: AccessPoint) -> None:
        """Add a sighting, merging it into a compatible sighting of the same AP.

        A sighting that disagrees with every earlier sighting of its BSSID on
        encryption, channel or SSID is kept as its own row and all of them are
        flagged as a possible cloned-BSSID evil twin, instead of being merged away.
        """
        if not ap.bssid and not ap.ssid:
            # No stable identifier — macOS withholds both the BSSID and the SSID
            # without location permission. Keep every reported network instead of
            # merging distinct ones that merely share a channel and encryption.
            self.access_points[f"anon:{self._anon_seq}"] = ap
            self._anon_seq += 1
            return
        sightings = self._sightings(ap.key)
        for existing in sightings:
            if not sighting_conflicts(existing, ap):
                merge_sighting(existing, ap)
                break
        else:
            if len(sightings) >= MAX_SIGHTINGS_PER_BSSID:
                return
            slot = f"{ap.key}#{len(sightings) + 1}" if sightings else ap.key
            self.access_points[slot] = ap
            sightings.append(ap)
        if ap.bssid and len(sightings) > 1:
            message = cloned_bssid_message(sightings)
            for sighting in sightings:
                _set_flag(sighting, _CLONED_BSSID, message)

    def _sightings(self, key: str) -> list[AccessPoint]:
        """Every stored sighting for ``key`` (extra sightings live at ``key#2``...)."""
        found: list[AccessPoint] = []
        slot = key
        while slot in self.access_points:
            found.append(self.access_points[slot])
            slot = f"{key}#{len(found) + 1}"
        return found

    def add_ble(self, device: BleDevice) -> None:
        self.ble_devices[device.address.upper()] = device

    def aps(self) -> list[AccessPoint]:
        return sorted(self.access_points.values(), key=lambda a: a.signal_dbm, reverse=True)

    def ble(self) -> list[BleDevice]:
        return sorted(self.ble_devices.values(), key=lambda d: d.rssi, reverse=True)


def assess_access_point(ap: AccessPoint) -> list[str]:
    """Return read-only security findings for an access point."""
    issues: list[str] = []
    enc = ap.encryption.lower()
    auth = ap.auth.lower()

    # "owe" (Enhanced Open) is unauthenticated but encrypted, so it is not open.
    if enc in ("", "open", "none", "opn"):
        issues.append("Open network — no encryption; traffic can be eavesdropped")
    if "wep" in enc:
        issues.append("WEP encryption — trivially crackable; migrate to WPA2/WPA3")
    if enc in ("wpa", "wpa1"):
        issues.append("WPA (v1) — deprecated; upgrade to WPA2/WPA3")
    if "TKIP" in ap.ciphers:
        issues.append("TKIP cipher — weak; require CCMP/AES")
    if ap.wps:
        issues.append("WPS enabled — vulnerable to PIN brute force (Pixie Dust)")
    if enc == "wpa2" and "sae" not in auth:
        issues.append("WPA2-only — consider WPA3 (SAE) for offline-attack resistance")
    if "802.1x" not in auth and "psk" in auth and _is_guessable(ap.ssid):
        issues.append("Default/guessable SSID with PSK — verify a strong passphrase")
    return issues


def sighting_conflicts(a: AccessPoint, b: AccessPoint) -> list[str]:
    """Name the attributes on which two sightings of one BSSID disagree.

    Unknown values (empty encryption or SSID, channel 0) never conflict, so a
    sparse sighting can still fill the gaps of a richer one. A hidden-SSID
    beacon and the probe response that names it therefore merge.
    """
    conflicts: list[str] = []
    if a.encryption and b.encryption and a.encryption.lower() != b.encryption.lower():
        conflicts.append("encryption")
    if a.channel and b.channel and a.channel != b.channel:
        conflicts.append("channel")
    if a.ssid and b.ssid and a.ssid != b.ssid:
        conflicts.append("SSID")
    return conflicts


def merge_sighting(existing: AccessPoint, ap: AccessPoint) -> None:
    """Fold a compatible sighting into ``existing`` and re-assess it.

    Keeps the strongest signal, fills empty fields and caps the client list;
    findings that compare access points with each other are preserved.
    """
    if ap.signal_dbm and (not existing.signal_dbm or ap.signal_dbm > existing.signal_dbm):
        existing.signal_dbm = ap.signal_dbm
    for name in ("ssid", "vendor", "channel", "band", "encryption", "cipher", "auth",
                 "latitude", "longitude"):
        if not getattr(existing, name) and getattr(ap, name):
            setattr(existing, name, getattr(ap, name))
    existing.wps = existing.wps or ap.wps
    for client in ap.clients:
        if len(existing.clients) >= MAX_CLIENTS_PER_AP:
            break
        if client not in existing.clients:
            existing.clients.append(client)
    kept = [issue for issue in existing.issues if issue.startswith(_CROSS_AP_PREFIXES)]
    existing.issues = assess_access_point(existing) + kept


def cloned_bssid_message(sightings: list[AccessPoint]) -> str | None:
    """Describe how sightings of one BSSID conflict, or None when they agree.

    The BSSID itself is left out so the message survives report redaction.
    """
    parts: list[str] = []
    encryptions = sorted({ap.encryption.lower() for ap in sightings if ap.encryption})
    if len(encryptions) > 1:
        parts.append(f"encryption ({', '.join(encryptions)})")
    channels = sorted({ap.channel for ap in sightings if ap.channel})
    if len(channels) > 1:
        parts.append(f"channel ({', '.join(str(channel) for channel in channels)})")
    ssids = sorted({ap.ssid for ap in sightings if ap.ssid})
    if len(ssids) > 1:
        parts.append("SSID (" + ", ".join(f"'{ssid}'" for ssid in ssids) + ")")
    if not parts:
        return None
    return f"{_CLONED_BSSID}: one BSSID advertised with conflicting {'; '.join(parts)}"


def detect_evil_twins(aps: list[AccessPoint]) -> None:
    """Flag possible rogue/evil-twin APs, annotating ``issues`` in place.

    Three independent checks:

    * Shared SSID: sharing an SSID across BSSIDs is normal (dual-band routers,
      mesh nodes and enterprise roaming all do it), so a group is only reported
      when its members disagree on encryption or come from different vendors
      (OUIs). APs with no known BSSID are skipped — they cannot be told apart.
    * Cloned BSSID: one BSSID seen with conflicting encryption, channel or SSID.
    * Lookalike SSID: different SSIDs that fold to the same
      :func:`ssid_skeleton` (case, width or Cyrillic/Greek homoglyphs).
    """
    _flag_shared_ssids(aps)
    _flag_cloned_bssids(aps)
    _flag_lookalike_ssids(aps)


def _flag_shared_ssids(aps: list[AccessPoint]) -> None:
    """Flag exact-SSID groups whose BSSIDs disagree on encryption or vendor."""
    by_ssid: dict[str, list[AccessPoint]] = {}
    for ap in aps:
        if ap.ssid and ap.bssid:
            by_ssid.setdefault(ap.ssid, []).append(ap)

    for ssid, group in by_ssid.items():
        bssids = {ap.bssid.upper() for ap in group}
        if len(bssids) < 2:
            continue
        encryptions = {ap.encryption.lower() for ap in group if ap.encryption}
        ouis = {bssid[:8] for bssid in bssids}
        prefix = f"{_EVIL_TWIN}: SSID '{ssid}' on {len(bssids)} BSSIDs"
        if len(encryptions) > 1:
            message = f"{prefix} with differing encryption ({', '.join(sorted(encryptions))})"
        elif len(ouis) > 1:
            message = f"{prefix} from different vendors ({', '.join(sorted(ouis))})"
        else:
            continue
        for ap in group:
            if message not in ap.issues:
                ap.issues.append(message)


def _flag_cloned_bssids(aps: list[AccessPoint]) -> None:
    """Flag every sighting of a BSSID that is advertised with conflicting parameters."""
    by_bssid: dict[str, list[AccessPoint]] = {}
    for ap in aps:
        if ap.bssid:
            by_bssid.setdefault(ap.bssid.upper(), []).append(ap)
    for group in by_bssid.values():
        if len(group) < 2:
            continue
        message = cloned_bssid_message(group)
        if message is not None:
            for ap in group:
                _set_flag(ap, _CLONED_BSSID, message)


def _flag_lookalike_ssids(aps: list[AccessPoint]) -> None:
    """Flag distinct SSIDs that look the same once case, width and homoglyphs are folded."""
    by_skeleton: dict[str, list[AccessPoint]] = {}
    for ap in aps:
        if ap.ssid:
            by_skeleton.setdefault(ssid_skeleton(ap.ssid), []).append(ap)
    for group in by_skeleton.values():
        names = {ap.ssid for ap in group}
        if len(names) < 2:
            continue
        for ap in group:
            others = sorted(names - {ap.ssid})
            listed = ", ".join(f"'{name}'" for name in others[:_LOOKALIKE_LISTED])
            if len(others) > _LOOKALIKE_LISTED:
                listed += f" and {len(others) - _LOOKALIKE_LISTED} more"
            message = f"{_LOOKALIKE}: '{ap.ssid}' resembles {listed} (possible evil twin)"
            _set_flag(ap, _LOOKALIKE, message)


def _set_flag(ap: AccessPoint, prefix: str, message: str | None) -> None:
    """Replace any finding starting with ``prefix`` by ``message`` (or just drop it)."""
    ap.issues = [issue for issue in ap.issues if not issue.startswith(prefix)]
    if message is not None:
        ap.issues.append(message)


def assess_ble_device(device: BleDevice) -> list[str]:
    """Return read-only security findings for a BLE device."""
    issues: list[str] = []
    if device.connectable is True and not device.services:
        issues.append("Connectable BLE device with no advertised services — probe access controls")
    if device.name and _is_guessable(device.name):
        issues.append("Generic/default device name — verify pairing and firmware hardening")
    return issues


def _is_guessable(name: str) -> bool:
    """Heuristic: does an SSID/name look default or vendor-generic?"""
    lowered = name.lower()
    markers = (
        "default", "linksys", "netgear", "dlink", "d-link", "tplink", "tp-link",
        "xfinity", "guest", "setup", "admin", "router", "printer", "camera",
    )
    return any(marker in lowered for marker in markers)
