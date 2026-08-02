"""Wireless inventory types and read-only security assessment.

Covers Wi-Fi access points / clients and BLE devices. All capabilities here are
read-only recon and audit — no deauth, handshake capture, or attacks.
The ``assess_*`` helpers are pure so they can be unit-tested without radios.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_NAME_LIMIT = 64


def sanitize_name(text: str, limit: int = _NAME_LIMIT) -> str:
    """Reduce an attacker-controlled SSID / device name to a printable token.

    SSIDs and BLE names are broadcast by untrusted radios and end up in logs and
    terminal tables, so control characters are dropped and the length is capped.
    """
    cleaned = "".join(ch for ch in str(text or "") if ch.isprintable())
    return cleaned[:limit]


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


@dataclass
class AccessPoint:
    """A Wi-Fi access point observed live or imported from wardriving data."""

    bssid: str
    ssid: str = ""
    channel: int = 0
    band: str = ""              # "2.4GHz" | "5GHz" | "6GHz"
    encryption: str = "open"    # open | owe | wep | wpa | wpa2 | wpa3 | wpa2/wpa3
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
        """De-duplication key: the BSSID when known, otherwise the SSID."""
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

    def add_ap(self, ap: AccessPoint) -> None:
        existing = self.access_points.get(ap.key)
        if existing is None:
            self.access_points[ap.key] = ap
            return
        # Merge: keep the strongest signal and richest fields. Wardrive exports
        # carry one row per sighting, so later rows often fill earlier gaps.
        if ap.signal_dbm and (not existing.signal_dbm or ap.signal_dbm > existing.signal_dbm):
            existing.signal_dbm = ap.signal_dbm
        for name in ("ssid", "vendor", "channel", "band", "cipher", "auth",
                     "latitude", "longitude"):
            if not getattr(existing, name) and getattr(ap, name):
                setattr(existing, name, getattr(ap, name))
        existing.wps = existing.wps or ap.wps
        if existing.encryption in ("", "open") and ap.encryption not in ("", "open"):
            existing.encryption = ap.encryption
        for client in ap.clients:
            if client not in existing.clients:
                existing.clients.append(client)
        existing.issues = assess_access_point(existing)

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


def detect_evil_twins(aps: list[AccessPoint]) -> None:
    """Flag possible rogue/evil-twin APs, annotating ``issues`` in place.

    Sharing an SSID across BSSIDs is normal (dual-band routers, mesh nodes and
    enterprise roaming all do it), so a group is only reported when its members
    disagree on encryption or come from different vendors (OUIs). APs with no
    known BSSID are skipped — they cannot be told apart.
    """
    by_ssid: dict[str, list[AccessPoint]] = {}
    for ap in aps:
        if ap.ssid and ap.bssid:
            by_ssid.setdefault(ap.ssid, []).append(ap)

    for ssid, group in by_ssid.items():
        bssids = {ap.bssid.upper() for ap in group}
        if len(bssids) < 2:
            continue
        encryptions = {ap.encryption.lower() for ap in group}
        ouis = {bssid[:8] for bssid in bssids}
        prefix = f"Possible rogue/evil-twin: SSID '{ssid}' on {len(bssids)} BSSIDs"
        if len(encryptions) > 1:
            message = f"{prefix} with differing encryption ({', '.join(sorted(encryptions))})"
        elif len(ouis) > 1:
            message = f"{prefix} from different vendors ({', '.join(sorted(ouis))})"
        else:
            continue
        for ap in group:
            if message not in ap.issues:
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
