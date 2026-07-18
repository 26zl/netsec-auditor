"""Wireless inventory types and read-only security assessment.

Covers Wi-Fi access points / clients and BLE devices. All capabilities here are
passive/read-only recon and audit — no deauth, handshake capture, or attacks.
The ``assess_*`` helpers are pure so they can be unit-tested without radios.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AccessPoint:
    """A Wi-Fi access point observed live or imported from wardriving data."""

    bssid: str
    ssid: str = ""
    channel: int = 0
    band: str = ""              # "2.4GHz" | "5GHz" | "6GHz"
    encryption: str = "open"    # open | wep | wpa | wpa2 | wpa3 | wpa2/wpa3
    cipher: str = ""            # TKIP | CCMP | GCMP | ...
    auth: str = ""              # PSK | SAE | 802.1X | ...
    wps: bool = False
    signal_dbm: int = 0
    vendor: str = ""
    clients: list[str] = field(default_factory=list)
    latitude: float | None = None
    longitude: float | None = None
    source: str = "scan"        # scan | wigle | gpx | kismet
    issues: list[str] = field(default_factory=list)

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
    connectable: bool = True
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
        existing = self.access_points.get(ap.bssid.upper())
        if existing is None:
            self.access_points[ap.bssid.upper()] = ap
            return
        # Merge: keep the strongest signal and richest fields.
        if ap.signal_dbm and (not existing.signal_dbm or ap.signal_dbm > existing.signal_dbm):
            existing.signal_dbm = ap.signal_dbm
        existing.ssid = existing.ssid or ap.ssid
        existing.vendor = existing.vendor or ap.vendor
        for client in ap.clients:
            if client not in existing.clients:
                existing.clients.append(client)

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
    cipher = ap.cipher.lower()
    auth = ap.auth.lower()

    if enc in ("", "open", "none", "opn"):
        issues.append("Open network — no encryption; traffic can be eavesdropped")
    if "wep" in enc:
        issues.append("WEP encryption — trivially crackable; migrate to WPA2/WPA3")
    if enc in ("wpa", "wpa1"):
        issues.append("WPA (v1) — deprecated; upgrade to WPA2/WPA3")
    if "tkip" in cipher:
        issues.append("TKIP cipher — weak; require CCMP/AES")
    if ap.wps:
        issues.append("WPS enabled — vulnerable to PIN brute force (Pixie Dust)")
    if enc == "wpa2" and "sae" not in auth and "wpa3" not in enc:
        issues.append("WPA2-only — consider WPA3 (SAE) for offline-attack resistance")
    if "802.1x" not in auth and "psk" in auth and _is_guessable(ap.ssid):
        issues.append("Default/guessable SSID with PSK — verify a strong passphrase")
    return issues


def detect_evil_twins(aps: list[AccessPoint]) -> None:
    """Flag possible rogue/evil-twin APs: one SSID advertised by multiple BSSIDs.

    Annotates each affected AP's ``issues`` in place. This is a heuristic — large
    enterprise WLANs legitimately share an SSID across many BSSIDs (roaming), so
    differing encryption across the group is the stronger signal.
    """
    by_ssid: dict[str, list[AccessPoint]] = {}
    for ap in aps:
        if ap.ssid:
            by_ssid.setdefault(ap.ssid, []).append(ap)

    for ssid, group in by_ssid.items():
        bssids = {ap.bssid.upper() for ap in group}
        if len(bssids) < 2:
            continue
        encryptions = {ap.encryption.lower() for ap in group}
        message = f"Possible rogue/evil-twin: SSID '{ssid}' on {len(bssids)} BSSIDs"
        if len(encryptions) > 1:
            message += f" with differing encryption ({', '.join(sorted(encryptions))})"
        for ap in group:
            if message not in ap.issues:
                ap.issues.append(message)


def assess_ble_device(device: BleDevice) -> list[str]:
    """Return read-only security findings for a BLE device."""
    issues: list[str] = []
    if device.connectable and not device.services:
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
