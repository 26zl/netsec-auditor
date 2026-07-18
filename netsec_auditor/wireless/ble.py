"""Passive Bluetooth Low Energy (BLE) recon — read-only IoT device audit.

This module performs a *passive* BLE advertisement scan: it listens for the
advertising packets devices broadcast and never connects, pairs, writes, or
otherwise interacts with them. That makes it safe for auditing IoT estates
without disturbing the devices under test.

The live scan needs the optional :mod:`bleak` backend (and a Bluetooth adapter),
imported lazily so this module imports cleanly without it — :func:`scan_ble`
degrades to an empty list with a clear warning when bleak is missing or the scan
fails, and never raises. The advertisement-to-model conversion
(:func:`build_ble_device`) and the vendor lookup (:func:`vendor_from_company_id`)
are pure and need neither bleak nor a radio, so they are fully unit-testable.
"""

from __future__ import annotations

from netsec_auditor.utils.logging import get_logger
from netsec_auditor.wireless.base import BleDevice, assess_ble_device

logger = get_logger(__name__)

# A small subset of the Bluetooth SIG "Company Identifiers" (assigned numbers).
# The 16-bit company id is the leading field of a manufacturer-specific
# advertisement data record, so it identifies the silicon/brand behind an
# advertising device even when it broadcasts no readable name.
_COMPANY_IDS: dict[int, str] = {
    0x0001: "Nokia",
    0x0002: "Intel",
    0x0006: "Microsoft",
    0x000D: "Texas Instruments",
    0x000F: "Broadcom",
    0x004C: "Apple",
    0x0059: "Nordic Semiconductor",
    0x0075: "Samsung",
    0x0087: "Garmin",
    0x00E0: "Google",
    0x0131: "Cypress Semiconductor",
    0x0157: "Anhui Huami",
    0x0171: "Amazon",
    0x0499: "Ruuvi Innovations",
}


def vendor_from_company_id(company_id: int) -> str:
    """Map a 16-bit Bluetooth SIG company identifier to a short vendor name.

    Returns ``""`` for identifiers not in the built-in table — the same default
    the :attr:`BleDevice.vendor` field carries when the vendor is unknown.
    """
    return _COMPANY_IDS.get(company_id, "")


def build_ble_device(
    address: str,
    name: str,
    rssi: int,
    service_uuids: list[str],
    manufacturer_data: dict[int, bytes],
) -> BleDevice:
    """Convert raw advertisement fields into an assessed :class:`BleDevice`.

    Pure and bleak-free, so it can be unit-tested without a radio. The vendor is
    resolved from the *first* company identifier in ``manufacturer_data`` (its
    16-bit key); that identifier is also recorded in ``appearance`` as a
    ``0xNNNN`` token so the raw manufacturer id survives even when the vendor is
    unknown. ``issues`` is populated by :func:`assess_ble_device`. Inputs are
    coerced defensively so a malformed advertisement can never raise.
    """
    company_id = next(iter(manufacturer_data), None)
    if isinstance(company_id, int):
        vendor = vendor_from_company_id(company_id)
        appearance = f"0x{company_id:04X}"
    else:
        vendor = ""
        appearance = ""

    try:
        rssi_value = int(rssi)
    except (TypeError, ValueError):
        rssi_value = 0

    device = BleDevice(
        address=str(address),
        name=str(name) if name else "",
        rssi=rssi_value,
        vendor=vendor,
        services=[str(uuid) for uuid in (service_uuids or [])],
        appearance=appearance,
    )
    device.issues = assess_ble_device(device)
    return device


async def scan_ble(duration: float = 10.0, adapter: str | None = None) -> list[BleDevice]:
    """Passively scan for advertising BLE devices for ``duration`` seconds.

    Listens for advertisement packets only — it never connects or pairs — and
    returns the observed devices, each already assessed. Requires the optional
    :mod:`bleak` backend and a Bluetooth adapter; when bleak is not installed, or
    the scan fails, it logs a clear warning and returns ``[]`` rather than
    raising, so callers can treat BLE as best-effort.

    ``adapter`` selects a specific host adapter (e.g. ``"hci0"`` on BlueZ) and is
    forwarded to bleak only when set.
    """
    try:
        from bleak import BleakScanner
    except ImportError:
        logger.warning(
            "ble_scan_unavailable",
            reason="bleak_not_installed",
            hint="pip install 'netsec-auditor[wireless]'",
        )
        return []

    kwargs: dict[str, object] = {"timeout": duration, "return_adv": True}
    if adapter is not None:
        kwargs["adapter"] = adapter

    try:
        discovered = await BleakScanner.discover(**kwargs)
    except Exception as exc:  # any backend/adapter error → degrade to empty result
        logger.warning("ble_scan_failed", error=str(exc))
        return []

    devices: list[BleDevice] = []
    for address, (adv_device, adv) in discovered.items():
        name = getattr(adv, "local_name", None) or getattr(adv_device, "name", None) or ""
        device = build_ble_device(
            address=str(address),
            name=name,
            rssi=getattr(adv, "rssi", 0),
            service_uuids=list(getattr(adv, "service_uuids", None) or []),
            manufacturer_data=dict(getattr(adv, "manufacturer_data", None) or {}),
        )
        devices.append(device)

    logger.info("ble_scan_complete", duration=duration, devices=len(devices))
    return devices
