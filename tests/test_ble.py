"""Unit tests for passive BLE recon.

Every test here is radio-free and bleak-free: the pure helpers
(:func:`build_ble_device`, :func:`vendor_from_company_id`) are exercised with
hand-built advertisement fields, and :func:`scan_ble` is driven through a fake
``bleak`` module injected into :data:`sys.modules`, so nothing touches a real
Bluetooth adapter or the network.
"""

from __future__ import annotations

import sys
import types

import pytest

from netsec_auditor.wireless.base import BleDevice, assess_ble_device
from netsec_auditor.wireless.ble import (
    build_ble_device,
    scan_ble,
    vendor_from_company_id,
)

_NO_SERVICES = "no advertised services"
_GENERIC_NAME = "Generic/default device name"


# vendor lookup


def test_vendor_from_company_id_known() -> None:
    assert vendor_from_company_id(0x0075) == "Samsung"
    assert vendor_from_company_id(0x004C) == "Apple"
    assert vendor_from_company_id(0x0006) == "Microsoft"
    assert vendor_from_company_id(0x00E0) == "Google"
    assert vendor_from_company_id(0x0059) == "Nordic Semiconductor"


def test_vendor_from_company_id_unknown_is_empty() -> None:
    assert vendor_from_company_id(0x1234) == ""
    assert vendor_from_company_id(0xFFFF) == ""


# build_ble_device


def test_build_ble_device_apple_vendor_and_appearance() -> None:
    # 0x02 0x15 ... is Apple's iBeacon manufacturer payload; only the company id
    # (the dict key 0x004C) drives the vendor mapping.
    device = build_ble_device(
        address="11:22:33:44:55:66",
        name="",
        rssi=-40,
        service_uuids=[],
        manufacturer_data={0x004C: b"\x02\x15" + b"\x00" * 21},
    )
    assert device.vendor == "Apple"
    assert device.appearance == "0x004C"


def test_build_ble_device_unknown_company_id_keeps_raw_id() -> None:
    device = build_ble_device(
        address="AA:BB:CC:DD:EE:FF",
        name="thing",
        rssi=-50,
        service_uuids=["svc"],
        manufacturer_data={0x1234: b"\x00"},
    )
    assert device.vendor == ""
    assert device.appearance == "0x1234"


def test_build_ble_device_without_manufacturer_data() -> None:
    device = build_ble_device("AA:BB:CC:DD:EE:FF", "thing", -50, ["svc"], {})
    assert device.vendor == ""
    assert device.appearance == ""


def test_build_ble_device_no_services_connectable_is_flagged() -> None:
    # A connectable device advertising no services should be flagged by the
    # assessment that build_ble_device runs.
    device = build_ble_device("AA:BB:CC:DD:EE:FF", "", -60, [], {})
    assert device.connectable is True
    assert device.issues
    assert any(_NO_SERVICES in issue for issue in device.issues)


def test_build_ble_device_with_services_not_flagged_for_services() -> None:
    device = build_ble_device(
        address="AA:BB:CC:DD:EE:FF",
        name="Battery Sensor",
        rssi=-55,
        service_uuids=["0000180f-0000-1000-8000-00805f9b34fb"],
        manufacturer_data={0x0059: b"\x01"},
    )
    assert device.vendor == "Nordic Semiconductor"
    assert all(_NO_SERVICES not in issue for issue in device.issues)


def test_build_ble_device_generic_name_is_flagged() -> None:
    # Has a service (so it is not flagged for missing services), isolating the
    # generic-name finding.
    device = build_ble_device(
        address="AA:BB:CC:DD:EE:FF",
        name="HP-Printer",
        rssi=-50,
        service_uuids=["0000180a-0000-1000-8000-00805f9b34fb"],
        manufacturer_data={},
    )
    assert any(_GENERIC_NAME in issue for issue in device.issues)


def test_build_ble_device_issues_match_direct_assessment() -> None:
    device = build_ble_device("AA:BB:CC:DD:EE:FF", "", -70, [], {})
    assert device.issues == assess_ble_device(device)


# assess_ble_device (base)


def test_assess_flags_connectable_without_services() -> None:
    device = BleDevice(address="AA:BB:CC:DD:EE:FF", connectable=True, services=[])
    assert any(_NO_SERVICES in issue for issue in assess_ble_device(device))


def test_assess_ignores_non_connectable_without_services() -> None:
    device = BleDevice(address="AA:BB:CC:DD:EE:FF", connectable=False, services=[])
    assert all(_NO_SERVICES not in issue for issue in assess_ble_device(device))


def test_assess_clean_device_has_no_issues() -> None:
    device = BleDevice(
        address="AA:BB:CC:DD:EE:FF",
        name="Acme Widget 9000",
        connectable=True,
        services=["0000180f-0000-1000-8000-00805f9b34fb"],
    )
    assert assess_ble_device(device) == []


def test_assess_flags_generic_name() -> None:
    device = BleDevice(
        address="AA:BB:CC:DD:EE:FF",
        name="Netgear-Router",
        connectable=True,
        services=["svc"],
    )
    assert any(_GENERIC_NAME in issue for issue in assess_ble_device(device))


# scan_ble (no radio)


class _FakeAdv:
    """Minimal stand-in for bleak's ``AdvertisementData``."""

    def __init__(
        self,
        local_name: str | None = None,
        rssi: int | None = 0,
        service_uuids: list[str] | None = None,
        manufacturer_data: dict[int, bytes] | None = None,
    ) -> None:
        self.local_name = local_name
        self.rssi = rssi
        self.service_uuids = service_uuids or []
        self.manufacturer_data = manufacturer_data or {}


class _FakeDev:
    """Minimal stand-in for bleak's ``BLEDevice``."""

    def __init__(self, name: str | None = None) -> None:
        self.name = name


def _install_fake_bleak(
    monkeypatch: pytest.MonkeyPatch,
    discovered: dict | None = None,
    error: Exception | None = None,
) -> dict:
    """Inject a fake ``bleak`` module; return the kwargs discover() was called with."""
    calls: dict = {}

    async def discover(**kwargs: object) -> dict:
        calls.update(kwargs)
        if error is not None:
            raise error
        return {} if discovered is None else discovered

    scanner = type("BleakScanner", (), {"discover": staticmethod(discover)})
    module = types.ModuleType("bleak")
    module.BleakScanner = scanner
    monkeypatch.setitem(sys.modules, "bleak", module)
    return calls


async def test_scan_ble_returns_empty_without_bleak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Setting the module to None makes ``from bleak import ...`` raise ImportError.
    monkeypatch.setitem(sys.modules, "bleak", None)
    assert await scan_ble(duration=0.1) == []


async def test_scan_ble_returns_empty_on_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_bleak(monkeypatch, error=RuntimeError("no adapter"))
    assert await scan_ble(duration=0.1) == []


async def test_scan_ble_builds_and_assesses_devices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adv = _FakeAdv(
        local_name="Sensor",
        rssi=-55,
        service_uuids=["0000180f-0000-1000-8000-00805f9b34fb"],
        manufacturer_data={0x0059: b"\x01"},
    )
    discovered = {"AA:BB:CC:DD:EE:FF": (_FakeDev("Sensor"), adv)}
    _install_fake_bleak(monkeypatch, discovered=discovered)

    result = await scan_ble(duration=0.1)

    assert len(result) == 1
    device = result[0]
    assert device.address == "AA:BB:CC:DD:EE:FF"
    assert device.name == "Sensor"
    assert device.rssi == -55
    assert device.vendor == "Nordic Semiconductor"
    assert device.services == ["0000180f-0000-1000-8000-00805f9b34fb"]
    assert all(_NO_SERVICES not in issue for issue in device.issues)


async def test_scan_ble_falls_back_to_device_name_and_zero_rssi(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No advertised local_name and a None rssi: name falls back to the device
    # name and rssi coerces to 0.
    adv = _FakeAdv(local_name=None, rssi=None, service_uuids=[], manufacturer_data={})
    discovered = {"11:22:33:44:55:66": (_FakeDev("Fallback"), adv)}
    _install_fake_bleak(monkeypatch, discovered=discovered)

    result = await scan_ble(duration=0.1)

    assert len(result) == 1
    assert result[0].name == "Fallback"
    assert result[0].rssi == 0
    # Connectable (default) with no services → flagged.
    assert any(_NO_SERVICES in issue for issue in result[0].issues)


async def test_scan_ble_forwards_adapter_and_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_fake_bleak(monkeypatch, discovered={})
    await scan_ble(duration=2.0, adapter="hci0")
    assert calls["timeout"] == 2.0
    assert calls["return_adv"] is True
    assert calls["adapter"] == "hci0"


async def test_scan_ble_omits_adapter_when_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_fake_bleak(monkeypatch, discovered={})
    await scan_ble(duration=1.0)
    assert "adapter" not in calls
