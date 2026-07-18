"""Tests for the protocol probe framework contract."""

from __future__ import annotations

from netsec_auditor.protocols.base import ProbeResult, ProbeSpec, register


def test_probe_result_to_dict() -> None:
    r = ProbeResult(
        protocol="modbus",
        port=502,
        transport="tcp",
        is_ot=True,
        device_info={"vendor": "Acme"},
    )
    d = r.to_dict()
    assert d["protocol"] == "modbus"
    assert d["is_ot"] is True
    assert d["device_info"]["vendor"] == "Acme"


def test_register_indexes_by_port() -> None:
    async def _noop(host: str, port: int, timeout: float) -> ProbeResult | None:
        return None

    spec = ProbeSpec(
        name="unit-test-proto",
        default_port=65001,
        transport="tcp",
        is_ot=True,
        probe=_noop,
    )
    register([spec])

    from netsec_auditor.protocols.base import probers_for_port

    assert spec in probers_for_port(65001)
