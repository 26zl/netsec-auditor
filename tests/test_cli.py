"""Tests for CLI helpers."""

from __future__ import annotations

import stat
from unittest.mock import AsyncMock

import pytest
import typer
import yaml
from typer.testing import CliRunner

from netsec_auditor.cli import _scan_web_targets, _write_scope_file, app
from netsec_auditor.scanner.scope import Scope, ScopeError
from netsec_auditor.web.scanner import WebScanResult


def _scope() -> Scope:
    return Scope(name="team", cidr_ranges=["10.0.0.0/24"])


def test_write_scope_file_is_private(tmp_path) -> None:
    path = tmp_path / "team-scope.yaml"
    _write_scope_file(_scope(), path)
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_write_scope_file_refuses_to_overwrite(tmp_path) -> None:
    path = tmp_path / "team-scope.yaml"
    _write_scope_file(_scope(), path)
    with pytest.raises(typer.BadParameter):
        _write_scope_file(_scope(), path)


def test_write_scope_file_refuses_symlink(tmp_path) -> None:
    target = tmp_path / "secret.yaml"
    link = tmp_path / "link-scope.yaml"
    link.symlink_to(target)
    with pytest.raises(typer.BadParameter):
        _write_scope_file(_scope(), link)
    # O_NOFOLLOW means the symlink target is never created through the link.
    assert not target.exists()


def _scope_file(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text(
        yaml.safe_dump({
            "name": "t",
            "cidr_ranges": ["10.0.0.0/24"],
            "excluded_ip_addresses": ["10.0.0.9"],
        }),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    ("args", "expected_code"),
    [
        (["--target", "10.0.0.5"], 0),
        (["--target", "8.8.8.8"], 1),
        (["--target", "10.0.0.9"], 1),
    ],
)
def test_scope_validate_exit_code_reflects_authorization(
    tmp_path, args: list[str], expected_code: int
) -> None:
    # Callers gate scans on this exit code, so a rejected target must not exit 0.
    result = CliRunner().invoke(
        app, ["scope", "validate", "--file", str(_scope_file(tmp_path)), *args]
    )
    assert result.exit_code == expected_code


def test_scope_unknown_action_exits_non_zero(tmp_path) -> None:
    result = CliRunner().invoke(
        app, ["scope", "nonsense", "--file", str(_scope_file(tmp_path))]
    )
    assert result.exit_code == 1


def test_display_escapes_attacker_controlled_names(capsys) -> None:
    # An SSID or device name is broadcast by an untrusted radio; rich would
    # otherwise read "[link=...]" as markup and render a live terminal hyperlink.
    from netsec_auditor.cli import _display_ble, _display_wifi
    from netsec_auditor.wireless.base import AccessPoint, BleDevice, WirelessInventory

    inventory = WirelessInventory()
    inventory.add_ap(
        AccessPoint(bssid="AA:BB:CC:DD:EE:FF", ssid="[link=file:///etc/passwd]x[/link]")
    )
    inventory.add_ble(BleDevice(address="00:11:22:33:44:55", name="[blink]y[/blink]"))

    _display_wifi(inventory)
    _display_ble(inventory)
    out = capsys.readouterr().out

    assert "[link=" in out or "[link…" in out or "[link" in out
    assert "[blink]y[/blink]" in out


def test_web_reports_when_no_targets_could_be_audited() -> None:
    # An unusable target (invalid port) must not exit silently with just a banner.
    result = CliRunner().invoke(app, ["web", "http://127.0.0.1:99999"])
    assert result.exit_code == 0
    assert "No web interfaces could be audited" in result.output


@pytest.mark.parametrize(
    ("target", "outcomes", "expected_urls", "expected_index"),
    [
        ("device.example.test", [True], ["https://device.example.test"], 0),
        (
            "device.example.test", [False, True],
            ["https://device.example.test", "http://device.example.test"], 1,
        ),
        (
            "https://device.example.test", [False],
            ["https://device.example.test"], 0,
        ),
        ("http://device.example.test", [False], ["http://device.example.test"], 0),
        (
            "device.example.test", [False, False],
            ["https://device.example.test", "http://device.example.test"], 1,
        ),
        (
            "device.example.test", [ScopeError("Out of scope"), True],
            ["https://device.example.test", "http://device.example.test"], 1,
        ),
        (
            "device.example.test", [False, ScopeError("Out of scope")],
            ["https://device.example.test", "http://device.example.test"], 0,
        ),
        (
            "device.example.test", [ScopeError("Out of scope"), ScopeError("Out of scope")],
            ["https://device.example.test", "http://device.example.test"], None,
        ),
        (
            "https://device.example.test", [ScopeError("Out of scope")],
            ["https://device.example.test"], None,
        ),
    ],
)
async def test_web_protocol_fallback(target, outcomes, expected_urls, expected_index) -> None:
    responses = [
        outcome if isinstance(outcome, Exception) else WebScanResult(url=url, reachable=outcome)
        for url, outcome in zip(expected_urls, outcomes, strict=True)
    ]
    scanner = AsyncMock()
    scanner.scan.side_effect = responses

    results = await _scan_web_targets(scanner, [target], deep=True, concurrency=1)

    expected = [] if expected_index is None else [responses[expected_index]]
    assert results == expected
    assert [call.args[0] for call in scanner.scan.await_args_list] == expected_urls
    assert all(call.kwargs == {"deep": True} for call in scanner.scan.await_args_list)


def test_full_rejects_invalid_scan_type() -> None:
    result = CliRunner().invoke(app, ["full", "127.0.0.1", "--scan-type", "bogus"])
    assert result.exit_code != 0


def test_full_accepts_scan_type_option() -> None:
    # The option must exist so an unprivileged user can request a connect scan.
    # Introspect the command rather than parse --help, whose width-dependent
    # wrapping splits the option name under CI's narrow terminal.
    import typer

    command = typer.main.get_command(app).commands["full"]  # type: ignore[attr-defined]
    option_names = {name for param in command.params for name in param.opts}
    assert "--scan-type" in option_names


def test_weasyprint_status_reflects_native_library(monkeypatch) -> None:
    # doctor must report weasyprint unusable when the GObject/Pango libs are
    # missing, not merely because the Python module is importable.
    from netsec_auditor import cli

    monkeypatch.setattr("ctypes.util.find_library", lambda _name: None)
    ok, detail, _ = cli._weasyprint_status()
    assert ok is None
    assert "Pango" in detail

    monkeypatch.setattr("ctypes.util.find_library", lambda _name: "/usr/lib/libgobject-2.0.so")
    ok, detail, _ = cli._weasyprint_status()
    assert ok is True
    assert detail == "available"
