"""Tests for CLI helpers."""

from __future__ import annotations

import stat

import pytest
import typer
import yaml
from typer.testing import CliRunner

from netsec_auditor.cli import _write_scope_file, app
from netsec_auditor.scanner.scope import Scope


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
