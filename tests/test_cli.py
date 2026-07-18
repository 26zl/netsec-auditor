"""Tests for CLI helpers."""

from __future__ import annotations

import stat

import pytest
import typer

from netsec_auditor.cli import _write_scope_file
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
