"""Tests for safe local file writes."""

from __future__ import annotations

import json
import os

from netsec_auditor.utils.files import write_json_atomic


def test_atomic_write_replaces_planted_links_instead_of_writing_through(tmp_path) -> None:
    # Under sudo a cache path in the user's home could be a link to a system file.
    victim = tmp_path / "victim.txt"
    victim.write_text("original", encoding="utf-8")
    symlinked = tmp_path / "symlinked.json"
    symlinked.symlink_to(victim)
    hardlinked = tmp_path / "hardlinked.json"
    os.link(victim, hardlinked)

    write_json_atomic(symlinked, {"ok": True})
    write_json_atomic(hardlinked, [1])

    assert victim.read_text(encoding="utf-8") == "original"
    assert not symlinked.is_symlink()
    assert json.loads(symlinked.read_text(encoding="utf-8")) == {"ok": True}
    assert json.loads(hardlinked.read_text(encoding="utf-8")) == [1]
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
