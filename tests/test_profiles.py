"""Tests for environment profiles and the OT safety interlock."""

from __future__ import annotations

import pytest

from netsec_auditor.profiles import (
    IOT,
    IT,
    OT,
    apply_interlock,
    classify_ports,
    get_profile,
)


def test_classify_ports() -> None:
    assert classify_ports({80, 443}) == "it"
    assert classify_ports({502, 80}) == "ot"      # OT takes precedence
    assert classify_ports({1883, 80}) == "iot"
    assert classify_ports({502, 1883}) == "ot"    # OT beats IoT


def test_get_profile_resolves_known_names() -> None:
    assert get_profile("ot") is OT
    assert get_profile("iot") is IOT
    assert get_profile("it") is IT


def test_get_profile_rejects_unknown_name() -> None:
    # Failing open to IT would run an aggressive scan against a network the
    # operator asked to treat as fragile.
    with pytest.raises(ValueError, match="unknown profile"):
        get_profile("ot-safe")


def test_ot_interlock_downgrades() -> None:
    # An IT scan that touches an OT port auto-downgrades to the gentle OT profile.
    assert apply_interlock(IT, {502}, forced=False) is OT
    # An operator who forced a profile opts out of the automatic downgrade.
    assert apply_interlock(IT, {502}, forced=True) is IT
    assert apply_interlock(IT, {1883}, forced=False) is IOT
    assert apply_interlock(OT, {502}, forced=False) is OT
    assert apply_interlock(IT, {80, 443}, forced=False) is IT


def test_ot_profile_is_gentle() -> None:
    assert OT.max_concurrency == 1
    assert OT.scan_delay > 0
    assert OT.allow_intrusive is False
    assert OT.allow_os_detection is False
