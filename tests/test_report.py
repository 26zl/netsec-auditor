"""Tests for report accounting and confidential file output."""

from __future__ import annotations

import builtins
import stat

import pytest

from netsec_auditor.report.generator import ReportGenerator
from netsec_auditor.web.scanner import WebScanResult, WebVulnerability


def _web_finding() -> WebVulnerability:
    return WebVulnerability(
        id="WEB-1",
        name="Example",
        description="Example finding",
        severity="high",
        category="test",
        url="https://example.test",
    )


def test_web_findings_are_included_in_report_totals(tmp_path) -> None:
    generator = ReportGenerator(tmp_path / "reports")
    web = WebScanResult(url="https://example.test", vulnerabilities=[_web_finding()])

    report = generator.build_report(web_results=[web])

    assert report.total_vulnerabilities == 1
    assert report.overall_risk_score == 7
    assert report.summary.high == 1


def test_report_drops_active_non_http_reference_links(tmp_path) -> None:
    generator = ReportGenerator(tmp_path / "reports")
    finding = _web_finding()
    finding.references = ["javascript:alert(1)", "https://example.test/advisory"]

    report = generator.build_report(
        web_results=[WebScanResult(url="https://example.test", vulnerabilities=[finding])]
    )

    assert report.web_results[0]["vulnerabilities"][0]["references"] == [
        "https://example.test/advisory"
    ]


def test_report_output_is_private_and_format_selection_is_honored(tmp_path) -> None:
    generator = ReportGenerator(tmp_path / "reports")
    paths = generator.generate_all(formats={"json"})

    assert set(paths) == {"json"}
    assert stat.S_IMODE(paths["json"].stat().st_mode) == 0o600
    assert stat.S_IMODE(generator.output_dir.stat().st_mode) == 0o700


def test_report_filename_cannot_escape_output_directory(tmp_path) -> None:
    generator = ReportGenerator(tmp_path / "reports")
    report = generator.build_report()

    with pytest.raises(ValueError, match="plain filename"):
        generator.generate_json(report, "../outside.json")


def test_missing_native_pdf_backend_degrades_cleanly(tmp_path, monkeypatch) -> None:
    generator = ReportGenerator(tmp_path / "reports")
    report = generator.build_report()
    real_import = builtins.__import__

    def fail_weasyprint(name, *args, **kwargs):
        if name == "weasyprint":
            raise OSError("native PDF backend unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_weasyprint)

    assert generator.generate_pdf(report) is None


def test_wireless_redaction_masks_third_party_identifiers() -> None:
    entry = {
        "bssid": "aa:bb:cc:dd:ee:ff",
        "ssid": "CafeWiFi",
        "clients": ["11:22:33:44:55:66"],
        "latitude": 59.913868,
        "longitude": 10.752245,
    }
    out = ReportGenerator._redact_wireless(entry)
    assert out["bssid"] == "aa:bb:cc:xx:xx:xx"
    assert out["clients"] == ["11:22:33:xx:xx:xx"]
    assert out["latitude"] == 59.91
    assert out["longitude"] == 10.75
    assert out["ssid"] == "CafeWiFi"  # SSID is the audit subject, not an identifier


def test_wireless_redaction_is_opt_in(tmp_path) -> None:
    class _Inventory:
        @staticmethod
        def aps():
            return [_Ap()]

        @staticmethod
        def ble():
            return []

    class _Ap:
        @staticmethod
        def to_dict():
            return {"bssid": "aa:bb:cc:dd:ee:ff", "clients": [], "latitude": None}

    gen = ReportGenerator(output_dir=tmp_path / "r")
    plain = gen.build_report(wireless=_Inventory())
    assert plain.access_points[0]["bssid"] == "aa:bb:cc:dd:ee:ff"
    masked = gen.build_report(wireless=_Inventory(), redact_wireless=True)
    assert masked.access_points[0]["bssid"] == "aa:bb:cc:xx:xx:xx"
