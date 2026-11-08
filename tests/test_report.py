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


def test_html_report_lists_web_findings_certificate_issues_and_device_hosts(tmp_path) -> None:
    # The summary cards count web findings, so the body must show what they are.
    from netsec_auditor.protocols.base import ProbeResult
    from netsec_auditor.web.scanner import SSLCertificate

    finding = _web_finding()
    finding.name = "Missing security header: <Strict-Transport-Security>"
    web = WebScanResult(
        url="https://example.test",
        vulnerabilities=[finding],
        ssl_certificate=SSLCertificate(issues=["Self-signed certificate"]),
    )
    device = ProbeResult(protocol="modbus", port=502, transport="tcp", is_ot=True)
    device.extra["host"] = "10.0.0.7"

    paths = ReportGenerator(tmp_path / "reports").generate_all(
        web_results=[web], identified_services=[device], formats={"html"}
    )
    html = paths["html"].read_text(encoding="utf-8")

    assert "Missing security header: &lt;Strict-Transport-Security&gt;" in html
    assert "Self-signed certificate" in html
    assert "<td>10.0.0.7</td>" in html


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


def test_existing_output_directory_keeps_its_permissions(tmp_path) -> None:
    # Restricting a shared directory such as /tmp (1777) would break it for everyone.
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o1777)

    paths = ReportGenerator(shared).generate_all(formats={"json"})

    assert stat.S_IMODE(shared.stat().st_mode) == 0o1777
    assert stat.S_IMODE(paths["json"].stat().st_mode) == 0o600


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
        "bssid": "00:1a:2b:dd:ee:ff",
        "ssid": "CafeWiFi",
        "clients": ["11:22:33:44:55:66"],
        "latitude": 59.913868,
        "longitude": 10.752245,
    }
    out = ReportGenerator._redact_wireless(entry)
    assert out["bssid"] == "00:1a:2b:xx:xx:xx"
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
            return {"bssid": "00:1a:2b:dd:ee:ff", "clients": [], "latitude": None}

    gen = ReportGenerator(output_dir=tmp_path / "r")
    plain = gen.build_report(wireless=_Inventory())
    assert plain.access_points[0]["bssid"] == "00:1a:2b:dd:ee:ff"
    masked = gen.build_report(wireless=_Inventory(), redact_wireless=True)
    assert masked.access_points[0]["bssid"] == "00:1a:2b:xx:xx:xx"


def test_randomized_mac_is_masked_whole() -> None:
    # A locally administered address carries random bits, not a vendor OUI.
    from netsec_auditor.report.generator import mask_mac

    assert mask_mac("DA:A1:19:12:34:56") == "xx:xx:xx:xx:xx:xx"
    assert mask_mac("00-1A-2B-12-34-56") == "00:1A:2B:xx:xx:xx"
    assert mask_mac("not-a-mac") == "[REDACTED]"
