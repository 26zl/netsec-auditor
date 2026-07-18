"""Report generation — JSON, HTML, and PDF security audit reports."""

from __future__ import annotations

import importlib.resources
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape

from netsec_auditor.scanner.engine import HostResult, ScanResult
from netsec_auditor.utils.logging import get_logger
from netsec_auditor.vuln.detector import Vulnerability, VulnScanResult
from netsec_auditor.web.scanner import WebScanResult

logger = get_logger(__name__)

HTML_TEMPLATE = (
    importlib.resources.files("netsec_auditor.data")
    .joinpath("report-template.html")
    .read_text(encoding="utf-8")
)


@dataclass
class ReportSummary:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


@dataclass
class AuditReport:
    title: str
    scope_name: str = ""
    generated_at: str = ""
    scan_duration: str = ""
    total_hosts: int = 0
    hosts_up: int = 0
    total_vulnerabilities: int = 0
    overall_risk_score: float = 0.0
    risk_level: str = "Unknown"
    summary: ReportSummary = field(default_factory=ReportSummary)
    hosts: list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    web_results: list[dict[str, Any]] = field(default_factory=list)
    devices: list[dict[str, Any]] = field(default_factory=list)
    access_points: list[dict[str, Any]] = field(default_factory=list)
    ble_devices: list[dict[str, Any]] = field(default_factory=list)
    cve_priorities: list[dict[str, Any]] = field(default_factory=list)
    raw_scan_result: dict[str, Any] | None = None
    raw_vuln_results: list[dict[str, Any]] | None = None
    raw_web_results: list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "scope_name": self.scope_name,
            "generated_at": self.generated_at,
            "scan_duration": self.scan_duration,
            "total_hosts": self.total_hosts,
            "hosts_up": self.hosts_up,
            "total_vulnerabilities": self.total_vulnerabilities,
            "overall_risk_score": self.overall_risk_score,
            "risk_level": self.risk_level,
            "summary": {
                "critical": self.summary.critical,
                "high": self.summary.high,
                "medium": self.summary.medium,
                "low": self.summary.low,
                "info": self.summary.info,
            },
            "hosts": self.hosts,
            "vulnerabilities": self.vulnerabilities,
            "web_results": self.web_results,
            "devices": self.devices,
            "access_points": self.access_points,
            "ble_devices": self.ble_devices,
            "cve_priorities": self.cve_priorities,
        }


class ReportGenerator:
    """Generates security audit reports in JSON, HTML, and PDF formats."""

    def __init__(self, output_dir: Path | None = None) -> None:
        self.output_dir = output_dir or Path("reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def build_report(
        self,
        scan_result: ScanResult | None = None,
        vuln_results: list[VulnScanResult] | None = None,
        web_results: list[WebScanResult] | None = None,
        title: str = "Security Audit Report",
        scope_name: str = "",
        identified_services: list[Any] | None = None,
        wireless: Any | None = None,
        cve_priorities: list[dict[str, Any]] | None = None,
    ) -> AuditReport:
        """Build a comprehensive audit report from scan and recon results."""
        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

        report = AuditReport(
            title=title,
            scope_name=scope_name,
            generated_at=now,
        )

        if scan_result:
            report.scan_duration = f"{scan_result.duration:.1f}s"
            report.total_hosts = scan_result.total_hosts
            report.hosts_up = scan_result.hosts_up
            report.hosts = [self._host_to_dict(h) for h in scan_result.hosts]
            report.raw_scan_result = {
                "scan_type": scan_result.scan_type,
                "start_time": scan_result.start_time,
                "end_time": scan_result.end_time,
                "total_hosts": scan_result.total_hosts,
                "hosts_up": scan_result.hosts_up,
                "hosts_down": scan_result.hosts_down,
            }

        if vuln_results:
            all_vulns: list[Vulnerability] = []
            for vr in vuln_results:
                all_vulns.extend(vr.vulnerabilities)
                report.overall_risk_score += vr.risk_score

            report.total_vulnerabilities = len(all_vulns)
            report.vulnerabilities = [v.to_dict() for v in all_vulns]
            report.raw_vuln_results = [
                {
                    "host": vr.host,
                    "risk_score": vr.risk_score,
                    "critical_count": vr.critical_count,
                    "high_count": vr.high_count,
                    "medium_count": vr.medium_count,
                    "low_count": vr.low_count,
                    "info_count": vr.info_count,
                }
                for vr in vuln_results
            ]

            for vuln in all_vulns:
                match vuln.severity.value:
                    case "critical":
                        report.summary.critical += 1
                    case "high":
                        report.summary.high += 1
                    case "medium":
                        report.summary.medium += 1
                    case "low":
                        report.summary.low += 1
                    case "info":
                        report.summary.info += 1

        if web_results:
            report.web_results = [self._web_to_dict(w) for w in web_results]
            report.raw_web_results = [
                {
                    "url": w.url,
                    "risk_score": w.risk_score,
                    "vulnerabilities": [v.to_dict() for v in w.vulnerabilities],
                }
                for w in web_results
            ]

            for web in web_results:
                for vuln in web.vulnerabilities:
                    match vuln.severity:
                        case "critical":
                            report.summary.critical += 1
                        case "high":
                            report.summary.high += 1
                        case "medium":
                            report.summary.medium += 1
                        case "low":
                            report.summary.low += 1
                        case "info":
                            report.summary.info += 1

        if identified_services:
            report.devices = [s.to_dict() for s in identified_services]

        if wireless is not None:
            report.access_points = [ap.to_dict() for ap in wireless.aps()]
            report.ble_devices = [d.to_dict() for d in wireless.ble()]

        if cve_priorities:
            report.cve_priorities = cve_priorities

        report.risk_level = self._calculate_risk_level(report)
        return report

    def generate_json(self, report: AuditReport, filename: str | None = None) -> Path:
        """Generate a JSON report."""
        filename = filename or f"audit-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        output_path = self.output_dir / filename

        data = report.to_dict()
        if report.raw_scan_result:
            data["raw_scan_result"] = report.raw_scan_result
        if report.raw_vuln_results:
            data["raw_vuln_results"] = report.raw_vuln_results
        if report.raw_web_results:
            data["raw_web_results"] = report.raw_web_results

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info("json_report_generated", path=str(output_path))
        return output_path

    def generate_html(self, report: AuditReport, filename: str | None = None) -> Path:
        """Generate an HTML report."""
        filename = filename or f"audit-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
        output_path = self.output_dir / filename

        env = Environment(autoescape=select_autoescape(["html", "xml"]))
        template = env.from_string(HTML_TEMPLATE)
        html = template.render(report=report)

        with open(output_path, "w") as f:
            f.write(html)

        logger.info("html_report_generated", path=str(output_path))
        return output_path

    def generate_pdf(self, report: AuditReport, filename: str | None = None) -> Path | None:
        """Generate a PDF report (requires weasyprint)."""
        try:
            from weasyprint import HTML
        except ImportError:
            logger.error("weasyprint_not_installed", hint="pip install weasyprint")
            return None

        filename = filename or f"audit-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
        output_path = self.output_dir / filename

        env = Environment(autoescape=select_autoescape(["html", "xml"]))
        template = env.from_string(HTML_TEMPLATE)
        html = template.render(report=report)

        HTML(string=html).write_pdf(str(output_path))

        logger.info("pdf_report_generated", path=str(output_path))
        return output_path

    def generate_all(
        self,
        scan_result: ScanResult | None = None,
        vuln_results: list[VulnScanResult] | None = None,
        web_results: list[WebScanResult] | None = None,
        title: str = "Security Audit Report",
        scope_name: str = "",
        identified_services: list[Any] | None = None,
        wireless: Any | None = None,
        cve_priorities: list[dict[str, Any]] | None = None,
    ) -> dict[str, Path]:
        """Generate all report formats."""
        report = self.build_report(
            scan_result, vuln_results, web_results, title, scope_name,
            identified_services=identified_services,
            wireless=wireless,
            cve_priorities=cve_priorities,
        )

        paths: dict[str, Path] = {}
        paths["json"] = self.generate_json(report)
        paths["html"] = self.generate_html(report)

        pdf_path = self.generate_pdf(report)
        if pdf_path:
            paths["pdf"] = pdf_path

        return paths

    @staticmethod
    def _host_to_dict(host: HostResult) -> dict[str, Any]:
        return {
            "ip": host.ip,
            "hostname": host.hostname,
            "mac": host.mac,
            "vendor": host.vendor,
            "os": host.os,
            "os_accuracy": host.os_accuracy,
            "os_family": host.os_family,
            "status": host.status,
            "scan_duration": host.scan_duration,
            "open_ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state.value,
                    "service": {
                        "name": p.service.name,
                        "product": p.service.product,
                        "version": p.service.version,
                    }
                    if p.service
                    else None,
                    "banner": p.banner,
                }
                for p in host.open_ports
            ],
        }

    @staticmethod
    def _web_to_dict(web: WebScanResult) -> dict[str, Any]:
        return {
            "url": web.url,
            "ip": web.ip,
            "server": web.server,
            "technologies": web.technologies,
            "headers": web.headers,
            "ssl_certificate": {
                "subject": web.ssl_certificate.subject,
                "issuer": web.ssl_certificate.issuer,
                "is_expired": web.ssl_certificate.is_expired,
                "is_self_signed": web.ssl_certificate.is_self_signed,
                "days_until_expiry": web.ssl_certificate.days_until_expiry,
                "issues": web.ssl_certificate.issues,
            }
            if web.ssl_certificate
            else None,
            "vulnerabilities": [v.to_dict() for v in web.vulnerabilities],
            "discovered_directories": web.discovered_directories,
            "discovered_urls": web.discovered_urls,
            "forms": web.forms,
            "scan_duration": web.scan_duration,
        }

    @staticmethod
    def _calculate_risk_level(report: AuditReport) -> str:
        if report.summary.critical > 0:
            return "CRITICAL"
        if report.summary.high > 3:
            return "HIGH"
        if report.summary.high > 0 or report.summary.medium > 5:
            return "MEDIUM"
        if report.summary.medium > 0 or report.summary.low > 3:
            return "LOW"
        return "INFORMATIONAL"
