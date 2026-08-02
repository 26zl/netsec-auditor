"""Report generation — JSON, HTML, and PDF security audit reports."""

from __future__ import annotations

import importlib.resources
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, TextIO
from urllib.parse import urlparse

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
        # Keep the report directory private (0700) whether or not it already existed:
        # reports hold sensitive findings and their filenames leak scan targets.
        try:
            self.output_dir.chmod(0o700)
        except OSError as exc:
            logger.warning("report_dir_chmod_failed", path=str(self.output_dir), error=str(exc))

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
        redact_wireless: bool = False,
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
            report.vulnerabilities = [self._finding_to_dict(v.to_dict()) for v in all_vulns]
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
                    "vulnerabilities": [
                        self._finding_to_dict(v.to_dict()) for v in w.vulnerabilities
                    ],
                }
                for w in web_results
            ]

            for web in web_results:
                report.total_vulnerabilities += len(web.vulnerabilities)
                report.overall_risk_score += web.risk_score
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
            access_points = [ap.to_dict() for ap in wireless.aps()]
            ble_devices = [d.to_dict() for d in wireless.ble()]
            if redact_wireless:
                access_points = [self._redact_wireless(a) for a in access_points]
                ble_devices = [self._redact_wireless(d) for d in ble_devices]
            report.access_points = access_points
            report.ble_devices = ble_devices

        if cve_priorities:
            report.cve_priorities = cve_priorities

        report.risk_level = self._calculate_risk_level(report)
        return report

    def generate_json(self, report: AuditReport, filename: str | None = None) -> Path:
        """Generate a JSON report."""
        filename = filename or f"audit-report-{self._filename_timestamp()}.json"
        output_path = self._output_path(filename)

        data = report.to_dict()
        if report.raw_scan_result:
            data["raw_scan_result"] = report.raw_scan_result
        if report.raw_vuln_results:
            data["raw_vuln_results"] = report.raw_vuln_results
        if report.raw_web_results:
            data["raw_web_results"] = report.raw_web_results

        with self._open_private_text(output_path) as f:
            json.dump(data, f, indent=2, default=str)

        logger.info("json_report_generated", path=str(output_path))
        return output_path

    def generate_html(self, report: AuditReport, filename: str | None = None) -> Path:
        """Generate an HTML report."""
        filename = filename or f"audit-report-{self._filename_timestamp()}.html"
        output_path = self._output_path(filename)

        env = Environment(autoescape=select_autoescape(["html", "xml"]))
        template = env.from_string(HTML_TEMPLATE)
        html = template.render(report=report)

        with self._open_private_text(output_path) as f:
            f.write(html)

        logger.info("html_report_generated", path=str(output_path))
        return output_path

    def generate_pdf(self, report: AuditReport, filename: str | None = None) -> Path | None:
        """Generate a PDF report (requires weasyprint)."""
        try:
            from weasyprint import HTML
        except (ImportError, OSError) as exc:
            logger.warning(
                "pdf_backend_unavailable",
                error=str(exc),
                hint="install the PDF extra and the required Pango/HarfBuzz system libraries",
            )
            return None

        filename = filename or f"audit-report-{self._filename_timestamp()}.pdf"
        output_path = self._output_path(filename)

        env = Environment(autoescape=select_autoescape(["html", "xml"]))
        template = env.from_string(HTML_TEMPLATE)
        html = template.render(report=report)

        try:
            pdf = HTML(string=html).write_pdf()
        except OSError as exc:
            logger.warning("pdf_generation_unavailable", error=str(exc))
            return None
        with self._open_private_binary(output_path) as f:
            f.write(pdf)

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
        formats: set[str] | None = None,
        redact_wireless: bool = False,
    ) -> dict[str, Path]:
        """Generate all report formats."""
        selected = formats if formats is not None else {"json", "html", "pdf"}
        unknown = selected - {"json", "html", "pdf"}
        if unknown:
            raise ValueError(f"Unsupported report formats: {', '.join(sorted(unknown))}")
        report = self.build_report(
            scan_result, vuln_results, web_results, title, scope_name,
            identified_services=identified_services,
            wireless=wireless,
            cve_priorities=cve_priorities,
            redact_wireless=redact_wireless,
        )

        paths: dict[str, Path] = {}
        timestamp = self._filename_timestamp()
        if "json" in selected:
            paths["json"] = self.generate_json(report, f"audit-report-{timestamp}.json")
        if "html" in selected:
            paths["html"] = self.generate_html(report, f"audit-report-{timestamp}.html")

        if "pdf" in selected:
            pdf_path = self.generate_pdf(report, f"audit-report-{timestamp}.pdf")
            if pdf_path:
                paths["pdf"] = pdf_path

        return paths

    def _output_path(self, filename: str) -> Path:
        """Resolve a report filename without permitting directory traversal."""
        candidate = Path(filename)
        if candidate.name != filename or filename in {"", ".", ".."}:
            raise ValueError("Report filename must be a plain filename")
        return self.output_dir / candidate

    @staticmethod
    def _filename_timestamp() -> str:
        """UTC, matching the report's ``generated_at`` field."""
        return datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")

    @staticmethod
    def _private_fd(path: Path) -> int:
        """Create a new report with owner-only permissions and no symlink following."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        return os.open(path, flags, 0o600)

    @classmethod
    def _open_private_text(cls, path: Path) -> TextIO:
        return os.fdopen(cls._private_fd(path), "w", encoding="utf-8")

    @classmethod
    def _open_private_binary(cls, path: Path) -> BinaryIO:
        return os.fdopen(cls._private_fd(path), "wb")

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
            "reachable": web.reachable,
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
            "vulnerabilities": [
                ReportGenerator._finding_to_dict(v.to_dict()) for v in web.vulnerabilities
            ],
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

    @staticmethod
    def _mask_mac(value: str) -> str:
        """Keep only the vendor OUI of a MAC, so the device is not re-identifiable."""
        parts = value.split(":")
        if len(parts) != 6:
            return "[REDACTED]"
        return ":".join(parts[:3] + ["xx"] * 3)

    @classmethod
    def _redact_wireless(cls, entry: dict[str, Any]) -> dict[str, Any]:
        """Strip third-party identifiers from a wireless record.

        A wardrive or Wi-Fi capture catalogs bystanders' networks and devices, so
        reports keep the vendor OUI and a coarse location rather than the exact
        hardware address and coordinates.
        """
        redacted = dict(entry)
        for key in ("bssid", "address"):
            value = redacted.get(key)
            if isinstance(value, str) and value:
                redacted[key] = cls._mask_mac(value)
        clients = redacted.get("clients")
        if isinstance(clients, list):
            redacted["clients"] = [
                cls._mask_mac(c) for c in clients if isinstance(c, str)
            ]
        for key in ("latitude", "longitude"):
            value = redacted.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                redacted[key] = round(float(value), 2)  # ~1 km
        return redacted

    @staticmethod
    def _finding_to_dict(finding: dict[str, Any]) -> dict[str, Any]:
        """Keep only HTTP(S) reference links in generated reports."""
        sanitized = dict(finding)
        references = finding.get("references", [])
        sanitized["references"] = [
            ref
            for ref in references
            if isinstance(ref, str) and urlparse(ref).scheme.lower() in {"http", "https"}
        ]
        return sanitized
