"""Vulnerability detection engine — CVE matching, misconfiguration checks, and risk scoring."""

from __future__ import annotations

import asyncio
import importlib.resources
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import httpx
import yaml

from netsec_auditor.scanner.engine import HostResult, ServiceInfo
from netsec_auditor.utils.hashing import short_id
from netsec_auditor.utils.logging import get_logger

logger = get_logger(__name__)


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def to_score(self) -> float:
        return {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.0,
        }[self]

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score >= 0.1:
            return cls.LOW
        return cls.INFO


class VulnCategory(Enum):
    CVE = "cve"
    MISCONFIGURATION = "misconfiguration"
    WEAK_CREDENTIAL = "weak_credential"
    OUTDATED_SOFTWARE = "outdated_software"
    MISSING_PATCH = "missing_patch"
    INSECURE_PROTOCOL = "insecure_protocol"
    EXPOSED_SERVICE = "exposed_service"
    CERTIFICATE = "certificate"
    INFORMATION_DISCLOSURE = "information_disclosure"


@dataclass
class Vulnerability:
    id: str
    name: str
    description: str
    severity: Severity
    category: VulnCategory
    cvss_score: float = 0.0
    cve_id: str = ""
    affected_host: str = ""
    affected_port: int = 0
    affected_service: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cvss_vector: str = ""
    exploit_available: bool = False
    metasploit_module: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "affected_host": self.affected_host,
            "affected_port": self.affected_port,
            "affected_service": self.affected_service,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "cvss_vector": self.cvss_vector,
            "exploit_available": self.exploit_available,
            "metasploit_module": self.metasploit_module,
        }


@dataclass
class VulnScanResult:
    host: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    risk_score: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        self.vulnerabilities.append(vuln)
        self.risk_score += vuln.severity.to_score()
        match vuln.severity:
            case Severity.CRITICAL:
                self.critical_count += 1
            case Severity.HIGH:
                self.high_count += 1
            case Severity.MEDIUM:
                self.medium_count += 1
            case Severity.LOW:
                self.low_count += 1
            case Severity.INFO:
                self.info_count += 1


class VulnerabilityDatabase:
    """Local vulnerability signature database with CVE matching rules."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._rules: list[dict[str, Any]] = []
        self._cve_cache: dict[str, dict[str, Any]] = {}
        if db_path is None:
            self._load_default_rules()
        elif db_path.exists():
            self._load_rules(db_path)

    def _load_default_rules(self) -> None:
        """Load the signature rules packaged with the distribution."""
        try:
            resource = importlib.resources.files("netsec_auditor.data") / "vuln-rules.yaml"
            data = yaml.safe_load(resource.read_text(encoding="utf-8"))
            self._rules = data.get("rules", [])
        except (FileNotFoundError, ModuleNotFoundError, OSError) as e:
            logger.warning("default_vuln_rules_unavailable", error=str(e))
            return
        logger.info("vuln_rules_loaded", count=len(self._rules), source="packaged")

    def _load_rules(self, path: Path) -> None:
        with open(path) as f:
            data = yaml.safe_load(f)
            self._rules = data.get("rules", [])
        logger.info("vuln_rules_loaded", count=len(self._rules), source=str(path))

    def match_service(
        self, service: ServiceInfo, port: int
    ) -> list[Vulnerability]:
        """Match a service against vulnerability rules."""
        vulns: list[Vulnerability] = []
        for rule in self._rules:
            if self._rule_matches(rule, service, port):
                vulns.append(self._rule_to_vuln(rule))
        return vulns

    def _rule_matches(self, rule: dict[str, Any], service: ServiceInfo, port: int) -> bool:
        conditions = rule.get("conditions", {})

        name = conditions.get("service_name")
        if name is not None and name.lower() != service.name.lower():
            return False
        if "port" in conditions and conditions["port"] != port:
            return False
        product = conditions.get("product")
        if product is not None and not re.search(product, service.product, re.IGNORECASE):
            return False
        version = conditions.get("version")
        if version is not None and not re.search(version, service.version, re.IGNORECASE):
            return False
        vlt = conditions.get("version_lt")
        # Guard-clause style kept for consistency with the checks above.
        if vlt is not None and not self._version_less_than(service.version, vlt):  # noqa: SIM103
            return False
        return True

    @staticmethod
    def _version_less_than(current: str, target: str) -> bool:
        """Simple semantic version comparison."""
        current_match = re.match(r"^[vV]?(\d+(?:\.\d+)*)", current.strip())
        target_match = re.match(r"^[vV]?(\d+(?:\.\d+)*)", target.strip())
        if current_match is None or target_match is None:
            return False
        cur_parts = [int(x) for x in current_match.group(1).split(".")]
        tgt_parts = [int(x) for x in target_match.group(1).split(".")]
        width = max(len(cur_parts), len(tgt_parts))
        return cur_parts + [0] * (width - len(cur_parts)) < tgt_parts + [0] * (
            width - len(tgt_parts)
        )

    def _rule_to_vuln(self, rule: dict[str, Any]) -> Vulnerability:
        return Vulnerability(
            id=rule.get("id", short_id(rule.get("name", ""), 12)),
            name=rule.get("name", "Unknown"),
            description=rule.get("description", ""),
            severity=Severity(rule.get("severity", "info")),
            category=VulnCategory(rule.get("category", "misconfiguration")),
            cvss_score=float(rule.get("cvss_score", 0)),
            cve_id=rule.get("cve_id", ""),
            remediation=rule.get("remediation", ""),
            references=rule.get("references", []),
            exploit_available=rule.get("exploit_available", False),
            metasploit_module=rule.get("metasploit_module", ""),
        )


class VulnerabilityScanner:
    """Scans host results for known vulnerabilities and misconfigurations."""

    def __init__(self, vuln_db: VulnerabilityDatabase | None = None) -> None:
        self.vuln_db = vuln_db or VulnerabilityDatabase()
        self._checks: list[Callable[[HostResult], list[Vulnerability]]] = [
            self._check_insecure_protocols,
            self._check_exposed_services,
            self._check_default_ports,
            self._check_weak_services,
        ]

    async def scan_host(self, host: HostResult) -> VulnScanResult:
        """Run all vulnerability checks against a host."""
        result = VulnScanResult(host=host.ip)

        for port_result in host.open_ports:
            if port_result.service:
                db_vulns = self.vuln_db.match_service(port_result.service, port_result.port)
                for vuln in db_vulns:
                    vuln.affected_host = host.ip
                    vuln.affected_port = port_result.port
                    vuln.affected_service = port_result.service.name
                    result.add_vulnerability(vuln)

        for check in self._checks:
            vulns = check(host)
            for vuln in vulns:
                result.add_vulnerability(vuln)

        logger.info(
            "vuln_scan_complete",
            host=host.ip,
            vulns=len(result.vulnerabilities),
            risk=result.risk_score,
        )
        return result

    async def scan_hosts(self, hosts: list[HostResult]) -> list[VulnScanResult]:
        """Scan multiple hosts concurrently."""
        tasks = [self.scan_host(h) for h in hosts]
        return await asyncio.gather(*tasks)

    def _check_insecure_protocols(self, host: HostResult) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        insecure_ports = {
            21: ("FTP", "Use SFTP or FTPS instead"),
            23: ("Telnet", "Use SSH instead"),
            110: ("POP3", "Use POP3S (port 995) instead"),
            143: ("IMAP", "Use IMAPS (port 993) instead"),
            161: ("SNMP v1/v2c", "Use SNMPv3 with encryption"),
            389: ("LDAP", "Use LDAPS (port 636) instead"),
            512: ("rexec", "Disable rexec service"),
            513: ("rlogin", "Disable rlogin service"),
            514: ("rsh", "Disable rsh service"),
        }

        for port_result in host.open_ports:
            if port_result.port in insecure_ports:
                proto, remediation = insecure_ports[port_result.port]
                vulns.append(
                    Vulnerability(
                        id=f"INSECURE-PROTO-{host.ip}-{port_result.port}",
                        name=f"Insecure protocol: {proto} on port {port_result.port}",
                        description=f"{proto} transmits data in cleartext and is vulnerable to "
                        f"eavesdropping and credential theft.",
                        severity=Severity.HIGH,
                        category=VulnCategory.INSECURE_PROTOCOL,
                        affected_host=host.ip,
                        affected_port=port_result.port,
                        affected_service=proto,
                        evidence=f"Port {port_result.port} is open running {proto}",
                        remediation=remediation,
                        references=["https://owasp.org/www-project-top-ten/"],
                    )
                )
        return vulns

    def _check_exposed_services(self, host: HostResult) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        sensitive_ports = {
            3306: ("MySQL", "Restrict MySQL to localhost or use firewall rules"),
            5432: ("PostgreSQL", "Restrict PostgreSQL to localhost or use firewall rules"),
            6379: ("Redis", "Enable Redis authentication and bind to localhost"),
            27017: ("MongoDB", "Enable MongoDB authentication and bind to localhost"),
            9200: ("Elasticsearch", "Restrict Elasticsearch access with firewall"),
            3389: ("RDP", "Restrict RDP access with firewall and use VPN"),
            5900: ("VNC", "Use VNC over SSH tunnel or VPN"),
            11211: ("Memcached", "Bind Memcached to localhost only"),
        }

        for port_result in host.open_ports:
            if port_result.port in sensitive_ports:
                service_name, remediation = sensitive_ports[port_result.port]
                vulns.append(
                    Vulnerability(
                        id=f"EXPOSED-{host.ip}-{port_result.port}",
                        name=f"Potentially exposed {service_name} on port {port_result.port}",
                        description=f"{service_name} is exposed on the network. If this service "
                        f"does not require remote access, it should be firewalled.",
                        severity=Severity.MEDIUM,
                        category=VulnCategory.EXPOSED_SERVICE,
                        affected_host=host.ip,
                        affected_port=port_result.port,
                        affected_service=service_name,
                        evidence=f"Port {port_result.port} ({service_name}) is open",
                        remediation=remediation,
                    )
                )
        return vulns

    def _check_default_ports(self, host: HostResult) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        default_credentials_services = {
            22: "SSH",
            23: "Telnet",
            21: "FTP",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            8080: "HTTP Management",
            9200: "Elasticsearch",
        }

        for port_result in host.open_ports:
            if port_result.port in default_credentials_services:
                service_name = default_credentials_services[port_result.port]
                vulns.append(
                    Vulnerability(
                        id=f"DEFAULT-CRED-CHECK-{host.ip}-{port_result.port}",
                        name=(
                            f"Default credential check: {service_name} "
                            f"on port {port_result.port}"
                        ),
                        description=f"{service_name} is running on a default port. Verify that "
                        f"default credentials have been changed.",
                        severity=Severity.LOW,
                        category=VulnCategory.WEAK_CREDENTIAL,
                        affected_host=host.ip,
                        affected_port=port_result.port,
                        affected_service=service_name,
                        evidence=f"Port {port_result.port} ({service_name}) is open",
                        remediation=f"Ensure {service_name} is not using default credentials. "
                        f"Enforce strong password policies.",
                    )
                )
        return vulns

    def _check_weak_services(self, host: HostResult) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        for port_result in host.open_ports:
            if port_result.service and port_result.service.name == "http":  # noqa: SIM102
                if port_result.port == 80:
                    vulns.append(
                        Vulnerability(
                            id=f"HTTP-NO-TLS-{host.ip}-80",
                            name="HTTP without TLS on port 80",
                            description="HTTP service detected without encryption. "
                            "All web traffic should use HTTPS.",
                            severity=Severity.MEDIUM,
                            category=VulnCategory.INSECURE_PROTOCOL,
                            affected_host=host.ip,
                            affected_port=80,
                            affected_service="HTTP",
                            evidence="Port 80 is open with HTTP service",
                            remediation="Redirect all HTTP traffic to HTTPS (port 443). "
                            "Implement HSTS headers.",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                        )
                    )
        return vulns


class CVEQueryClient:
    """Query NVD and other CVE databases for vulnerability intelligence."""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str = "", cache_dir: Path | None = None) -> None:
        self.api_key = api_key
        self.cache_dir = cache_dir or Path.home() / ".netsec-auditor" / "cve-cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._client = httpx.AsyncClient(timeout=30.0)

    async def search_cve(self, keyword: str, limit: int = 20) -> list[dict[str, Any]]:
        """Search CVEs by keyword (product name, vendor, etc.)."""
        cache_key = short_id(f"search:{keyword}:{limit}", 32)
        cached = self._load_cache(cache_key)
        if cached is not None:
            return cached

        data = await self._request_nvd({
            "keywordSearch": keyword,
            "resultsPerPage": min(limit, 100),
        })
        if data is None:
            return []
        results = self._parse_nvd_response(data)
        self._save_cache(cache_key, results)
        return results

    async def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Get details for a specific CVE."""
        normalized_id = cve_id.strip().upper()
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized_id) is None:
            return None
        cache_key = short_id(f"cve:{normalized_id}", 32)
        cached = self._load_cache(cache_key)
        if cached:
            return cached[0]

        data = await self._request_nvd({"cveId": normalized_id})
        if data is None:
            return None
        results = self._parse_nvd_response(data)
        if results:
            self._save_cache(cache_key, results)
            return results[0]
        return None

    async def _request_nvd(self, params: dict[str, Any]) -> dict[str, Any] | None:
        """GET the NVD API, backing off on rate-limit (429) and 503 responses."""
        headers = {"apiKey": self.api_key} if self.api_key else {}
        delay = 6.0  # NVD asks unauthenticated clients to stay well under 5 req / 30 s
        for _attempt in range(3):
            try:
                response = await self._client.get(
                    self.NVD_API_BASE, params=params, headers=headers
                )
                if response.status_code in (429, 503):
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                response.raise_for_status()
                return response.json()
            except httpx.HTTPError as e:
                logger.error("nvd_request_failed", error=str(e))
                return None
        logger.error("nvd_rate_limited")
        return None

    async def get_cves_for_product(
        self, product: str, version: str = ""
    ) -> list[dict[str, Any]]:
        """Get CVEs for a specific product and version."""
        query = product
        if version:
            query = f"{product} {version}"
        return await self.search_cve(query)

    def _parse_nvd_response(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        results = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")

            descriptions = cve.get("descriptions", [])
            desc_en = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"), ""
            )

            metrics = cve.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [{}])[0]
            cvss_v30 = metrics.get("cvssMetricV30", [{}])[0]

            cvss_data = cvss_v31.get("cvssData", {}) or cvss_v30.get("cvssData", {})
            base_score = cvss_data.get("baseScore", 0.0)
            vector = cvss_data.get("vectorString", "")

            published = cve.get("published", "")
            modified = cve.get("lastModified", "")

            references = [
                ref.get("url", "") for ref in cve.get("references", [])
            ]

            results.append({
                "cve_id": cve_id,
                "description": desc_en,
                "cvss_score": base_score,
                "cvss_vector": vector,
                "severity": Severity.from_cvss(base_score).value,
                "published": published,
                "modified": modified,
                "references": references,
            })

        return results

    def _load_cache(self, key: str) -> list[dict[str, Any]] | None:
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return None
        return None

    def _save_cache(self, key: str, data: list[dict[str, Any]]) -> None:
        cache_file = self.cache_dir / f"{key}.json"
        try:
            with open(cache_file, "w") as f:
                json.dump(data, f, indent=2)
        except OSError:
            pass

    async def close(self) -> None:
        await self._client.aclose()
