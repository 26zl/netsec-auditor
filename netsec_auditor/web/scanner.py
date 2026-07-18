"""Web application security scanner — HTTP analysis, header checks, directory enumeration,
SSL/TLS assessment, and common web vulnerability detection."""

from __future__ import annotations

import asyncio
import hashlib
import re
import ssl
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from cryptography import x509

from netsec_auditor.scanner.scope import Scope
from netsec_auditor.utils.logging import get_logger

logger = get_logger(__name__)


class HTTPMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"
    PATCH = "PATCH"
    TRACE = "TRACE"


@dataclass
class HTTPResponse:
    status_code: int
    headers: dict[str, str]
    body: str = ""
    body_size: int = 0
    response_time: float = 0.0
    redirect_chain: list[str] = field(default_factory=list)
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass
class SSLCertificate:
    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    san: list[str] = field(default_factory=list)
    fingerprint_sha256: str = ""
    signature_algorithm: str = ""
    key_size: int = 0
    is_expired: bool = False
    is_self_signed: bool = False
    days_until_expiry: int = 0
    issues: list[str] = field(default_factory=list)


@dataclass
class WebVulnerability:
    id: str
    name: str
    description: str
    severity: str
    category: str
    url: str
    parameter: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe_id: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "url": self.url,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "references": self.references,
        }


@dataclass
class WebScanResult:
    url: str
    ip: str = ""
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    ssl_certificate: SSLCertificate | None = None
    vulnerabilities: list[WebVulnerability] = field(default_factory=list)
    discovered_urls: list[str] = field(default_factory=list)
    discovered_directories: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    cookies: dict[str, str] = field(default_factory=dict)
    scan_duration: float = 0.0

    @property
    def risk_score(self) -> float:
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        return sum(weights.get(v.severity, 0) for v in self.vulnerabilities)


class WebScanner:
    """Comprehensive web application security scanner."""

    COMMON_DIRECTORIES = [
        "admin", "administrator", "backup", "backups", "config", "cpanel",
        "dashboard", "db", "debug", "dev", "docs", "download", "files",
        "git", "install", "jenkins", "login", "logs", "manager", "old",
        "panel", "phpmyadmin", "private", "robots.txt", "secret", "secure",
        "setup", "sql", "staging", "svn", "temp", "test", "tmp", "upload",
        "uploads", "webdav", "wp-admin", "wp-content", "wp-includes",
        ".env", ".git/config", ".htaccess", ".svn/entries", ".DS_Store",
        "crossdomain.xml", "sitemap.xml", "server-status", "server-info",
        "actuator", "actuator/health", "actuator/info", "swagger-ui.html",
        "api-docs", "v2/api-docs", "graphql", "console", "api/v1",
        ".well-known/security.txt",
    ]

    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "severity": "high",
            "description": "HSTS header missing — enables HTTPS enforcement",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
        },
        "Content-Security-Policy": {
            "severity": "medium",
            "description": "CSP header missing — no XSS/mixed-content protection",
            "remediation": "Implement a Content-Security-Policy header",
        },
        "X-Content-Type-Options": {
            "severity": "low",
            "description": "X-Content-Type-Options missing — MIME sniffing possible",
            "remediation": "Add 'X-Content-Type-Options: nosniff'",
        },
        "X-Frame-Options": {
            "severity": "low",
            "description": "X-Frame-Options missing — clickjacking possible",
            "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'",
        },
        "X-XSS-Protection": {
            "severity": "low",
            "description": "X-XSS-Protection missing",
            "remediation": "Add 'X-XSS-Protection: 1; mode=block'",
        },
        "Referrer-Policy": {
            "severity": "low",
            "description": "Referrer-Policy missing — information leakage possible",
            "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'",
        },
        "Permissions-Policy": {
            "severity": "low",
            "description": "Permissions-Policy missing",
            "remediation": "Implement a Permissions-Policy header",
        },
    }

    TECHNOLOGY_SIGNATURES: dict[str, list[str]] = {
        "Apache": ["Server: Apache", "X-Powered-By: Apache"],
        "nginx": ["Server: nginx"],
        "IIS": ["Server: Microsoft-IIS", "X-Powered-By: ASP.NET"],
        "PHP": ["X-Powered-By: PHP", "Set-Cookie: PHPSESSID"],
        "Django": ["X-Frame-Options: SAMEORIGIN", "csrftoken"],
        "Ruby on Rails": ["X-Powered-By: Phusion", "_rails_session"],
        "Express": ["X-Powered-By: Express"],
        "WordPress": ["wp-content", "wp-includes", "X-Powered-By: WordPress"],
        "Drupal": ["X-Generator: Drupal"],
        "Joomla": ["X-Meta-Generator: Joomla"],
        "Cloudflare": ["Server: cloudflare", "CF-Ray"],
        "AWS": ["X-Amz-Request-Id", "X-Cache: Hit from cloudfront"],
        "jQuery": ["jquery"],
        "React": ["react", "__NEXT_DATA__"],
        "Vue.js": ["vue", "data-v-"],
        "Angular": ["ng-version", "angular"],
        "Bootstrap": ["bootstrap"],
        "Tomcat": ["Apache-Coyote", "Apache Tomcat"],
        "Jenkins": ["X-Jenkins", "Jenkins-Crumb"],
        "Grafana": ["X-Grafana-Org-Id"],
        "Prometheus": ["Prometheus"],
    }

    def __init__(
        self,
        scope: Scope,
        timeout: float = 10.0,
        max_redirects: int = 5,
        user_agent: str = "NetSec-Auditor/1.0 (Authorized Security Scan)",
        concurrency: int = 10,
    ) -> None:
        self.scope = scope
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.concurrency = concurrency
        # TLS verification is intentionally disabled: scan targets frequently
        # present invalid/self-signed certs, which _analyze_ssl reports separately.
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            max_redirects=max_redirects,
            headers={"User-Agent": user_agent},
            verify=False,
        )

    async def scan(self, url: str, deep: bool = False) -> WebScanResult:
        """Perform a comprehensive web security scan."""
        self.scope.validate_target(url)
        start = time.monotonic()

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        result = WebScanResult(url=base_url)

        # TLS/cert analysis runs first so it works even for old-TLS-only servers
        # that a modern HTTP client cannot GET.
        if parsed.scheme == "https":
            tls_port = parsed.port or 443
            result.ssl_certificate = await self._analyze_ssl(parsed.hostname, tls_port)
            result.vulnerabilities.extend(
                await self._check_tls_posture(parsed.hostname, tls_port, base_url)
            )

        response = await self._safe_request("GET", base_url)
        if response is None:
            result.scan_duration = time.monotonic() - start
            return result

        result.headers = response.headers
        result.server = response.headers.get("Server", "")
        result.cookies = response.cookies

        result.technologies = self._fingerprint_technologies(response)

        result.vulnerabilities.extend(self._check_security_headers(response, base_url))
        result.vulnerabilities.extend(self._check_information_disclosure(response, base_url))
        result.vulnerabilities.extend(await self._check_http_methods(base_url))
        result.vulnerabilities.extend(self._check_cookie_security(response, base_url))

        if deep:
            result.forms = await self._discover_forms(response)
            result.discovered_directories = await self._enumerate_directories(base_url)
            result.discovered_urls = await self._crawl(base_url, response)

        result.scan_duration = time.monotonic() - start
        logger.info("web_scan_complete", url=base_url, vulns=len(result.vulnerabilities))
        return result

    async def _safe_request(
        self, method: str, url: str, **kwargs: Any
    ) -> HTTPResponse | None:
        """Make a safe HTTP request with error handling."""
        try:
            resp = await self._client.request(method, url, **kwargs)
            cookies = {}
            for key, value in resp.cookies.items():
                cookies[key] = value

            return HTTPResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                body_size=len(resp.content),
                response_time=resp.elapsed.total_seconds(),
                redirect_chain=[str(h.url) for h in resp.history],
                cookies=cookies,
            )
        except (httpx.HTTPError, httpx.TimeoutException) as e:
            logger.debug("request_failed", url=url, error=str(e))
            return None

    def _fingerprint_technologies(self, response: HTTPResponse) -> list[str]:
        """Detect web technologies from headers and response body."""
        detected: list[str] = []
        combined = "\n".join(
            f"{k}: {v}" for k, v in response.headers.items()
        ) + "\n" + response.body[:10000]

        for tech, signatures in self.TECHNOLOGY_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in combined.lower():
                    if tech not in detected:
                        detected.append(tech)
                    break

        return sorted(detected)

    def _check_security_headers(
        self, response: HTTPResponse, url: str
    ) -> list[WebVulnerability]:
        """Check for missing or misconfigured security headers."""
        vulns: list[WebVulnerability] = []

        for header, info in self.SECURITY_HEADERS.items():
            if header not in response.headers:
                vulns.append(
                    WebVulnerability(
                        id=f"HEADER-MISSING-{hashlib.md5(header.encode()).hexdigest()[:8]}",
                        name=f"Missing security header: {header}",
                        description=info["description"],
                        severity=info["severity"],
                        category="security_header",
                        url=url,
                        evidence=f"Header '{header}' not present in response",
                        remediation=info["remediation"],
                    )
                )

        if "Server" in response.headers:
            vulns.append(
                WebVulnerability(
                    id=f"HEADER-SERVER-{hashlib.md5(url.encode()).hexdigest()[:8]}",
                    name="Server header exposes version information",
                    description=f"Server header reveals: {response.headers['Server']}",
                    severity="low",
                    category="information_disclosure",
                    url=url,
                    evidence=f"Server: {response.headers['Server']}",
                    remediation="Remove or obfuscate the Server header",
                )
            )

        if "X-Powered-By" in response.headers:
            vulns.append(
                WebVulnerability(
                    id=f"HEADER-POWERED-{hashlib.md5(url.encode()).hexdigest()[:8]}",
                    name="X-Powered-By header exposes technology",
                    description=f"X-Powered-By reveals: {response.headers['X-Powered-By']}",
                    severity="low",
                    category="information_disclosure",
                    url=url,
                    evidence=f"X-Powered-By: {response.headers['X-Powered-By']}",
                    remediation="Remove the X-Powered-By header",
                )
            )

        return vulns

    def _check_information_disclosure(
        self, response: HTTPResponse, url: str
    ) -> list[WebVulnerability]:
        """Check for information disclosure in response body."""
        vulns: list[WebVulnerability] = []

        patterns: dict[str, tuple[str, str, str]] = {
            r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?\S+['\"]?": (
                "high",
                "Possible password in response body",
                "Remove hardcoded credentials from responses",
            ),
            r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?\S+['\"]?": (
                "high",
                "Possible API key in response body",
                "Never expose API keys in client-side code",
            ),
            r"(?:-----BEGIN\s*(?:RSA|DSA|EC|OPENSSH|PGP)\s*PRIVATE\s*KEY)": (
                "critical",
                "Private key exposed in response",
                "Remove private keys from web-accessible locations immediately",
            ),
            r"(?:jdbc|mysql|postgresql|mongodb|redis)://[^/\s'\"]+": (
                "high",
                "Database connection string in response",
                "Remove database connection strings from client-side code",
            ),
            r"(?:AKIA[0-9A-Z]{16})": (
                "high",
                "AWS access key in response",
                "Remove AWS keys and rotate immediately",
            ),
            r"<!--.*?(?:TODO|FIXME|HACK|BUG).*?-->": (
                "low",
                "Developer comments in HTML source",
                "Remove development comments from production code",
            ),
        }

        for pattern, (severity, description, remediation) in patterns.items():
            matches = re.findall(pattern, response.body, re.IGNORECASE)
            for match in matches[:3]:
                vulns.append(
                    WebVulnerability(
                        id=f"INFO-DISC-{hashlib.md5(match.encode()).hexdigest()[:8]}",
                        name=description,
                        description=f"Found: {match[:100]}",
                        severity=severity,
                        category="information_disclosure",
                        url=url,
                        evidence=match[:200],
                        remediation=remediation,
                    )
                )

        return vulns

    async def _check_http_methods(self, url: str) -> list[WebVulnerability]:
        """Probe for dangerous HTTP methods using the async client (non-blocking)."""
        vulns: list[WebVulnerability] = []

        dangerous_methods = {
            "PUT": ("high", "PUT method enabled — allows file upload", "Disable PUT method"),
            "DELETE": ("medium", "DELETE method enabled", "Disable DELETE method"),
            "TRACE": ("medium", "TRACE method enabled — XST possible", "Disable TRACE method"),
        }

        for method, (severity, desc, remediation) in dangerous_methods.items():
            resp = await self._safe_request(method, url, follow_redirects=False)
            if resp is None or not (200 <= resp.status_code < 300):
                continue
            vulns.append(
                WebVulnerability(
                    id=f"HTTP-METHOD-{method}-{hashlib.md5(url.encode()).hexdigest()[:8]}",
                    name=desc,
                    description=f"HTTP {method} returned status {resp.status_code}",
                    severity=severity,
                    category="http_method",
                    url=url,
                    evidence=f"{method} {url} -> {resp.status_code}",
                    remediation=remediation,
                )
            )

        return vulns

    def _check_cookie_security(
        self, response: HTTPResponse, url: str
    ) -> list[WebVulnerability]:
        """Check for insecure cookie attributes."""
        vulns: list[WebVulnerability] = []

        set_cookie_headers = [
            v for k, v in response.headers.items() if k.lower() == "set-cookie"
        ]

        for cookie_str in set_cookie_headers:
            cookie_lower = cookie_str.lower()

            if "httponly" not in cookie_lower:
                vulns.append(
                    WebVulnerability(
                        id=f"COOKIE-NO-HTTPONLY-{hashlib.md5(cookie_str.encode()).hexdigest()[:8]}",
                        name="Cookie missing HttpOnly flag",
                        description=(
                            "Cookie without HttpOnly can be accessed by "
                            "JavaScript (XSS risk)"
                        ),
                        severity="medium",
                        category="cookie_security",
                        url=url,
                        evidence=cookie_str[:200],
                        remediation="Add HttpOnly flag to all cookies",
                        cwe_id="CWE-1004",
                    )
                )

            if "secure" not in cookie_lower:
                vulns.append(
                    WebVulnerability(
                        id=f"COOKIE-NO-SECURE-{hashlib.md5(cookie_str.encode()).hexdigest()[:8]}",
                        name="Cookie missing Secure flag",
                        description="Cookie without Secure can be transmitted over HTTP",
                        severity="medium",
                        category="cookie_security",
                        url=url,
                        evidence=cookie_str[:200],
                        remediation="Add Secure flag to all cookies",
                        cwe_id="CWE-614",
                    )
                )

            if "samesite" not in cookie_lower:
                vulns.append(
                    WebVulnerability(
                        id=f"COOKIE-NO-SAMESITE-{hashlib.md5(cookie_str.encode()).hexdigest()[:8]}",
                        name="Cookie missing SameSite attribute",
                        description="Cookie without SameSite is vulnerable to CSRF",
                        severity="low",
                        category="cookie_security",
                        url=url,
                        evidence=cookie_str[:200],
                        remediation="Add SameSite=Lax or SameSite=Strict to cookies",
                        cwe_id="CWE-1275",
                    )
                )

        return vulns

    async def _check_tls_posture(
        self, hostname: str, port: int, url: str
    ) -> list[WebVulnerability]:
        """Scan TLS protocol versions and ciphers; map findings to vulnerabilities."""
        from netsec_auditor.web.tls import scan_tls

        result = await scan_tls(hostname, port, self.timeout)
        vulns: list[WebVulnerability] = []
        for finding in result.get("findings", []):
            digest = hashlib.md5((finding["name"] + url).encode()).hexdigest()[:8]
            vulns.append(
                WebVulnerability(
                    id=f"TLS-{digest}",
                    name=finding["name"],
                    description=finding.get("description", ""),
                    severity=finding.get("severity", "info"),
                    category="tls",
                    url=url,
                    evidence=finding.get("evidence", ""),
                    remediation=finding.get("remediation", ""),
                )
            )
        return vulns

    async def _analyze_ssl(
        self, hostname: str, port: int = 443
    ) -> SSLCertificate | None:
        """Analyze the TLS certificate.

        The certificate is fetched without requiring validation and parsed
        directly, so expired / self-signed / hostname-mismatch certs are reported
        rather than silently dropped. Chain trust is checked separately.
        """
        cert_bin = await self._fetch_cert_der(hostname, port)
        if cert_bin is None:
            return None

        cert = self._parse_certificate(cert_bin, hostname)

        trusted, reason = await self._verify_trust(hostname, port)
        if not trusted and reason:
            cert.issues.append(f"Certificate chain not trusted: {reason}")
        return cert

    async def _fetch_cert_der(self, hostname: str, port: int) -> bytes | None:
        """Retrieve the peer certificate (DER) without requiring it to validate."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=ctx), timeout=self.timeout
            )
            cert_bin = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
            writer.close()
            await writer.wait_closed()
            return cert_bin
        except (TimeoutError, ssl.SSLError, OSError) as e:
            logger.debug("ssl_fetch_failed", hostname=hostname, error=str(e))
            return None

    async def _verify_trust(self, hostname: str, port: int) -> tuple[bool, str]:
        """Check whether the chain and hostname validate against the system trust store."""
        ctx = ssl.create_default_context()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=ctx), timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True, ""
        except ssl.SSLCertVerificationError as e:
            return False, e.verify_message or str(e)
        except (TimeoutError, ssl.SSLError, OSError) as e:
            return False, str(e)

    def _parse_certificate(self, cert_bin: bytes, hostname: str) -> SSLCertificate:
        """Parse a DER certificate into an SSLCertificate (dates, subject, SAN, key)."""
        cert = SSLCertificate()
        cert.fingerprint_sha256 = hashlib.sha256(cert_bin).hexdigest()
        try:
            x = x509.load_der_x509_certificate(cert_bin)
        except ValueError:
            return cert

        cert.subject = self._name_to_dict(x.subject)
        cert.issuer = self._name_to_dict(x.issuer)
        cert.serial_number = format(x.serial_number, "x")
        cert.is_self_signed = x.subject == x.issuer

        not_after = getattr(x, "not_valid_after_utc", None) or x.not_valid_after.replace(
            tzinfo=UTC
        )
        not_before = getattr(x, "not_valid_before_utc", None) or x.not_valid_before.replace(
            tzinfo=UTC
        )
        cert.not_after = not_after.strftime("%Y-%m-%d %H:%M:%S UTC")
        cert.not_before = not_before.strftime("%Y-%m-%d %H:%M:%S UTC")
        cert.days_until_expiry = (not_after - datetime.now(UTC)).days
        cert.is_expired = cert.days_until_expiry < 0

        try:
            san_ext = x.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            cert.san = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            cert.san = []

        key = x.public_key()
        cert.key_size = getattr(key, "key_size", 0)
        if x.signature_hash_algorithm:
            cert.signature_algorithm = x.signature_hash_algorithm.name

        if cert.is_expired:
            cert.issues.append("Certificate has expired")
        elif 0 <= cert.days_until_expiry < 30:
            cert.issues.append(f"Certificate expires in {cert.days_until_expiry} days")
        if cert.is_self_signed:
            cert.issues.append("Self-signed certificate")
        if cert.san and not self._hostname_matches(hostname, cert.san):
            cert.issues.append(f"Hostname {hostname} not covered by certificate SANs")
        if cert.days_until_expiry > 398:
            cert.issues.append("Certificate validity period exceeds 398 days")

        return cert

    @staticmethod
    def _name_to_dict(name: x509.Name) -> dict[str, str]:
        result: dict[str, str] = {}
        for attr in name:
            value = attr.value if isinstance(attr.value, str) else str(attr.value)
            result[attr.rfc4514_attribute_name] = value
        return result

    @staticmethod
    def _hostname_matches(hostname: str, patterns: list[str]) -> bool:
        """RFC 6125 match: a '*' wildcard covers exactly one left-most label."""
        hostname = hostname.lower().rstrip(".")
        for pattern in patterns:
            pattern = pattern.lower()
            if pattern.startswith("*."):
                head, _, tail = hostname.partition(".")
                if tail and pattern[1:] == "." + tail:
                    return True
            elif pattern == hostname:
                return True
        return False

    async def _enumerate_directories(self, base_url: str) -> list[str]:
        """Enumerate common directories and files."""
        found: list[str] = []
        semaphore = asyncio.Semaphore(self.concurrency)

        async def _check(path: str) -> None:
            async with semaphore:
                url = urljoin(base_url, path)
                resp = await self._safe_request("GET", url)
                if resp and resp.status_code in (200, 301, 302, 403, 401):
                    found.append(f"{url} [{resp.status_code}]")

        await asyncio.gather(*[_check(d) for d in self.COMMON_DIRECTORIES])
        return sorted(found)

    async def _discover_forms(self, response: HTTPResponse) -> list[dict[str, Any]]:
        """Discover HTML forms on the page."""
        forms: list[dict[str, Any]] = []
        try:
            soup = BeautifulSoup(response.body, "lxml")
            for form in soup.find_all("form"):
                form_info: dict[str, Any] = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "GET").upper(),
                    "inputs": [],
                }
                for inp in form.find_all(["input", "textarea", "select"]):
                    form_info["inputs"].append({
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })
                forms.append(form_info)
        except Exception:
            pass
        return forms

    async def _crawl(self, base_url: str, response: HTTPResponse) -> list[str]:
        """Extract links from the page for crawling."""
        urls: set[str] = set()
        try:
            soup = BeautifulSoup(response.body, "lxml")
            parsed_base = urlparse(base_url)

            for tag in soup.find_all(["a", "link", "script", "img", "iframe", "source"]):
                href = tag.get("href") or tag.get("src")
                if not href:
                    continue
                if href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                    continue

                full_url = urljoin(base_url, href)
                full_parsed = urlparse(full_url)

                if full_parsed.netloc == parsed_base.netloc:
                    urls.add(full_url)
        except Exception:
            pass

        return sorted(urls)[:200]

    async def close(self) -> None:
        await self._client.aclose()
