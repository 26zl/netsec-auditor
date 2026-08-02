"""TLS/SSL protocol and cipher posture scanning (testssl-style, mostly passive).

Complements the certificate analysis in ``web.scanner`` by enumerating which
protocol versions a server negotiates and whether it accepts weak ciphers.
Everything is best-effort: probing depends on what the *local* OpenSSL build is
willing to offer, so the scan honestly distinguishes "server does not support"
from "could not be tested by this client".
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import warnings

from netsec_auditor.utils.logging import get_logger

logger = get_logger(__name__)

# Public protocol name -> ssl.TLSVersion attribute name (may be absent on new builds).
_PROTOCOL_ATTRS: dict[str, str] = {
    "TLSv1": "TLSv1",
    "TLSv1.1": "TLSv1_1",
    "TLSv1.2": "TLSv1_2",
    "TLSv1.3": "TLSv1_3",
    "SSLv3": "SSLv3",
}

# Exact weak-cipher offer string (guarded — modern OpenSSL may compile these out).
_WEAK_CIPHER_SPEC = "RC4:3DES:DES:NULL:EXPORT:MD5"

_PROTOCOL_REMEDIATION = (
    "Disable SSLv3 and TLS 1.0/1.1; require TLS 1.2+ with AEAD ciphers "
    "(ECDHE + AES-GCM or ChaCha20-Poly1305)."
)
_CIPHER_REMEDIATION = (
    "Disable weak ciphers (RC4, 3DES, DES, NULL, EXPORT, MD5); require TLS 1.2+ "
    "AEAD suites such as AES-GCM or ChaCha20-Poly1305."
)


def _finding(
    name: str, severity: str, description: str, evidence: str, remediation: str
) -> dict[str, str]:
    """Build a finding record with the canonical five-key shape."""
    return {
        "name": name,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
    }


def classify_protocol_findings(protocols: dict[str, bool | None]) -> list[dict[str, str]]:
    """Derive findings from a protocol-support map (pure; ``None`` = untested)."""
    findings: list[dict[str, str]] = []

    if protocols.get("SSLv2") is True:
        findings.append(_finding(
            "Obsolete protocol SSLv2 supported", "high",
            "SSL 2.0 is fundamentally broken and must never be enabled.",
            "Server completed an SSLv2 handshake.", _PROTOCOL_REMEDIATION,
        ))
    if protocols.get("SSLv3") is True:
        findings.append(_finding(
            "Obsolete protocol SSLv3 supported", "high",
            "SSL 3.0 is obsolete and vulnerable to the POODLE attack (CVE-2014-3566).",
            "Server completed an SSLv3 handshake.", _PROTOCOL_REMEDIATION,
        ))
    if protocols.get("TLSv1") is True:
        findings.append(_finding(
            "Deprecated protocol TLS 1.0 supported", "medium",
            "TLS 1.0 is deprecated (RFC 8996) and exposed to BEAST and downgrade attacks.",
            "Server completed a TLS 1.0 handshake.", _PROTOCOL_REMEDIATION,
        ))
    if protocols.get("TLSv1.1") is True:
        findings.append(_finding(
            "Deprecated protocol TLS 1.1 supported", "medium",
            "TLS 1.1 is deprecated (RFC 8996) and should no longer be offered.",
            "Server completed a TLS 1.1 handshake.", _PROTOCOL_REMEDIATION,
        ))
    if protocols.get("TLSv1.3") is False:
        findings.append(_finding(
            "TLS 1.3 not supported", "low",
            "Server does not support TLS 1.3 and its AEAD-only, forward-secret suites.",
            "TLS 1.3 handshake was refused by the server.",
            "Enable TLS 1.3 alongside TLS 1.2.",
        ))
    return findings


def _weak_cipher_severity(cipher: str) -> tuple[str, str]:
    """Map a cipher name to (severity, reason); order matters (3DES before DES)."""
    upper = cipher.upper()
    if "NULL" in upper:
        return "high", "NULL cipher provides no traffic encryption."
    if "EXP" in upper:
        return "high", "Export-grade cipher uses deliberately weakened key sizes."
    if "RC4" in upper:
        return "high", "RC4 is a broken stream cipher with practical biases (CVE-2015-2808)."
    if "3DES" in upper or "DES-CBC3" in upper or "DES_EDE" in upper:
        return "medium", "3DES is vulnerable to the SWEET32 birthday attack (CVE-2016-2183)."
    if "DES" in upper:
        return "high", "Single-DES uses a 56-bit key and is trivially brute-forced."
    if "MD5" in upper:
        return "medium", "MD5-based MAC is cryptographically weak."
    return "medium", "Legacy or otherwise weak cipher suite accepted."


def classify_cipher_findings(weak: list[str]) -> list[dict[str, str]]:
    """Derive findings from a list of accepted weak cipher names (pure)."""
    findings: list[dict[str, str]] = []
    for cipher in weak:
        if not cipher:
            continue
        severity, reason = _weak_cipher_severity(cipher)
        findings.append(_finding(
            f"Weak cipher accepted: {cipher}", severity, reason,
            f"Server negotiated {cipher} when offered legacy/weak cipher suites.",
            _CIPHER_REMEDIATION,
        ))
    return findings


_EXPECTED_VERSION = {
    "SSLv3": "SSLv3",
    "TLSv1": "TLSv1",
    "TLSv1_1": "TLSv1.1",
    "TLSv1_2": "TLSv1.2",
    "TLSv1_3": "TLSv1.3",
}


def _resolve_version(attr: str) -> ssl.TLSVersion | None:
    """Return the TLSVersion enum for ``attr`` or None if this build lacks it."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return getattr(ssl.TLSVersion, attr, None)


def _relax_ciphers(ctx: ssl.SSLContext) -> None:
    """Widen the client cipher list so legacy protocols can actually be probed."""
    with contextlib.suppress(ssl.SSLError, ValueError):
        ctx.set_ciphers("ALL:@SECLEVEL=0")


def _build_pinned_context(ver: ssl.TLSVersion) -> ssl.SSLContext | None:
    """Build a CERT_NONE client context pinned to a single version, or None."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            ctx.minimum_version = ver
            ctx.maximum_version = ver
        except (ValueError, OSError):
            return None  # local OpenSSL refuses to negotiate this version
    _relax_ciphers(ctx)
    return ctx


async def _handshake(
    hostname: str,
    port: int,
    ctx: ssl.SSLContext,
    timeout: float,
    connect_host: str | None = None,
) -> tuple[str, str] | None:
    """Attempt a TLS handshake; return (version, cipher) on success else None.

    ``connect_host`` is the scope-validated address to dial; SNI still carries the
    hostname so a second DNS answer cannot redirect the probe off-scope.
    """
    try:
        conn = asyncio.open_connection(
            connect_host or hostname, port, ssl=ctx, server_hostname=hostname
        )
        _, writer = await asyncio.wait_for(conn, timeout=timeout)
    except (TimeoutError, ssl.SSLError, OSError):
        return None

    ssl_object = writer.get_extra_info("ssl_object")
    version = ssl_object.version() or "" if ssl_object is not None else ""
    cipher_tuple = ssl_object.cipher() if ssl_object is not None else None
    cipher = cipher_tuple[0] if cipher_tuple else ""

    writer.close()
    with contextlib.suppress(TimeoutError, ssl.SSLError, OSError):
        await writer.wait_closed()
    return version, cipher


async def _probe_protocol(
    hostname: str, port: int, attr: str, timeout: float, connect_host: str | None = None
) -> bool | None:
    """True if supported, False if refused, None if this client cannot test it."""
    ver = _resolve_version(attr)
    if ver is None:
        return None  # attribute absent on this build
    ctx = _build_pinned_context(ver)
    if ctx is None:
        return None  # local OpenSSL will not offer this version
    result = await _handshake(hostname, port, ctx, timeout, connect_host)
    if result is None:
        return False  # server refused this version
    negotiated, _ = result
    expected = _EXPECTED_VERSION.get(attr, "")
    if expected and negotiated and negotiated != expected:
        # The client ignored the pin (e.g. LibreSSL) and negotiated another
        # version — we cannot confirm support for the pinned one.
        return None
    return True


async def _probe_weak_ciphers(
    hostname: str, port: int, timeout: float, connect_host: str | None = None
) -> str:
    """Offer only weak ciphers over TLS 1.2; return the negotiated name or ''."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Pin TLS 1.2 so we test classic ciphers, not fixed TLS 1.3 AEAD suites.
    with contextlib.suppress(ValueError):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers(_WEAK_CIPHER_SPEC)
    except (ssl.SSLError, ValueError):
        return ""  # local OpenSSL has none of these weak ciphers to offer
    result = await _handshake(hostname, port, ctx, timeout, connect_host)
    return result[1] if result is not None else ""


async def _probe_default(
    hostname: str, port: int, timeout: float, connect_host: str | None = None
) -> tuple[str, str] | None:
    """Perform a default handshake to record the normally-negotiated params."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return await _handshake(hostname, port, ctx, timeout, connect_host)


async def scan_tls(
    hostname: str,
    port: int = 443,
    timeout: float = 10.0,
    connect_host: str | None = None,
) -> dict[str, object]:
    """Scan a host's TLS protocol versions and weak-cipher acceptance.

    Returns ``{"protocols": {...}, "weak_ciphers": [...], "findings": [...]}``.
    Never raises: any unexpected failure yields the empty result structure.
    """
    try:
        protocols: dict[str, bool | None] = {}
        for name, attr in _PROTOCOL_ATTRS.items():
            protocols[name] = await _probe_protocol(hostname, port, attr, timeout, connect_host)

        negotiated = await _probe_default(hostname, port, timeout, connect_host)
        # A refused TLS version and a closed port both present as a failed
        # handshake, so posture is only assessed once a TLS service is confirmed
        # reachable — otherwise a host with nothing on this port would be reported
        # as "TLS 1.3 not supported".
        if negotiated is None and not any(v is True for v in protocols.values()):
            logger.debug("tls_no_service", hostname=hostname, port=port)
            return {"protocols": {}, "weak_ciphers": [], "findings": []}

        findings = classify_protocol_findings(protocols)

        weak_cipher = await _probe_weak_ciphers(hostname, port, timeout, connect_host)
        weak_ciphers = [weak_cipher] if weak_cipher else []
        findings.extend(classify_cipher_findings(weak_ciphers))

        if negotiated is not None:
            version, cipher = negotiated
            findings.append(_finding(
                "Negotiated TLS parameters", "info",
                f"Default handshake negotiated {version or 'unknown'} using "
                f"{cipher or 'unknown cipher'}.",
                f"protocol={version}, cipher={cipher}", "",
            ))

        untested = [name for name, ok in protocols.items() if ok is None]
        if untested:
            findings.append(_finding(
                "Protocols not tested (client limitation)", "info",
                "The local TLS stack could not negotiate these versions, so their "
                "server-side status is unknown (not necessarily disabled): "
                + ", ".join(untested) + ".",
                f"Local OpenSSL: {ssl.OPENSSL_VERSION}",
                "Re-scan with a TLS stack supporting these versions to confirm.",
            ))

        logger.info(
            "tls_scan_complete", hostname=hostname,
            supported=[k for k, v in protocols.items() if v is True],
            weak_ciphers=weak_ciphers,
        )
        return {
            "protocols": protocols,
            "weak_ciphers": weak_ciphers,
            "findings": findings,
        }
    except Exception as e:  # never raise — TLS probing is strictly best-effort
        logger.debug("tls_scan_failed", hostname=hostname, error=str(e))
        return {"protocols": {}, "weak_ciphers": [], "findings": []}
