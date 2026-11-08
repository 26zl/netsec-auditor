"""Optional nmap NSE (Nmap Scripting Engine) integration.

When the ``nmap`` binary is present, this module runs a *curated* set of
read-only / safe NSE scripts to obtain deeper, authoritative results that
corroborate the toolkit's own native probes (TLS, SMB, SNMP, ICS/OT, banners).
It is strictly optional: :func:`nse_available` reports whether nmap is on
``PATH`` and every entry point degrades to an empty result when it is not.

Design notes:

* The only external process invoked is ``nmap`` with ``-oX -`` (XML to stdout).
* No script here performs brute-force, DoS, or exploitation; ``smb-vuln-ms17-010``
  is categorized ``safe`` and only detects. Note that ``modbus-discover`` and
  ``ssl-enum-ciphers`` carry nmap's ``intrusive`` category, and the ICS scripts are
  ``discovery``/``version`` rather than ``safe`` — the ICS set sends protocol
  requests to PLCs and should be run only when that is acceptable.
* :func:`parse_nmap_xml` and :func:`summarize_findings` are pure and unit-testable
  without a network or the nmap binary; they are the testable core.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import shutil
import xml.etree.ElementTree as ET
from collections.abc import Collection, Iterable
from typing import Any, cast

from defusedxml.ElementTree import DefusedXMLParser

from netsec_auditor.utils.logging import get_logger

logger = get_logger(__name__)

# Curated, read-only/safe script sets grouped by the probe they corroborate.
TLS_SCRIPTS = ["ssl-enum-ciphers", "ssl-cert"]
SMB_SCRIPTS = [
    "smb-protocols",
    "smb-security-mode",
    "smb2-security-mode",
    "smb-os-discovery",
    "smb-vuln-ms17-010",  # officially categorized safe DETECTION (no exploitation)
]
SNMP_SCRIPTS = ["snmp-info", "snmp-sysdescr"]
# iec-identify, iec61850-mms and hartip-info stay out: nmap classes them intrusive
# (iec-identify activates data transfer on the RTU).
ICS_SCRIPTS = [
    "modbus-discover",
    "s7-info",
    "bacnet-info",
    "enip-info",
    "omron-info",
    "fox-info",
    "knx-gateway-info",
    "pcworx-info",
]
DISCOVERY_SCRIPTS = ["banner", "http-title"]

# Public name -> curated script list (drives run_script_set and the CLI wiring).
SCRIPT_SETS: dict[str, list[str]] = {
    "tls": TLS_SCRIPTS,
    "smb": SMB_SCRIPTS,
    "snmp": SNMP_SCRIPTS,
    "ics": ICS_SCRIPTS,
    "discovery": DISCOVERY_SCRIPTS,
}

# Ports each set needs: the TCP ports kept from a host's open ports (None keeps all of
# them) and the UDP ports, which nmap can only scan with root.
SET_PORTS: dict[str, tuple[frozenset[int] | None, frozenset[int]]] = {
    "tls": (None, frozenset()),
    "smb": (frozenset({139, 445}), frozenset()),
    "snmp": (frozenset(), frozenset({161})),
    "ics": (
        frozenset({102, 502, 1911, 1962, 4911, 9600, 44818}),
        frozenset({3671, 47808}),
    ),
    "discovery": (None, frozenset()),
}

# Data-driven heuristics: (script_id, keyword, severity, name). Matching is a
# case-insensitive substring test against a script's textual output; every rule
# that matches a finding yields one normalized finding.
SUMMARY_RULES: list[tuple[str, str, str, str]] = [
    ("smb-vuln-ms17-010", "VULNERABLE", "critical", "MS17-010 (EternalBlue) vulnerable"),
    ("smb-protocols", "SMBv1", "high", "SMBv1 (CIFS) protocol enabled"),
    ("ssl-enum-ciphers", "SSLv3", "high", "Obsolete SSLv3 offered"),
    ("ssl-enum-ciphers", "RC4", "high", "Weak RC4 cipher offered"),
    ("ssl-enum-ciphers", "TLSv1.0", "medium", "Deprecated TLS 1.0 offered"),
    ("ssl-enum-ciphers", "weak", "medium", "Weak TLS ciphers offered"),
]

# Per-script remediation copy for normalized findings.
_REMEDIATION: dict[str, str] = {
    "smb-vuln-ms17-010": "Apply MS17-010, disable SMBv1, and restrict SMB (445) exposure.",
    "smb-protocols": "Disable SMBv1 (CIFS); require SMBv2/3 with signing enforced.",
    "ssl-enum-ciphers": "Disable SSLv3/TLS 1.0 and weak ciphers (RC4); require TLS 1.2+ AEAD.",
}
_DEFAULT_REMEDIATION = "Review the NSE output and remediate per vendor guidance."


# Callers may only soften pacing; anything else (notably --script) would void the
# read-only guarantee the curated script sets provide.
_PACING_ARG_RE = re.compile(
    r"-T[0-5]|--host-timeout=\S+|--max-retries=\d+|--scan-delay=\S+|--min-rate=\d+"
    r"|--max-rate=\d+|--max-parallelism=\d+"
)


def nse_available() -> bool:
    """Return True if the ``nmap`` binary is on ``PATH``."""
    return shutil.which("nmap") is not None


def port_spec(
    set_name: str,
    open_tcp: Iterable[int],
    *,
    udp: bool,
    allowed: Collection[int] | None = None,
) -> str:
    """Return the ``-p`` value for one set on one host ('' when nothing applies).

    TCP ports come from what the scan found open, so NSE never runs its own port
    discovery; UDP ports are added only when a UDP scan is possible.
    """
    tcp_filter, udp_ports = SET_PORTS.get(set_name, (None, frozenset()))
    tcp = sorted(p for p in set(open_tcp) if tcp_filter is None or p in tcp_filter)
    udp_list = sorted(udp_ports) if udp else []
    if allowed is not None:
        tcp = [p for p in tcp if p in allowed]
        udp_list = [p for p in udp_list if p in allowed]
    return ",".join([f"T:{p}" for p in tcp] + [f"U:{p}" for p in udp_list])


def build_nmap_command(
    target: str,
    scripts: list[str],
    ports: str | None = None,
    extra_args: list[str] | None = None,
) -> list[str]:
    """Build the argv for ``nmap -Pn --script ... [-p ...] -oX - <target>``."""
    cmd = ["nmap", "-Pn", "--script", ",".join(scripts)]
    if ports:
        if "U:" in ports:
            # UDP ports need -sU (root); TCP ports alongside them then need -sS too.
            cmd += ["-sU", "-sS"] if "T:" in ports else ["-sU"]
        cmd += ["-p", ports]
    for arg in extra_args or []:
        if _PACING_ARG_RE.fullmatch(arg):
            cmd.append(arg)
        else:
            logger.warning("nse_extra_arg_rejected", arg=arg)
    # "--" stops option parsing so a target beginning with "-" cannot become a flag.
    cmd += ["-oX", "-", "--", target]
    return cmd


async def _run_nmap(cmd: list[str], timeout: float) -> str:
    """Run nmap and return its stdout (XML), or '' on failure/timeout."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(Exception):  # reap the killed child
            await proc.wait()
        logger.warning("nse_timeout", timeout=timeout)
        return ""
    # A bad script name makes nmap abort before scanning; without this the caller
    # cannot tell "nothing found" from "never ran".
    if proc.returncode != 0:
        detail = stderr.decode("utf-8", "replace").strip().splitlines()
        logger.warning(
            "nse_failed", returncode=proc.returncode, error=detail[-1] if detail else "",
        )
        return ""
    return stdout.decode("utf-8", "replace")


async def run_nse(
    target: str,
    scripts: list[str],
    ports: str | None = None,
    timeout: float = 120.0,
    extra_args: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Run curated NSE scripts against ``target`` and return parsed findings.

    Returns ``[]`` when nmap is absent, no scripts are requested, or on any
    error — this function never raises.
    """
    if not scripts:
        return []
    if not nse_available():
        logger.debug("nse_unavailable", target=target)
        return []
    cmd = build_nmap_command(target, scripts, ports, extra_args)
    logger.debug("nse_run", command=" ".join(cmd))
    try:
        xml_text = await _run_nmap(cmd, timeout)
    except Exception as exc:  # never raise — the integration is best-effort
        logger.debug("nse_run_failed", target=target, error=str(exc))
        return []
    return parse_nmap_xml(xml_text)


async def run_script_set(
    target: str,
    set_name: str,
    ports: str | None = None,
    timeout: float = 120.0,
    extra_args: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Run a named curated set from :data:`SCRIPT_SETS` (``[]`` if unknown)."""
    scripts = SCRIPT_SETS.get(set_name)
    if not scripts:
        logger.debug("nse_unknown_script_set", set_name=set_name)
        return []
    return await run_nse(target, scripts, ports=ports, timeout=timeout, extra_args=extra_args)


def _host_address(host: ET.Element) -> str:
    """Return the host's IPv4/IPv6 address (falling back to the first address)."""
    addresses = host.findall("./address")
    for addr in addresses:
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            return addr.get("addr", "")
    return addresses[0].get("addr", "") if addresses else ""


def _script_finding(
    host: str, port: int | None, protocol: str, script: ET.Element
) -> dict[str, Any]:
    """Build one raw finding record from a ``<script>`` element."""
    return {
        "host": host,
        "port": port,
        "protocol": protocol,
        "script_id": script.get("id", ""),
        "output": (script.get("output") or "").strip(),
    }


def _parse_host(host: ET.Element) -> list[dict[str, Any]]:
    """Extract host-level and port-level script outputs from a ``<host>``."""
    ip = _host_address(host)
    findings: list[dict[str, Any]] = []
    # Host-level scripts: <hostscript><script id=.. output=..>
    for script in host.findall("./hostscript/script"):
        findings.append(_script_finding(ip, None, "", script))
    # Port-level scripts: <ports><port protocol=.. portid=..><script ..>
    for port in host.findall("./ports/port"):
        portid = port.get("portid", "")
        protocol = port.get("protocol", "")
        port_num = int(portid) if portid.isdigit() else None
        for script in port.findall("./script"):
            findings.append(_script_finding(ip, port_num, protocol, script))
    return findings


def parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
    """Parse nmap ``-oX`` XML into one finding dict per script output.

    Each finding is ``{"host", "port", "protocol", "script_id", "output"}``.
    Handles both host-level ``<hostscript>`` and port-level ``<port>`` scripts,
    and tolerates truncated/malformed XML by returning whatever fully parsed.
    """
    findings: list[dict[str, Any]] = []
    if not xml_text or not xml_text.strip():
        return findings
    # A pull parser lets us keep complete <host> subtrees even if the tail is
    # truncated — ParseError is swallowed so we never raise on bad input.
    # nmap emits a plain <!DOCTYPE nmaprun>, so the DTD itself is allowed; entity
    # definitions are not, which blocks billion-laughs / XXE in a saved XML file.
    parser = ET.XMLPullParser(
        ["end"],
        _parser=DefusedXMLParser(forbid_dtd=False, forbid_entities=True, forbid_external=True),
    )
    with contextlib.suppress(ET.ParseError):
        parser.feed(xml_text)
    with contextlib.suppress(ET.ParseError):
        for event in parser.read_events():
            # defusedxml builds pure-Python elements, so match on the tag, not the C class.
            elem = event[-1]
            if getattr(elem, "tag", None) == "host":
                findings.extend(_parse_host(cast(ET.Element, elem)))
    return findings


def _normalize(finding: dict[str, Any], severity: str, name: str) -> dict[str, Any]:
    """Turn a raw finding into a normalized, five-key finding with context."""
    script_id = finding.get("script_id", "")
    return {
        "name": name,
        "severity": severity,
        "description": f"nmap NSE script '{script_id}' indicates: {name}.",
        "evidence": str(finding.get("output", ""))[:500],
        "remediation": _REMEDIATION.get(script_id, _DEFAULT_REMEDIATION),
        "host": finding.get("host", ""),
        "port": finding.get("port"),
        "script_id": script_id,
        "source": "nmap-nse",
    }


def summarize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Apply :data:`SUMMARY_RULES` to raw findings, yielding normalized findings."""
    summary: list[dict[str, Any]] = []
    for finding in findings:
        script_id = finding.get("script_id", "")
        output_upper = str(finding.get("output", "")).upper()
        for rule_id, keyword, severity, name in SUMMARY_RULES:
            if rule_id == script_id and keyword.upper() in output_upper:
                summary.append(_normalize(finding, severity, name))
    return summary


__all__ = [
    "DISCOVERY_SCRIPTS",
    "ICS_SCRIPTS",
    "SCRIPT_SETS",
    "SMB_SCRIPTS",
    "SNMP_SCRIPTS",
    "SUMMARY_RULES",
    "TLS_SCRIPTS",
    "build_nmap_command",
    "nse_available",
    "parse_nmap_xml",
    "run_nse",
    "run_script_set",
    "summarize_findings",
]
