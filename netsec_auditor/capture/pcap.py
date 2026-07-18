"""Offline PCAP analysis — host/protocol inventory plus cleartext credentials.

Reads a saved ``.pcap``/``.pcapng`` capture and produces two things:

* a passive host/protocol inventory, built by feeding every packet through the
  existing :func:`netsec_auditor.discovery.passive.handle_packet` decoder so the
  offline path yields exactly the same :class:`PassiveInventory` as live capture;
* a list of cleartext-credential findings recovered from packet payloads.

scapy is used only to parse the capture file and is imported lazily, so this
module imports without it. The credential detection lives in the pure, fully
testable :func:`scan_cleartext_credentials`, which works on raw payload bytes and
never touches scapy or the network. Every entry point degrades to an empty result
with a logged warning rather than raising — a malformed capture must never crash
the caller. Recovered secrets are always redacted before they reach a finding.
"""

from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path

from netsec_auditor.discovery.passive import PassiveInventory, handle_packet
from netsec_auditor.utils.logging import get_logger

logger = get_logger(__name__)

# A payload byte length above which usernames/communities are truncated in
# evidence, keeping findings compact and bounding any accidental disclosure.
_EVIDENCE_LIMIT = 64

# SNMP community strings that are public defaults — safe to show verbatim, since
# reporting *which* default is in use is the whole point of the finding.
_DEFAULT_SNMP_COMMUNITIES = frozenset({"public", "private"})

# HTTP Basic auth: "Authorization: Basic <base64(user:pass)>".
_HTTP_BASIC_RE = re.compile(
    rb"authorization:[ \t]*basic[ \t]+([A-Za-z0-9+/=]+)", re.IGNORECASE
)
# FTP/POP3 credential commands, one per line.
_USER_RE = re.compile(rb"^[ \t]*USER[ \t]+([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
_PASS_RE = re.compile(rb"^[ \t]*PASS[ \t]+[^\r\n]+", re.IGNORECASE | re.MULTILINE)
# IMAP: "<tag> LOGIN <user> <pass>".
_IMAP_LOGIN_RE = re.compile(rb"\bLOGIN[ \t]+(\S+)[ \t]+(\S+)", re.IGNORECASE)
# SMTP SASL: "AUTH PLAIN <base64>" carries creds inline; "AUTH LOGIN" prompts.
_SMTP_AUTH_PLAIN_RE = re.compile(
    rb"\bAUTH[ \t]+PLAIN[ \t]+([A-Za-z0-9+/=]{4,})", re.IGNORECASE
)
_SMTP_AUTH_LOGIN_RE = re.compile(rb"\bAUTH[ \t]+LOGIN", re.IGNORECASE)
# Telnet is fully cleartext; a login/password prompt is a reliable best-effort tell.
_TELNET_RE = re.compile(rb"(?:login|password|username)[ \t]*:", re.IGNORECASE)


# Reading the capture (lazy scapy)
def _read_packets(path: Path) -> object | None:
    """Read a capture file into a scapy ``PacketList``, or ``None`` on failure.

    scapy is imported here so the module loads without it. Returns ``None`` (with
    a clear warning) when scapy is missing or the file cannot be read/parsed, so
    callers can degrade to an empty result instead of raising.
    """
    try:
        from scapy.all import rdpcap
    except ImportError:
        logger.warning(
            "pcap_scapy_unavailable",
            reason="scapy_not_installed",
            hint="pip install scapy",
        )
        return None
    try:
        return rdpcap(str(path))
    except Exception as exc:  # scapy raises many parse/IO errors; degrade safely
        logger.warning("pcap_read_failed", path=str(path), error=str(exc))
        return None


def load_pcap(path: Path) -> PassiveInventory:
    """Read a capture file and fold every packet into a :class:`PassiveInventory`.

    Reuses the live-capture decoder (:func:`handle_packet`) so an offline capture
    produces the same inventory as sniffing would. Never raises: a missing scapy,
    an unreadable file, or a malformed packet yields an empty (or partial)
    inventory with a logged warning.
    """
    inventory = PassiveInventory()
    packets = _read_packets(path)
    if packets is None:
        return inventory
    for pkt in packets:
        handle_packet(inventory, pkt)
    logger.info("pcap_loaded", path=str(path), hosts=len(inventory))
    return inventory


def _records_from_packet(pkt: object) -> list[tuple[str, str, int, bytes]]:
    """Extract a ``(src_ip, dst_ip, dst_port, payload)`` record from a scapy packet.

    A thin scapy adapter: returns one record when the packet carries an IP layer,
    a TCP/UDP layer and a non-empty ``Raw`` payload, else an empty list. scapy is
    imported lazily and any decode error is swallowed, so a single bad packet
    never interrupts the credential pass.
    """
    try:
        from scapy.all import IP, TCP, UDP, IPv6, Raw
    except ImportError:
        return []
    try:
        if not pkt.haslayer(Raw):
            return []
        payload = bytes(pkt[Raw].load)
        if not payload:
            return []
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
        elif pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]
        else:
            return []
        if pkt.haslayer(TCP):
            dst_port = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            dst_port = int(pkt[UDP].dport)
        else:
            return []
        return [(str(ip_layer.src), str(ip_layer.dst), dst_port, payload)]
    except Exception:  # defensive: a malformed packet must not stop analysis
        return []


def analyze_pcap(path: Path) -> dict:
    """Analyze a capture: host inventory, cleartext credentials and packet count.

    Makes a single pass over the capture, folding each packet into a
    :class:`PassiveInventory` (as :func:`load_pcap` does) while collecting
    ``(src, dst, port, payload)`` records for :func:`scan_cleartext_credentials`.
    Returns ``{"hosts", "credentials", "packet_count"}`` and never raises — a
    missing scapy or unreadable file yields an empty, well-formed result.
    """
    inventory = PassiveInventory()
    records: list[tuple[str, str, int, bytes]] = []
    packet_count = 0

    packets = _read_packets(path)
    if packets is not None:
        for pkt in packets:
            packet_count += 1
            handle_packet(inventory, pkt)
            records.extend(_records_from_packet(pkt))

    credentials = scan_cleartext_credentials(records)
    logger.info(
        "pcap_analyzed",
        path=str(path),
        packets=packet_count,
        hosts=len(inventory),
        credentials=len(credentials),
    )
    return {
        "hosts": inventory.hosts(),
        "credentials": credentials,
        "packet_count": packet_count,
    }


# Cleartext-credential detection (pure, no scapy)
def scan_cleartext_credentials(
    records: list[tuple[str, str, int, bytes]],
) -> list[dict]:
    """Scan ``(src_ip, dst_ip, dst_port, payload)`` records for cleartext secrets.

    Pure and defensive: inspects only the payload bytes and the destination port
    (the client -> server direction, where credentials are submitted) and returns
    findings shaped ``{"protocol", "host", "port", "evidence", "severity"}``.
    Passwords are always redacted — no finding ever contains a recovered
    password, base64 blob or non-default community string in the clear. Malformed
    records are skipped rather than raising.
    """
    findings: list[dict] = []
    for record in records:
        try:
            src_ip, dst_ip, dst_port, payload = record
            port = int(dst_port)
            data = bytes(payload)
        except (TypeError, ValueError):
            continue
        if not data:
            continue
        findings.extend(_scan_record(dst_ip, port, data))
    return findings


def _scan_record(host: str, port: int, payload: bytes) -> list[dict]:
    """Run every applicable detector against one payload for a server ``host:port``."""
    findings: list[dict] = []
    findings.extend(_scan_http_basic(host, port, payload))
    if port == 21:
        findings.extend(_scan_user_pass("ftp", host, port, payload))
    elif port == 23:
        findings.extend(_scan_telnet(host, port, payload))
    elif port in (25, 587):
        findings.extend(_scan_smtp(host, port, payload))
    elif port == 110:
        findings.extend(_scan_user_pass("pop3", host, port, payload))
    elif port == 143:
        findings.extend(_scan_imap(host, port, payload))
    elif port in (161, 162):
        findings.extend(_scan_snmp(host, port, payload))
    return findings


def _finding(protocol: str, host: str, port: int, evidence: str, severity: str) -> dict:
    """Build a finding record with a consistent shape."""
    return {
        "protocol": protocol,
        "host": host,
        "port": port,
        "evidence": evidence,
        "severity": severity,
    }


def _sanitize(text: str, limit: int = _EVIDENCE_LIMIT) -> str:
    """Reduce ``text`` to a short, printable token safe to embed in evidence.

    Strips surrounding quotes/whitespace, drops non-printable characters (so a
    crafted username cannot inject control sequences into logs/terminals) and
    truncates. Usernames are shown; this never handles a password.
    """
    text = text.strip().strip('"').strip("'")
    text = "".join(ch for ch in text if ch.isprintable())
    return f"{text[:limit]}..." if len(text) > limit else text


def _sanitize_bytes(raw: bytes, limit: int = _EVIDENCE_LIMIT) -> str:
    """:func:`_sanitize` for a raw byte token (decoded permissively)."""
    return _sanitize(raw.decode("latin-1", "replace"), limit)


def _b64decode(token: bytes) -> bytes | None:
    """Strictly base64-decode ``token``; ``None`` if it is not valid base64."""
    try:
        return base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return None


def _scan_http_basic(host: str, port: int, payload: bytes) -> list[dict]:
    """Detect ``Authorization: Basic`` headers, showing the user and redacting the password."""
    match = _HTTP_BASIC_RE.search(payload)
    if match is None:
        return []
    decoded = _b64decode(match.group(1))
    if decoded is None:
        evidence = "HTTP Basic auth (unparsable credentials) [redacted]"
    else:
        user, sep, _password = decoded.decode("latin-1", "replace").partition(":")
        who = _sanitize(user) if sep else ""
        evidence = f"HTTP Basic auth {who}:***" if who else "HTTP Basic auth [redacted]"
    return [_finding("http", host, port, evidence, "high")]


def _scan_user_pass(protocol: str, host: str, port: int, payload: bytes) -> list[dict]:
    """Detect line-based ``USER``/``PASS`` auth (FTP, POP3); password redacted."""
    findings: list[dict] = []
    label = protocol.upper()
    user_match = _USER_RE.search(payload)
    if user_match is not None:
        username = _sanitize_bytes(user_match.group(1))
        evidence = f"{label} USER {username}" if username else f"{label} USER [redacted]"
        findings.append(_finding(protocol, host, port, evidence, "medium"))
    if _PASS_RE.search(payload) is not None:
        findings.append(_finding(protocol, host, port, f"{label} PASS ***", "high"))
    return findings


def _scan_telnet(host: str, port: int, payload: bytes) -> list[dict]:
    """Best-effort telnet tell: flag an observed cleartext login/password prompt."""
    if _TELNET_RE.search(payload) is None:
        return []
    evidence = "Telnet cleartext authentication observed (login/password prompt)"
    return [_finding("telnet", host, port, evidence, "medium")]


def _scan_imap(host: str, port: int, payload: bytes) -> list[dict]:
    """Detect an IMAP ``LOGIN`` command, showing the user and redacting the password."""
    match = _IMAP_LOGIN_RE.search(payload)
    if match is None:
        return []
    username = _sanitize_bytes(match.group(1))
    evidence = f"IMAP LOGIN {username} ***" if username else "IMAP LOGIN [redacted]"
    return [_finding("imap", host, port, evidence, "high")]


def _scan_smtp(host: str, port: int, payload: bytes) -> list[dict]:
    """Detect SMTP SASL auth (``AUTH PLAIN``/``AUTH LOGIN``); password redacted."""
    plain = _SMTP_AUTH_PLAIN_RE.search(payload)
    if plain is not None:
        username = ""
        decoded = _b64decode(plain.group(1))
        if decoded is not None:
            parts = decoded.split(b"\x00")
            if len(parts) >= 3:  # authzid \0 authcid \0 passwd
                username = _sanitize_bytes(parts[1])
        evidence = (
            f"SMTP AUTH PLAIN {username} ***" if username else "SMTP AUTH PLAIN ***"
        )
        return [_finding("smtp", host, port, evidence, "medium")]
    if _SMTP_AUTH_LOGIN_RE.search(payload) is not None:
        return [_finding("smtp", host, port, "SMTP AUTH LOGIN ***", "medium")]
    return []


def _read_ber_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one BER TLV at ``offset``; returns ``(tag, value, next_offset)``."""
    tag = data[offset]
    length = data[offset + 1]
    pos = offset + 2
    if length & 0x80:  # long-form length
        num = length & 0x7F
        length = int.from_bytes(data[pos:pos + num], "big")
        pos += num
    return tag, data[pos:pos + length], pos + length


def _snmp_community(payload: bytes) -> str | None:
    """Best-effort recovery of the SNMP v1/v2c community octet-string.

    The community is the second field of the top-level SEQUENCE, right after the
    version INTEGER. Returns the printable community, or ``None`` when the bytes
    are not a plausible SNMP message.
    """
    if len(payload) < 2 or payload[0] != 0x30:  # top-level SEQUENCE
        return None
    try:
        tag, message, _ = _read_ber_tlv(payload, 0)
        if tag != 0x30:
            return None
        version_tag, _, pos = _read_ber_tlv(message, 0)
        if version_tag != 0x02:  # version INTEGER
            return None
        community_tag, community, _ = _read_ber_tlv(message, pos)
        if community_tag != 0x04:  # community OCTET STRING
            return None
    except (IndexError, ValueError):
        return None
    text = community.decode("latin-1", "replace")
    if not text or not text.isprintable():
        return None
    return text


def _scan_snmp(host: str, port: int, payload: bytes) -> list[dict]:
    """Detect a cleartext SNMP community string; default communities shown, others redacted."""
    community = _snmp_community(payload)
    if community is None:
        return []
    if community in _DEFAULT_SNMP_COMMUNITIES:
        shown = community
        severity = "medium" if community == "private" else "low"
    else:
        shown = f"{community[:1]}***"  # redact a custom (secret) community
        severity = "low"
    evidence = f"SNMP community string in cleartext: {shown}"
    return [_finding("snmp", host, port, evidence, severity)]
