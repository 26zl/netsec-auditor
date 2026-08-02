"""SMB/CIFS read-only identification probe (port 445).

Fingerprints an SMB service using a single NEGOTIATE exchange per dialect family.
It reveals three things auditors care about:

* whether **SMBv1** is still accepted — the precondition for MS17-010/EternalBlue;
* the highest **SMB2/3 dialect** the server speaks (2.0.2 .. 3.1.1);
* the **signing posture** (enabled / required) advertised in the reply.

Everything here is strictly read-only: only NEGOTIATE_PROTOCOL requests are sent.
No SESSION_SETUP, TREE_CONNECT, authentication, or exploit traffic is ever
generated. The pure ``build_*`` / ``parse_*`` helpers are unit-testable without a
live host; ``probe_smb`` performs the I/O and never raises.
"""

from __future__ import annotations

import secrets
import struct

from netsec_auditor.protocols.base import ProbeResult, ProbeSpec, tcp_request

SMB_PORT = 445

# SMBv1 dialect strings offered by the classic ``smb-protocols`` / MS17-010 probe.
_SMB1_DIALECTS = (
    "PC NETWORK PROGRAM 1.0",
    "LANMAN1.0",
    "Windows for Workgroups 3.1a",
    "LM1.2X002",
    "LANMAN2.1",
    "NT LM 0.12",
)

# SMB2/3 dialect revisions offered in the SMB2 NEGOTIATE (2.0.2 .. 3.1.1).
_SMB2_DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
_SMB2_DIALECT_NAMES = {
    0x0202: "2.0.2",
    0x0210: "2.1",
    0x0300: "3.0",
    0x0302: "3.0.2",
    0x0311: "3.1.1",
    0x02FF: "2.wildcard",  # server asks for a second negotiate (SMB 2.???)
}

# 16-byte client identifier sent as the SMB2 ClientGuid (read-only probe).
_SMB2_CLIENT_GUID = b"netsec-auditor!!"

# SecurityMode signing bits: SMB2 uses 0x01/0x02, SMB1 uses 0x04/0x08.
_SMB2_SIGNING_ENABLED = 0x01
_SMB2_SIGNING_REQUIRED = 0x02
_SMB1_SIGNING_ENABLED = 0x04
_SMB1_SIGNING_REQUIRED = 0x08


# Framing helpers


def _netbios_session(payload: bytes) -> bytes:
    """Wrap an SMB message in a NetBIOS Session Service header."""
    # Byte 0 = message type 0x00 (session message); bytes 1-3 = 24-bit big-endian length.
    return bytes([0x00]) + len(payload).to_bytes(3, "big") + payload


def netbios_frame_length(data: bytes) -> int | None:
    """Total NetBIOS session frame size: 4-byte header + its 24-bit length field."""
    if len(data) < 4:
        return None
    return 4 + int.from_bytes(data[1:4], "big")


def _smb2_header(command: int, message_id: int = 0) -> bytes:
    """Build the fixed 64-byte SMB2 synchronous request header."""
    return struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",   # ProtocolId (0xFE 'SMB')
        64,           # StructureSize (always 64)
        0,            # CreditCharge
        0,            # Status (request: ChannelSequence/Reserved)
        command,      # Command
        0,            # CreditRequest
        0,            # Flags
        0,            # NextCommand (no compounding)
        message_id,   # MessageId
        0,            # Reserved (ProcessId)
        0,            # TreeId
        0,            # SessionId
        b"\x00" * 16,  # Signature
    )


def _smb2_context(ctx_type: int, data: bytes) -> bytes:
    """Encode one SMB2 negotiate context."""
    # Header: ContextType, DataLength, 4 reserved bytes, then the type-specific data.
    return struct.pack("<HHI", ctx_type, len(data), 0) + data


def _smb2_negotiate_contexts() -> tuple[bytes, int]:
    """Return (context list bytes, context count) required to offer SMB 3.1.1."""
    # Preauth integrity (mandatory for 3.1.1): 1 hash algorithm = SHA-512, 32-byte salt.
    # The salt is random rather than constant so the probe leaves no static wire
    # fingerprint; no session is established, so its value is never used.
    preauth = struct.pack("<HHH", 1, 32, 0x0001) + secrets.token_bytes(32)
    # Encryption capabilities: offer AES-128-CCM (0x0001) and AES-128-GCM (0x0002).
    encryption = struct.pack("<HHH", 2, 0x0001, 0x0002)
    ctx1 = _smb2_context(0x0001, preauth)  # SMB2_PREAUTH_INTEGRITY_CAPABILITIES
    ctx2 = _smb2_context(0x0002, encryption)  # SMB2_ENCRYPTION_CAPABILITIES
    between = b"\x00" * (-len(ctx1) % 8)  # 8-byte align before the next context
    return ctx1 + between + ctx2, 2


# Request builders


def build_smb1_negotiate() -> bytes:
    """Build an SMBv1 NEGOTIATE PROTOCOL REQUEST offering the legacy dialects."""
    header = struct.pack(
        "<4sBIBHH8sHHHHH",
        b"\xffSMB",   # protocol id (0xFF 'SMB')
        0x72,         # command: SMB_COM_NEGOTIATE
        0x00000000,   # NT status
        0x18,         # flags (case-insensitive | canonical paths)
        0xC853,       # flags2 (unicode | NT status | extended security | long names)
        0x0000,       # PID high
        b"\x00" * 8,  # security signature
        0x0000,       # reserved
        0x0000,       # tree id
        0xFEFF,       # process id
        0x0000,       # user id
        0x0000,       # multiplex id
    )
    # Each dialect entry: 0x02 buffer format, ASCII name, NUL terminator.
    dialects = b"".join(b"\x02" + name.encode("ascii") + b"\x00" for name in _SMB1_DIALECTS)
    # Body: WordCount 0, ByteCount, then the dialect list.
    body = header + bytes([0x00]) + struct.pack("<H", len(dialects)) + dialects
    return _netbios_session(body)


def build_smb2_negotiate() -> bytes:
    """Build an SMB2 NEGOTIATE offering dialects 2.0.2 .. 3.1.1 with 3.1.1 contexts."""
    header = _smb2_header(0x0000)  # command 0x0000 = NEGOTIATE
    dialects = b"".join(struct.pack("<H", d) for d in _SMB2_DIALECTS)
    # Fixed part of the NEGOTIATE request (StructureSize is the constant 36).
    fixed = struct.pack(
        "<HHHHI16s",
        36,                     # StructureSize
        len(_SMB2_DIALECTS),    # DialectCount
        _SMB2_SIGNING_ENABLED,  # SecurityMode: client can sign
        0,                      # Reserved
        0,                      # Capabilities
        _SMB2_CLIENT_GUID,      # ClientGuid
    )
    contexts, ctx_count = _smb2_negotiate_contexts()
    # NegotiateContextList is 8-byte aligned, measured from the SMB2 header start.
    after_dialects = len(header) + len(fixed) + 8 + len(dialects)
    ctx_offset = (after_dialects + 7) & ~7
    pad = b"\x00" * (ctx_offset - after_dialects)
    # The 8-byte slot after ClientGuid carries the context offset/count for 3.1.1.
    ctx_fields = struct.pack("<IHH", ctx_offset, ctx_count, 0)
    body = fixed + ctx_fields + dialects + pad + contexts
    return _netbios_session(header + body)


# Response parsing (pure)


def _strip_netbios(data: bytes) -> bytes:
    """Drop a leading NetBIOS session header so a bare SMB message remains."""
    if data[:4] in (b"\xffSMB", b"\xfeSMB"):
        return data
    if len(data) >= 8 and data[4:8] in (b"\xffSMB", b"\xfeSMB"):
        return data[4:]
    return data


def _parse_smb2_negotiate(data: bytes) -> dict[str, str]:
    """Extract dialect and signing flags from an SMB2 NEGOTIATE response."""
    info: dict[str, str] = {"smb2_supported": "true"}
    body = data[64:]  # skip the 64-byte SMB2 header
    if len(body) < 6:
        return info
    struct_size, security_mode, dialect = struct.unpack_from("<HHH", body, 0)
    if struct_size != 65:  # 0x0041 marks a NEGOTIATE response; else it is an error/other
        return info
    info["dialect_hex"] = f"0x{dialect:04x}"
    name = _SMB2_DIALECT_NAMES.get(dialect)
    if name:
        info["dialect"] = name
    info["signing_enabled"] = "true" if security_mode & _SMB2_SIGNING_ENABLED else "false"
    info["signing_required"] = "true" if security_mode & _SMB2_SIGNING_REQUIRED else "false"
    return info


def _parse_smb1_negotiate(data: bytes) -> dict[str, str]:
    """Note SMBv1 support and, when present, the SMB1 signing flags.

    A host with SMB1 disabled still answers with an ``\\xffSMB`` header, so support
    is only claimed once the server actually negotiated a dialect — otherwise the
    EternalBlue precondition would fire on a hardened host.
    """
    info: dict[str, str] = {}
    if len(data) < 33:  # 32-byte header + WordCount byte
        return info
    word_count = data[32]
    words = data[33:33 + word_count * 2]
    if data[4] == 0x72 and word_count >= 17 and len(words) >= 3:
        # NT LM 0.12 response: DialectIndex (2 bytes) then a 1-byte SecurityMode.
        dialect_index = struct.unpack_from("<H", words, 0)[0]
        security_mode = words[2]
        if dialect_index != 0xFFFF and dialect_index < len(_SMB1_DIALECTS):
            info["smbv1_supported"] = "true"
            info["dialect"] = _SMB1_DIALECTS[dialect_index]
        else:
            info["dialect"] = "none"  # server accepted none of the offered dialects
        info["signing_enabled"] = "true" if security_mode & _SMB1_SIGNING_ENABLED else "false"
        info["signing_required"] = "true" if security_mode & _SMB1_SIGNING_REQUIRED else "false"
    return info


def parse_smb_negotiate_response(data: bytes) -> dict[str, str]:
    """Parse an SMB1 or SMB2 negotiate reply into device-info fields; {} if neither."""
    if not data:
        return {}
    payload = _strip_netbios(data)
    if payload[:4] == b"\xfeSMB":
        return _parse_smb2_negotiate(payload)
    if payload[:4] == b"\xffSMB":
        return _parse_smb1_negotiate(payload)
    return {}


# Probe


async def _negotiate(host: str, port: int, payload: bytes, timeout: float) -> dict[str, str]:
    """Send one negotiate and parse the reply; returns {} on any failure (never raises)."""
    try:
        reply = await tcp_request(
            host, port, payload, timeout, frame_length=netbios_frame_length
        )
    except Exception:
        return {}
    if not reply:
        return {}
    return parse_smb_negotiate_response(reply)


async def probe_smb(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Identify SMB dialects and signing posture via read-only NEGOTIATE requests.

    The SMBv1 negotiate is sent first: an ``\\xffSMB`` reply proves SMBv1 is
    enabled (the MS17-010/EternalBlue precondition). The SMB2/3 negotiate then
    reveals the highest dialect and signing posture. Only NEGOTIATE is ever sent
    -- never SESSION_SETUP or TREE_CONNECT. Returns None if neither replies.
    """
    smb1 = await _negotiate(host, port, build_smb1_negotiate(), timeout)
    smb2 = await _negotiate(host, port, build_smb2_negotiate(), timeout)
    if not smb1 and not smb2:
        return None

    device_info: dict[str, str] = {}
    extra: dict[str, object] = {}
    versions: list[str] = []

    if smb1.get("smbv1_supported") == "true":
        versions.append("SMBv1")
        device_info["smbv1_supported"] = "true"  # evidence note; caller flags EternalBlue
        extra["smbv1_supported"] = True
        extra["ms17_010_precondition"] = True
        if "signing_required" in smb1:
            device_info["smb1_signing_required"] = smb1["signing_required"]

    if smb2.get("smb2_supported") == "true":
        versions.append("SMB2+")
        device_info["smb2_supported"] = "true"

    dialect = smb2.get("dialect") or smb1.get("dialect", "")
    if dialect:
        device_info["dialect"] = dialect
    if "dialect_hex" in smb2:
        device_info["dialect_revision"] = smb2["dialect_hex"]

    # Signing posture: prefer the SMB2/3 answer (modern default), else the SMB1 one.
    signing = smb2 if "signing_required" in smb2 else smb1
    for key in ("signing_required", "signing_enabled"):
        if key in signing:
            device_info[key] = signing[key]

    banner = " ".join(versions)
    if dialect:
        banner = f"{banner} dialect {dialect}".strip()

    return ProbeResult(
        protocol="smb",
        port=port,
        transport="tcp",
        is_ot=False,
        device_info=device_info,
        banner=banner.strip(),
        extra=extra,
    )


SPECS: list[ProbeSpec] = [
    ProbeSpec(name="smb", default_port=SMB_PORT, transport="tcp", is_ot=False, probe=probe_smb),
]
