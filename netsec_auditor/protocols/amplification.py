"""Read-only UDP amplification / reflector exposure probes.

Every probe sends a single, legitimate query to a UDP service that is commonly
abused for reflection/amplification DDoS and checks whether the service answers.
A reply means the host could be leveraged as a reflector — the finding is the
*exposure*, not any traffic we generate: we send one datagram (NTP falls back to
one extra liveness datagram if monlist is filtered) and read at most one reply.
Nothing here floods, writes, or changes device state, so it is passive- and
OT-safe.

Pure ``build_*`` request builders are unit-testable without a network; each
``probe_*`` coroutine returns a :class:`ProbeResult` when the service answers and
``None`` otherwise, and never raises. Amplification factors are the widely-cited
figures from US-CERT alert TA14-017A (memcached from later 2018 advisories).
"""

from __future__ import annotations

import struct

from netsec_auditor.protocols.base import ProbeResult, ProbeSpec, udp_request
from netsec_auditor.protocols.iot import build_ssdp_request

# Severity levels used for the reflector-exposure findings.
_HIGH = "high"
_MEDIUM = "medium"
_LOW = "low"


def _reflector_result(
    protocol: str,
    port: int,
    severity: str,
    amplification: str,
    banner: str,
    response: bytes,
    extra_info: dict[str, str] | None = None,
) -> ProbeResult:
    """Build a UDP reflector-exposure result from a service's reply."""
    info: dict[str, str] = {
        "reflector": "true",
        "amplification": amplification,
        "severity": severity,
        "response_bytes": str(len(response)),
    }
    if extra_info:
        info.update(extra_info)
    return ProbeResult(
        protocol=protocol,
        port=port,
        transport="udp",
        is_ot=False,
        device_info=info,
        banner=banner,
        extra={"reflector": True, "severity": severity},
    )


# NTP monlist (123/udp) — CVE-2013-5211, the classic amplifier

_NTP_MODE7_MON = 0x17          # response 0 | more 0 | version 2 | mode 7 (private)
_NTP_IMPL_XNTPD = 0x03         # implementation number 3 (IMPL_XNTPD)
_NTP_REQ_MON_GETLIST_1 = 0x2A  # request code 42 (REQ_MON_GETLIST_1 = monlist)
_NTP_CLIENT_V3 = 0x1B          # leap 0 | version 3 | mode 3 (client)


def build_ntp_monlist_request() -> bytes:
    r"""Build the classic NTP mode-7 MON_GETLIST_1 (monlist) request.

    Eight-byte private-mode header (all multi-byte fields big-endian)::

        byte 0    0x17    response=0, more=0, version=2, mode=7 (private)
        byte 1    0x00    auth=0, sequence=0
        byte 2    0x03    implementation = 3 (IMPL_XNTPD)
        byte 3    0x2a    request code = 42 (REQ_MON_GETLIST_1)
        bytes 4-5 0x0000  err (4 bits) + number of data items (12 bits) = 0
        bytes 6-7 0x0000  MBZ (4 bits) + size of data item (12 bits) = 0

    i.e. the well-known ``\x17\x00\x03\x2a`` followed by four zero-padding bytes.
    A server that answers has monlist enabled and can amplify traffic ~556x.
    """
    return struct.pack(
        "!BBBBHH",
        _NTP_MODE7_MON,
        0x00,
        _NTP_IMPL_XNTPD,
        _NTP_REQ_MON_GETLIST_1,
        0x0000,
        0x0000,
    )


def build_ntp_version_request() -> bytes:
    r"""Build a standard NTP mode-3 client request (48 bytes) for liveness.

    Byte 0 is ``0x1b`` (leap 0, version 3, mode 3 = client); the remaining 47
    bytes — including the transmit timestamp — are left zero. Useful when monlist
    is filtered but we still want to confirm that an NTP service is live.
    """
    return bytes([_NTP_CLIENT_V3]) + b"\x00" * 47


async def probe_ntp(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Probe NTP for monlist amplification, falling back to a liveness check."""
    try:
        data = await udp_request(host, port, build_ntp_monlist_request(), timeout)
        if data:
            return _reflector_result(
                protocol="ntp-monlist",
                port=port,
                severity=_HIGH,
                amplification="~556x",
                banner="NTP monlist enabled (CVE-2013-5211)",
                response=data,
                extra_info={"monlist_enabled": "true", "cve": "CVE-2013-5211"},
            )
        # monlist filtered: confirm the service is live with a plain client query.
        live = await udp_request(host, port, build_ntp_version_request(), timeout)
        if not live:
            return None
        return ProbeResult(
            protocol="ntp",
            port=port,
            transport="udp",
            is_ot=False,
            device_info={
                "reflector": "false",  # mode-3 reply ~= request size, no amplification
                "amplification": "~1x",
                "severity": _LOW,
                "monlist_enabled": "false",
                "response_bytes": str(len(live)),
            },
            banner="NTP reachable, monlist disabled",
        )
    except Exception:
        return None


# memcached (11211/udp) — ~50,000x, should never face the internet


def build_memcached_stats_request(request_id: int = 0x0000) -> bytes:
    r"""Build a memcached UDP ``stats`` request.

    Eight-byte UDP frame header (big-endian 16-bit fields) then the command::

        bytes 0-1  request id           (echoed back; correlation only)
        bytes 2-3  sequence number     = 0
        bytes 4-5  total datagram count = 1 (single-datagram request)
        bytes 6-7  reserved            = 0

    followed by ``b"stats\r\n"``. ``stats`` is read-only; a reply on UDP means the
    daemon faces the network and can be abused as a ~50,000x amplifier.
    """
    header = struct.pack("!HHHH", request_id & 0xFFFF, 0x0000, 0x0001, 0x0000)
    return header + b"stats\r\n"


async def probe_memcached(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Probe for a memcached daemon answering ``stats`` over UDP."""
    try:
        data = await udp_request(host, port, build_memcached_stats_request(), timeout)
        if not data:
            return None
        return _reflector_result(
            protocol="memcached",
            port=port,
            severity=_HIGH,
            amplification="~50000x",
            banner="memcached UDP stats exposed",
            response=data,
            extra_info={"command": "stats"},
        )
    except Exception:
        return None


# CharGen (19/udp) — RFC 864


def build_chargen_request() -> bytes:
    """Build a CharGen trigger: a single datagram byte.

    UDP CharGen (RFC 864) ignores the datagram's contents and replies with a line
    of characters, so one byte is enough to elicit — and detect — a reply.
    """
    return b"\x00"


async def probe_chargen(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Probe for a UDP CharGen responder (any reply confirms exposure)."""
    try:
        data = await udp_request(host, port, build_chargen_request(), timeout)
        if not data:
            return None
        return _reflector_result(
            protocol="chargen",
            port=port,
            severity=_MEDIUM,
            amplification="~358x",
            banner="CharGen UDP responder exposed",
            response=data,
        )
    except Exception:
        return None


# SSDP / UPnP (1900/udp) — reflector exposure (distinct from iot discovery)


def build_ssdp_amp_request() -> bytes:
    """Reuse the iot M-SEARCH ``ssdp:all`` request as a reflector trigger.

    Identical on the wire to :func:`netsec_auditor.protocols.iot.build_ssdp_request`
    (``M-SEARCH * HTTP/1.1`` … ``ST: ssdp:all``); the distinction is the finding —
    here a unicast reply means the host is an exploitable UPnP/SSDP reflector.
    """
    return build_ssdp_request(st="ssdp:all")


async def probe_ssdp_amp(host: str, port: int, timeout: float) -> ProbeResult | None:
    """Probe for a UPnP/SSDP reflector via a unicast M-SEARCH."""
    try:
        data = await udp_request(host, port, build_ssdp_amp_request(), timeout)
        if not data:
            return None
        return _reflector_result(
            protocol="ssdp-amp",
            port=port,
            severity=_MEDIUM,
            amplification="~30x",
            banner="SSDP/UPnP reflector exposed",
            response=data,
        )
    except Exception:
        return None


# Registry — all read-only, single-query UDP reflector-exposure probes.
# Deliberately NOT registered here (no register() call); the port-indexed
# registry already carries the iot SSDP discovery prober on 1900.

SPECS: list[ProbeSpec] = [
    ProbeSpec(
        name="ntp-monlist",
        default_port=123,
        transport="udp",
        is_ot=False,
        probe=probe_ntp,
    ),
    ProbeSpec(
        name="memcached",
        default_port=11211,
        transport="udp",
        is_ot=False,
        probe=probe_memcached,
    ),
    ProbeSpec(
        name="chargen",
        default_port=19,
        transport="udp",
        is_ot=False,
        probe=probe_chargen,
    ),
    ProbeSpec(
        name="ssdp-amp",
        default_port=1900,
        transport="udp",
        is_ot=False,
        probe=probe_ssdp_amp,
    ),
]
