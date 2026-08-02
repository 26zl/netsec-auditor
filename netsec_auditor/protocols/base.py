"""Read-only protocol probe framework for IT, OT/ICS, and IoT identification.

A prober is an async callable ``probe(host, port, timeout) -> ProbeResult | None``.
Each protocol module exposes pure ``build_*``/``parse_*`` helpers (unit-testable
without a live device) and a module-level ``SPECS`` list of :class:`ProbeSpec`,
which :mod:`netsec_auditor.protocols` aggregates into a port-indexed registry.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

Prober = Callable[[str, int, float], Awaitable["ProbeResult | None"]]
# Maps the bytes received so far to the full frame size, or None while undetermined.
FrameLength = Callable[[bytes], "int | None"]


@dataclass
class ProbeResult:
    """Outcome of a single read-only protocol probe."""

    protocol: str
    port: int
    transport: str = "tcp"
    is_ot: bool = False
    device_info: dict[str, str] = field(default_factory=dict)
    banner: str = ""
    extra: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "protocol": self.protocol,
            "port": self.port,
            "transport": self.transport,
            "is_ot": self.is_ot,
            "device_info": self.device_info,
            "banner": self.banner,
            "extra": self.extra,
        }


@dataclass(frozen=True)
class ProbeSpec:
    """Registry entry binding a prober to its default port and safety metadata."""

    name: str
    default_port: int
    transport: str  # "tcp" | "udp"
    is_ot: bool
    probe: Prober
    is_safe: bool = True  # read-only identification only


_REGISTRY: dict[tuple[int, str], list[ProbeSpec]] = {}
_SPECS: list[ProbeSpec] = []


def register(specs: list[ProbeSpec]) -> None:
    """Register a module's probe specs into the (port, transport)-indexed registry."""
    for spec in specs:
        _SPECS.append(spec)
        _REGISTRY.setdefault((spec.default_port, spec.transport), []).append(spec)


def probers_for_port(port: int, transport: str | None = None) -> list[ProbeSpec]:
    """Specs bound to ``port``; ``transport`` None matches both TCP and UDP.

    Keying on the transport keeps a TCP-only open port (e.g. 44818) from also
    receiving the UDP datagram of its same-port sibling spec.
    """
    if transport is not None:
        return _REGISTRY.get((port, transport), [])
    return [s for t in ("tcp", "udp") for s in _REGISTRY.get((port, t), [])]


def all_specs() -> list[ProbeSpec]:
    return list(_SPECS)


def ot_ports() -> set[int]:
    return {s.default_port for s in _SPECS if s.is_ot}


async def read_framed(
    reader: asyncio.StreamReader,
    timeout: float,
    frame_length: FrameLength | None = None,
    recv_size: int = 4096,
) -> bytes:
    """Read until ``frame_length`` is satisfied, EOF, or ``timeout`` expires.

    A single ``StreamReader.read`` returns as soon as any bytes arrive, so a
    segmented reply would otherwise be handed to the parsers as a truncated PDU.
    Whatever arrived before the timeout is still returned; parsers reject a short
    frame themselves.
    """
    buf = bytearray()
    with contextlib.suppress(TimeoutError):
        async with asyncio.timeout(timeout):
            while True:
                chunk = await reader.read(recv_size)
                if not chunk:
                    break
                buf += chunk
                if frame_length is None:
                    break
                want = frame_length(bytes(buf))
                if want is None or len(buf) >= want:
                    break
    return bytes(buf)


async def tcp_request(
    host: str,
    port: int,
    payload: bytes,
    timeout: float,
    recv_size: int = 4096,
    frame_length: FrameLength | None = None,
) -> bytes | None:
    """Send ``payload`` over TCP and return the reply, or None.

    Without ``frame_length`` a single read is returned; with it, reads continue
    until the protocol's own length prefix is satisfied.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout
        )
    except (TimeoutError, ConnectionError, OSError):
        return None
    try:
        if payload:
            writer.write(payload)
            await writer.drain()
        return await read_framed(reader, timeout, frame_length, recv_size)
    except (TimeoutError, ConnectionError, OSError):
        return None
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError, OSError):
            await writer.wait_closed()


async def udp_request(
    host: str, port: int, payload: bytes, timeout: float
) -> bytes | None:
    """Send ``payload`` over UDP and return the first datagram received, or None."""
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[bytes] = loop.create_future()

    class _Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: object) -> None:
            if not fut.done():
                fut.set_result(data)

        def error_received(self, exc: Exception) -> None:
            if not fut.done():
                fut.set_exception(exc)

    try:
        # remote_addr triggers a getaddrinfo, so this must respect the timeout too.
        transport, _ = await asyncio.wait_for(
            loop.create_datagram_endpoint(_Proto, remote_addr=(host, port)), timeout
        )
    except (TimeoutError, OSError):
        return None
    try:
        transport.sendto(payload)
        return await asyncio.wait_for(fut, timeout)
    except (TimeoutError, OSError):
        return None
    finally:
        transport.close()
