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


_REGISTRY: dict[int, list[ProbeSpec]] = {}
_SPECS: list[ProbeSpec] = []


def register(specs: list[ProbeSpec]) -> None:
    """Register a module's probe specs into the port-indexed registry."""
    for spec in specs:
        _SPECS.append(spec)
        _REGISTRY.setdefault(spec.default_port, []).append(spec)


def probers_for_port(port: int) -> list[ProbeSpec]:
    return _REGISTRY.get(port, [])


def all_specs() -> list[ProbeSpec]:
    return list(_SPECS)


def ot_ports() -> set[int]:
    return {s.default_port for s in _SPECS if s.is_ot}


async def tcp_request(
    host: str, port: int, payload: bytes, timeout: float, recv_size: int = 4096
) -> bytes | None:
    """Send ``payload`` over TCP and return up to ``recv_size`` bytes, or None."""
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
        return await asyncio.wait_for(reader.read(recv_size), timeout)
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
        transport, _ = await loop.create_datagram_endpoint(
            _Proto, remote_addr=(host, port)
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
