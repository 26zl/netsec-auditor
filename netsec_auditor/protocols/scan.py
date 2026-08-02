"""Run registered read-only protocol probers against a host's open ports."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable

from netsec_auditor.profiles import Profile
from netsec_auditor.protocols import probers_for_port
from netsec_auditor.protocols.base import ProbeResult, ProbeSpec
from netsec_auditor.utils.logging import get_logger

logger = get_logger(__name__)


async def identify_services(
    host: str,
    ports: list[int],
    profile: Profile,
    timeout: float = 5.0,
    rate_per_second: float = 0.0,
    udp_ports: Iterable[int] | None = None,
) -> list[ProbeResult]:
    """Probe each open port that has a registered prober, honouring the profile.

    The OT profile forces sequential, delayed probing (max_concurrency=1,
    scan_delay set) so fragile devices are not overwhelmed. Intrusive probers are
    skipped unless the profile explicitly allows them.

    Passing ``udp_ports`` makes ``ports`` TCP-only, so a host that only has a TCP
    port open is not sent the UDP datagram of a same-port sibling spec. When it is
    omitted every transport registered on a port is probed, as before.
    """
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    if rate_per_second < 0:
        raise ValueError("rate_per_second cannot be negative")

    if udp_ports is None:
        candidates: list[tuple[int, str | None]] = [(port, None) for port in ports]
    else:
        candidates = [(port, "tcp") for port in ports]
        candidates += [(port, "udp") for port in udp_ports]
    specs: list[ProbeSpec] = [
        spec
        for port, transport in candidates
        for spec in probers_for_port(port, transport)
        if spec.is_safe or profile.allow_intrusive
    ]
    if not specs:
        return []

    semaphore = asyncio.Semaphore(max(1, profile.max_concurrency))
    rate_lock = asyncio.Lock()
    next_start = 0.0
    results: list[ProbeResult] = []

    async def _throttle() -> None:
        nonlocal next_start
        if rate_per_second <= 0:
            return
        async with rate_lock:
            now = time.monotonic()
            if next_start > now:
                await asyncio.sleep(next_start - now)
                now = time.monotonic()
            next_start = max(next_start, now) + 1.0 / rate_per_second

    async def _run(spec: ProbeSpec) -> ProbeResult | None:
        await _throttle()
        async with semaphore:
            if profile.scan_delay:
                await asyncio.sleep(profile.scan_delay)
            try:
                return await spec.probe(host, spec.default_port, timeout)
            except Exception as e:  # a probe must never abort the whole scan
                logger.debug("probe_failed", protocol=spec.name, host=host, error=str(e))
                return None

    for coro in asyncio.as_completed([_run(s) for s in specs]):
        result = await coro
        if result is not None:
            results.append(result)

    logger.info("service_identification_complete", host=host, identified=len(results))
    return results
