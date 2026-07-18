"""Fast active discovery for large IP ranges.

Unprivileged TCP-connect sweeps that scale to large CIDR blocks and feed live
hosts into the detailed scanner. A host counts as alive if a probe port either
accepts the connection or actively refuses it (a refusal still proves the host
is reachable). Firewalled hosts that silently drop packets are missed by design;
run the authoritative scanner against the discovered set for full coverage.

Ranges are expanded with :mod:`ipaddress` and probed in fixed-size batches so
memory stays bounded even for very large blocks.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import time
from collections.abc import Iterable, Iterator
from typing import TypeVar

from netsec_auditor.utils.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")

# Default per-host probe ports: web, remote-admin, SMB/RDP plus a few OT/BMS
# services (Modbus 502, S7 102, BACnet 47808) so OT gear surfaces in a sweep.
DEFAULT_PROBE_PORTS: list[int] = [80, 443, 22, 445, 3389, 502, 102, 47808, 8080]

# Hosts are probed in batches of this size to bound concurrent tasks and memory.
_BATCH_SIZE = 4096
MAX_EXPANDED_TARGETS = 65_536


class TargetLimitError(ValueError):
    """Raised when local discovery would expand an unsafe number of targets."""


class _StartRateLimiter:
    def __init__(self, rate_per_second: float) -> None:
        self._interval = 1.0 / rate_per_second if rate_per_second > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def acquire(self) -> None:
        if self._interval == 0:
            return
        async with self._lock:
            now = time.monotonic()
            if self._next > now:
                await asyncio.sleep(self._next - now)
                now = time.monotonic()
            self._next = max(self._next, now) + self._interval


def batched(iterable: Iterable[T], n: int) -> Iterator[list[T]]:
    """Yield lists of up to ``n`` consecutive items from ``iterable``.

    A backport of :func:`itertools.batched` (added in 3.12) that yields lists.
    """
    if n < 1:
        raise ValueError("n must be at least 1")
    batch: list[T] = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= n:
            yield batch
            batch = []
    if batch:
        yield batch


def _ip_sort_key(ip: str) -> tuple[int, int, int | str]:
    """Order valid IPs numerically by version; push unparsable strings last."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (1, 0, ip)
    return (0, addr.version, int(addr))


def expand_targets(cidrs: list[str], max_targets: int = MAX_EXPANDED_TARGETS) -> list[str]:
    """Expand CIDRs/bare IPs into a sorted, de-duplicated list of host IPs.

    Each entry may be a network (``10.0.0.0/24``) or a single address
    (``10.0.0.5``, treated as a ``/32``). For blocks larger than a point-to-point
    link, network and broadcast addresses are excluded via
    :meth:`ipaddress.ip_network.hosts`. Invalid entries are logged and skipped.
    """
    if max_targets < 1:
        raise ValueError("max_targets must be at least one")
    seen: set[str] = set()
    for raw in cidrs:
        text = raw.strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            logger.warning("skipping_invalid_target", value=raw)
            continue
        # /31 and /32 (and IPv6 equivalents) have no host/broadcast split.
        addresses = network if network.num_addresses <= 2 else network.hosts()
        for host in addresses:
            seen.add(str(host))
            if len(seen) > max_targets:
                raise TargetLimitError(
                    f"Target expansion exceeds the safe limit of {max_targets:,} addresses"
                )
    return sorted(seen, key=_ip_sort_key)


async def _is_reachable(host: str, port: int, timeout: float) -> bool:
    """True if a TCP connect to ``host:port`` succeeds or is actively refused."""
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except ConnectionRefusedError:
        return True  # a refusal still proves the host is reachable
    except (TimeoutError, OSError):
        return False
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()
    return True


async def fast_discover(
    cidrs: list[str],
    ports: list[int] | None = None,
    concurrency: int = 500,
    timeout: float = 1.0,
    rate_per_second: float = 0.0,
) -> list[str]:
    """Discover live hosts across ``cidrs`` via unprivileged TCP-connect probes.

    Each host is probed on ``ports`` (default: common IT ports plus a few OT
    ports) and reported alive on the first port that connects or is refused.
    Probes run under an :class:`asyncio.Semaphore` of ``concurrency`` and hosts
    are processed in batches so memory stays bounded on large ranges. Returns
    sorted, unique live IPs.
    """
    probe_ports = DEFAULT_PROBE_PORTS if ports is None else ports
    hosts = expand_targets(cidrs)
    if not hosts or not probe_ports:
        return []

    if concurrency < 1:
        raise ValueError("concurrency must be at least one")
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    if rate_per_second < 0:
        raise ValueError("rate_per_second cannot be negative")

    limit = asyncio.Semaphore(concurrency)
    throttle = _StartRateLimiter(rate_per_second)
    live: set[str] = set()

    async def _probe_host(host: str) -> None:
        await throttle.acquire()
        for port in probe_ports:
            async with limit:
                if await _is_reachable(host, port, timeout):
                    live.add(host)
                    return

    for batch in batched(hosts, _BATCH_SIZE):
        await asyncio.gather(*(_probe_host(host) for host in batch))

    result = sorted(live, key=_ip_sort_key)
    logger.info(
        "fast_discover_complete",
        ranges=len(cidrs),
        hosts=len(hosts),
        live=len(result),
    )
    return result
