"""Optional masscan accelerator for line-rate discovery of very large ranges.

Falls back to the built-in async connect sweep when masscan is absent or fails.
masscan needs root (raw sockets); the parser is pure and unit-testable.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import shutil

from netsec_auditor.utils.logging import get_logger

logger = get_logger(__name__)


def masscan_available() -> bool:
    """True if the masscan binary is on PATH."""
    return shutil.which("masscan") is not None


def parse_masscan_list(text: str) -> list[str]:
    """Parse masscan ``-oL`` output into a sorted list of unique live IPs."""
    ips: set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        # Format: "open <proto> <port> <ip> <timestamp>"
        if len(parts) >= 4 and parts[0] == "open":
            ips.add(parts[3])
    return sorted(ips)


async def masscan_discover(
    cidrs: list[str], ports: str, rate: int = 1000, timeout: float = 600.0
) -> list[str] | None:
    """Run masscan over ``cidrs``; return live IPs, or None if masscan is unusable.

    ``ports`` is required (no built-in default) so every caller passes an explicit,
    scope-filtered port set — masscan runs at line rate, and a forgotten filter must
    never silently blast a broad or OT-inclusive default across a network.
    """
    if not masscan_available():
        return None
    ports = ports.strip()
    if not ports:
        logger.warning("masscan_no_ports")
        return None
    # masscan has no "--" terminator, so each range is validated instead: a target
    # beginning with "-" would otherwise be parsed as a flag.
    try:
        targets = [str(ipaddress.ip_network(cidr, strict=False)) for cidr in cidrs]
    except ValueError as exc:
        logger.warning("masscan_invalid_target", error=str(exc))
        return None
    args = ["masscan", *targets, "-p", ports, "--rate", str(rate), "-oL", "-"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError as e:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(Exception):
            await proc.wait()
        logger.warning("masscan_failed", error=str(e) or "timed out")
        return None
    except OSError as e:
        logger.warning("masscan_failed", error=str(e))
        return None
    if proc.returncode != 0:
        logger.warning("masscan_nonzero_exit", code=proc.returncode)
        return None
    return parse_masscan_list(stdout.decode("utf-8", "replace"))
