"""Optional masscan accelerator for line-rate discovery of very large ranges.

Falls back to the built-in async connect sweep when masscan is absent or fails.
masscan needs root (raw sockets); the parser is pure and unit-testable.
"""

from __future__ import annotations

import asyncio
import shutil

from netsec_auditor.utils.logging import get_logger

logger = get_logger(__name__)

# Common IT + OT ports to sweep when the caller does not specify.
DEFAULT_PORTS = "22,80,443,445,3389,8080,161,502,102,47808,44818,20000"


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
    cidrs: list[str], ports: str = DEFAULT_PORTS, rate: int = 1000, timeout: float = 600.0
) -> list[str] | None:
    """Run masscan over ``cidrs``; return live IPs, or None if masscan is unusable."""
    if not masscan_available():
        return None
    args = ["masscan", *cidrs, "-p", ports, "--rate", str(rate), "-oL", "-"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except (OSError, TimeoutError) as e:
        logger.warning("masscan_failed", error=str(e))
        return None
    if proc.returncode != 0:
        logger.warning("masscan_nonzero_exit", code=proc.returncode)
        return None
    return parse_masscan_list(stdout.decode("utf-8", "replace"))
