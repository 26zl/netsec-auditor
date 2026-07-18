"""Passive network discovery — GRASSMARLIN-style, zero packets sent.

This module observes traffic that already exists on a SPAN/tap port and builds
an inventory of hosts, MAC addresses, ports and protocols without emitting a
single packet at the targets. That makes it safe for fragile OT/ICS segments
where an active probe could disrupt a running process.

Capturing live traffic needs scapy and raw-socket privileges (root). Both are
imported/checked lazily, so this module imports cleanly without either and the
sniffer degrades to an empty inventory with a clear warning when they are
missing. The field-extraction path (:func:`handle_packet`) is pure and can be
exercised with a plain object or mapping, so it is fully testable without scapy.
"""

from __future__ import annotations

import asyncio
import importlib.util
import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass

from netsec_auditor.profiles import IOT_PORTS, OT_PORTS
from netsec_auditor.utils.logging import get_logger

logger = get_logger(__name__)

# Flat field names understood by :func:`observe_packet` for non-scapy inputs.
_FLAT_ATTRS = ("src_ip", "dst_ip", "src_mac", "dst_mac", "dst_port", "protocol")


def _blank_host() -> dict:
    """Return a fresh, empty host record."""
    return {
        "mac": "",
        "ports": set(),
        "protocols": set(),
        "is_ot": False,
        "is_iot": False,
    }


def _ip_sort_key(ip: str) -> tuple[int, int, int | str]:
    """Order valid IPs numerically by version; push unparsable strings last."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (1, 0, ip)
    return (0, addr.version, int(addr))


class PassiveInventory:
    """Accumulates hosts discovered passively from observed traffic.

    Records are keyed by IP. The destination of a flow owns the observed service
    port, so OT/IoT classification is applied to the destination only.
    """

    def __init__(self) -> None:
        self._hosts: dict[str, dict] = {}

    def add_observation(
        self,
        src_ip: str | None,
        dst_ip: str | None,
        src_mac: str | None = None,
        dst_mac: str | None = None,
        dst_port: int | None = None,
        protocol: str | None = None,
    ) -> None:
        """Merge one observed packet's endpoints into the inventory.

        ``dst_port`` is the destination's service port, so it (and the OT/IoT
        classification it implies) is attributed to ``dst_ip`` only. MAC and
        transport ``protocol`` are recorded for whichever endpoint they belong
        to. Missing values are ignored so partial observations still merge.
        """
        if src_ip:
            rec = self._hosts.setdefault(src_ip, _blank_host())
            if src_mac:
                rec["mac"] = src_mac
            if protocol:
                rec["protocols"].add(protocol)
        if dst_ip:
            rec = self._hosts.setdefault(dst_ip, _blank_host())
            if dst_mac:
                rec["mac"] = dst_mac
            if protocol:
                rec["protocols"].add(protocol)
            if dst_port is not None:
                rec["ports"].add(dst_port)
                rec["is_ot"] = rec["is_ot"] or dst_port in OT_PORTS
                rec["is_iot"] = rec["is_iot"] or dst_port in IOT_PORTS

    def hosts(self) -> list[dict]:
        """Return a serializable snapshot; ``set`` fields become sorted lists."""
        snapshot: list[dict] = []
        for ip in sorted(self._hosts, key=_ip_sort_key):
            rec = self._hosts[ip]
            snapshot.append({
                "ip": ip,
                "mac": rec["mac"],
                "ports": sorted(rec["ports"]),
                "protocols": sorted(rec["protocols"]),
                "is_ot": rec["is_ot"],
                "is_iot": rec["is_iot"],
            })
        return snapshot

    def __len__(self) -> int:
        return len(self._hosts)


@dataclass
class PacketObservation:
    """Normalized packet fields, independent of scapy."""

    src_ip: str | None = None
    dst_ip: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    dst_port: int | None = None
    protocol: str | None = None


def _as_str(value: object) -> str | None:
    """Coerce a value to ``str`` (or ``None``)."""
    return None if value is None else str(value)


def _coerce_port(value: object) -> int | None:
    """Coerce a value to a port ``int`` (or ``None``) without raising."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _get(pkt: object, name: str) -> object:
    """Read ``name`` from a mapping or object, defaulting to ``None``."""
    if isinstance(pkt, Mapping):
        return pkt.get(name)
    return getattr(pkt, name, None)


def _looks_flat(pkt: object) -> bool:
    """True when ``pkt`` is a plain mapping/object we can read directly.

    Real scapy packets expose ``haslayer`` and are routed to the scapy decoder;
    anything else that carries our flat field names is read attribute-by-name.
    """
    if isinstance(pkt, Mapping):
        return True
    if hasattr(pkt, "haslayer"):
        return False
    return any(hasattr(pkt, attr) for attr in _FLAT_ATTRS)


def observe_packet(pkt: object) -> PacketObservation | None:
    """Normalize a packet into a :class:`PacketObservation`.

    Accepts a plain mapping or object exposing the flat field names — this is
    pure and needs no scapy, and is the path exercised by the tests — or a real
    scapy packet, which is decoded via a lazy scapy import. Returns ``None`` when
    no IP endpoint can be determined.
    """
    if _looks_flat(pkt):
        obs = PacketObservation(
            src_ip=_as_str(_get(pkt, "src_ip")),
            dst_ip=_as_str(_get(pkt, "dst_ip")),
            src_mac=_as_str(_get(pkt, "src_mac")),
            dst_mac=_as_str(_get(pkt, "dst_mac")),
            dst_port=_coerce_port(_get(pkt, "dst_port")),
            protocol=_as_str(_get(pkt, "protocol")),
        )
        if obs.src_ip is None and obs.dst_ip is None:
            return None
        return obs
    return _observe_scapy(pkt)


def _observe_scapy(pkt: object) -> PacketObservation | None:
    """Decode a real scapy packet into a :class:`PacketObservation`."""
    try:
        from scapy.all import IP, TCP, UDP, Ether, IPv6
    except ImportError:
        return None

    obs = PacketObservation()
    if pkt.haslayer(Ether):
        ether = pkt[Ether]
        obs.src_mac = _as_str(getattr(ether, "src", None))
        obs.dst_mac = _as_str(getattr(ether, "dst", None))

    ip_layer = None
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
    if ip_layer is None:
        return None
    obs.src_ip = _as_str(getattr(ip_layer, "src", None))
    obs.dst_ip = _as_str(getattr(ip_layer, "dst", None))

    if pkt.haslayer(TCP):
        obs.protocol = "tcp"
        obs.dst_port = _coerce_port(getattr(pkt[TCP], "dport", None))
    elif pkt.haslayer(UDP):
        obs.protocol = "udp"
        obs.dst_port = _coerce_port(getattr(pkt[UDP], "dport", None))
    return obs


def handle_packet(inventory: PassiveInventory, pkt: object) -> None:
    """Extract endpoint fields from ``pkt`` and record them in ``inventory``.

    Pure and defensive: accepts a scapy packet (decoded lazily) or a plain
    object/mapping for testing, and never raises on malformed input — a bad
    packet must never crash a live capture.
    """
    try:
        observation = observe_packet(pkt)
    except Exception as exc:  # defensive: a bad packet must never stop the capture
        logger.debug("passive_packet_skipped", error=str(exc))
        return
    if observation is None:
        return
    inventory.add_observation(
        src_ip=observation.src_ip,
        dst_ip=observation.dst_ip,
        src_mac=observation.src_mac,
        dst_mac=observation.dst_mac,
        dst_port=observation.dst_port,
        protocol=observation.protocol,
    )


def _is_root() -> bool | None:
    """Root status where determinable (POSIX), else ``None`` (e.g. Windows)."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return None
    return geteuid() == 0


class PassiveSniffer:
    """Captures live traffic and folds it into a :class:`PassiveInventory`.

    Sends zero packets. Requires scapy and root; without either it logs a clear
    warning and returns an empty inventory instead of raising.
    """

    def __init__(self, bpf_filter: str | None = None) -> None:
        self.bpf_filter = bpf_filter

    async def sniff_for(
        self, seconds: float, iface: str | None = None
    ) -> PassiveInventory:
        """Passively capture for ``seconds`` and return the resulting inventory.

        Returns an empty inventory (with a warning) when scapy is not installed
        or the process is not root; capture errors are caught so any traffic seen
        before the failure is still returned.
        """
        inventory = PassiveInventory()

        if importlib.util.find_spec("scapy") is None:
            logger.warning(
                "passive_sniff_unavailable",
                reason="scapy_not_installed",
                hint="pip install scapy",
            )
            return inventory

        if _is_root() is False:
            logger.warning(
                "passive_sniff_unavailable",
                reason="requires_root",
                hint="run with sudo",
            )
            return inventory

        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, self._run_sniff, inventory, seconds, iface)
        except Exception as exc:  # scapy raises many capture errors; degrade safely
            logger.warning("passive_sniff_failed", error=str(exc))
            return inventory

        logger.info("passive_sniff_complete", seconds=seconds, hosts=len(inventory))
        return inventory

    def _run_sniff(
        self, inventory: PassiveInventory, seconds: float, iface: str | None
    ) -> None:
        """Blocking scapy capture; runs inside a thread executor."""
        from scapy.all import sniff

        sniff(
            prn=lambda pkt: handle_packet(inventory, pkt),
            store=False,
            timeout=seconds,
            iface=iface,
            filter=self.bpf_filter,
        )
