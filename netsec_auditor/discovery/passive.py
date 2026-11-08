"""Passive network discovery — GRASSMARLIN-style, zero packets sent.

This module observes traffic that already exists on a SPAN/tap port and builds
an inventory of hosts, MAC addresses, ports and protocols without emitting a
single packet at the targets. That makes it safe for fragile OT/ICS segments
where an active probe could disrupt a running process.

Industrial traffic is named, not just counted: IP flows on well-known OT ports
are labelled with their protocol (``modbus``, ``iec-104``...), and layer-2
industrial frames that never carry IP (PROFINET, EtherCAT, POWERLINK, IEC 61850
GOOSE/SV) are recognised by EtherType, VLAN tags included, and recorded as OT
hosts keyed by MAC. PROFINET DCP Identify responses also yield the station
name and vendor/device IDs.

Capturing live traffic needs scapy and raw-socket privileges (root). Both are
imported/checked lazily, so this module imports cleanly without either and the
sniffer degrades to an empty inventory with a clear warning when they are
missing. The field-extraction path (:func:`handle_packet`) is pure and can be
exercised with a plain object or mapping, so it is fully testable without scapy.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import ipaddress
import os
import re
import struct
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from netsec_auditor.profiles import IOT_PORTS, OT_ETHERTYPE_NAMES, OT_PORT_NAMES, OT_PORTS
from netsec_auditor.utils.logging import get_logger

logger = get_logger(__name__)

# Flat field names understood by :func:`observe_packet` for non-scapy inputs.
_FLAT_ATTRS = ("src_ip", "dst_ip", "src_mac", "dst_mac", "dst_port", "protocol", "ethertype")

# Hosts kept by one inventory; spoofed source addresses must not exhaust memory.
MAX_HOSTS = 65536

# Ports that identify a service; a reply sent from an OT one is credited to its sender.
_SERVICE_PORTS = OT_PORTS | IOT_PORTS

# 802.1Q, 802.1ad and legacy QinQ tag protocol identifiers, and how many to skip.
_VLAN_TPIDS = frozenset({0x8100, 0x88A8, 0x9100})
_MAX_VLAN_TAGS = 2

_PROFINET_ETHERTYPE = 0x8892
# FrameID, ServiceID and ServiceType of a successful PROFINET DCP Identify response.
_DCP_IDENTIFY_RESPONSE = (0xFEFF, 5, 1)
_DCP_HEADER_LEN = 12
_DCP_TEXT_LIMIT = 64

_MAC_RE = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}")

# How often a running capture checks for its deadline or an early failure.
_CAPTURE_POLL_SECONDS = 0.25
# How long a stopped capture thread may take to wind down before it is abandoned.
_CAPTURE_STOP_GRACE = 2.0


def _async_sniffer(**options: Any) -> Any:
    """Create a scapy ``AsyncSniffer`` (imported lazily, so scapy stays optional)."""
    from scapy.all import AsyncSniffer

    return AsyncSniffer(**options)


async def capture_for(seconds: float, prn: Callable[[Any], None], **options: Any) -> None:
    """Run a scapy capture for ``seconds`` without blocking the event loop.

    ``prn`` is called for every captured packet on the capture thread and
    ``options`` go to scapy's ``AsyncSniffer``. Cancelling the awaiting task
    (Ctrl+C) stops the capture promptly; packets seen so far have already been
    handed to ``prn``. A capture that fails to start (bad interface, missing
    privileges) raises its error at once instead of after ``seconds``. An
    infinite ``seconds`` runs until cancelled.
    """
    if not seconds >= 0:  # also rejects NaN, which would make the wait loop spin
        raise ValueError(f"capture duration must be a non-negative number, not {seconds!r}")
    stopped = threading.Event()

    def _deliver(pkt: Any) -> None:
        if not stopped.is_set():
            prn(pkt)

    sniffer = _async_sniffer(prn=_deliver, **options)
    sniffer.start()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + seconds
    try:
        while _sniffer_running(sniffer):
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            await asyncio.sleep(min(remaining, _CAPTURE_POLL_SECONDS))
    except BaseException:
        stopped.set()
        _stop_sniffer(sniffer, reraise=False)
        raise
    stopped.set()
    _stop_sniffer(sniffer, reraise=True)


def _sniffer_running(sniffer: Any) -> bool:
    """True while the sniffer's capture thread is alive."""
    thread = getattr(sniffer, "thread", None)
    return thread is not None and bool(thread.is_alive())


def _stop_sniffer(sniffer: Any, *, reraise: bool) -> None:
    """Signal the capture thread to stop and wait briefly for it.

    The thread is a daemon, so one that is still blocked after the grace period
    cannot keep the process alive. ``reraise`` surfaces a capture error.
    """
    with contextlib.suppress(Exception):  # it may never have started or already ended
        sniffer.stop(join=False)
    try:
        sniffer.join(timeout=_CAPTURE_STOP_GRACE)
    except Exception:
        if reraise:
            raise


def _blank_host() -> dict[str, Any]:
    """Return a fresh, empty host record."""
    return {
        "mac": "",
        "ports": set(),
        "protocols": set(),
        "is_ot": False,
        "is_iot": False,
        "device": {},
    }


def _snapshot(ip: str, rec: dict[str, Any]) -> dict[str, Any]:
    """Serialize one host record; ``set`` fields become sorted lists."""
    return {
        "ip": ip,
        "mac": rec["mac"],
        "ports": sorted(rec["ports"]),
        "protocols": sorted(rec["protocols"]),
        "is_ot": rec["is_ot"],
        "is_iot": rec["is_iot"],
        "device": dict(rec["device"]),
    }


def _unicast_mac(mac: str | None) -> str:
    """Return ``mac`` lower-cased if it is a unicast station address, else ''."""
    candidate = (mac or "").lower()
    if not _MAC_RE.fullmatch(candidate) or candidate == "00:00:00:00:00:00":
        return ""
    return "" if int(candidate[:2], 16) & 0x01 else candidate  # I/G bit: group address


def _ip_sort_key(ip: str) -> tuple[int, int, int | str]:
    """Order valid IPs numerically by version; push unparsable strings last."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (1, 0, ip)
    return (0, addr.version, int(addr))


class PassiveInventory:
    """Accumulates hosts discovered passively from observed traffic.

    IP hosts are keyed by IP. The destination of a flow owns the observed
    service port, so OT/IoT classification is applied to the destination only.
    Stations seen only through layer-2 industrial frames are kept separately,
    keyed by MAC. At most ``max_hosts`` hosts of both kinds are kept; later new
    hosts are counted in :attr:`dropped_hosts` instead of being stored.
    """

    def __init__(self, max_hosts: int = MAX_HOSTS) -> None:
        self._hosts: dict[str, dict[str, Any]] = {}
        self._link_hosts: dict[str, dict[str, Any]] = {}
        self.max_hosts = max_hosts
        self.dropped_hosts = 0

    def _record(self, table: dict[str, dict[str, Any]], key: str) -> dict[str, Any] | None:
        """The record for ``key`` in ``table``, created if there is room; None once full."""
        rec = table.get(key)
        if rec is not None:
            return rec
        if len(self) >= self.max_hosts:
            if not self.dropped_hosts:
                logger.warning("passive_host_limit_reached", max_hosts=self.max_hosts)
            self.dropped_hosts += 1
            return None
        rec = table[key] = _blank_host()
        return rec

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
        ``protocol`` are recorded for whichever endpoint they belong to; on a
        well-known OT port a bare ``tcp``/``udp`` becomes the protocol name
        (``modbus``, ``iec-104``...). Missing values are ignored so partial
        observations still merge.
        """
        if dst_port is not None and protocol in (None, "tcp", "udp"):
            protocol = OT_PORT_NAMES.get(dst_port, protocol)
        src = self._record(self._hosts, src_ip) if src_ip else None
        if src is not None:
            if src_mac:
                src["mac"] = src_mac
            if protocol:
                src["protocols"].add(protocol)
        dst = self._record(self._hosts, dst_ip) if dst_ip else None
        if dst is not None:
            if dst_mac:
                dst["mac"] = dst_mac
            if protocol:
                dst["protocols"].add(protocol)
            if dst_port is not None:
                dst["ports"].add(dst_port)
                dst["is_ot"] = dst["is_ot"] or dst_port in OT_PORTS
                dst["is_iot"] = dst["is_iot"] or dst_port in IOT_PORTS

    def add_link_observation(
        self,
        src_mac: str | None,
        dst_mac: str | None,
        protocol: str,
        device: Mapping[str, str] | None = None,
    ) -> None:
        """Record a layer-2 industrial frame; its unicast endpoints become OT hosts.

        Group (multicast/broadcast) addresses are not stations and are skipped.
        ``device`` is identity read from the frame (a PROFINET DCP answer) and
        describes the sender.
        """
        for mac, identity in ((src_mac, device), (dst_mac, None)):
            key = _unicast_mac(mac)
            rec = self._record(self._link_hosts, key) if key else None
            if rec is None:
                continue
            rec["mac"] = key
            rec["protocols"].add(protocol)
            rec["is_ot"] = True
            if identity:
                rec["device"].update(identity)

    def hosts(self) -> list[dict[str, Any]]:
        """Return a serializable snapshot; ``set`` fields become sorted lists.

        IP hosts come first in numeric order. Stations seen only at layer 2
        follow, ordered by MAC, with ``ip`` set to ``""``.
        """
        snapshot = [_snapshot(ip, self._hosts[ip]) for ip in sorted(self._hosts, key=_ip_sort_key)]
        snapshot += [_snapshot("", self._link_hosts[mac]) for mac in sorted(self._link_hosts)]
        return snapshot

    def __len__(self) -> int:
        return len(self._hosts) + len(self._link_hosts)


@dataclass
class PacketObservation:
    """Normalized packet fields, independent of scapy.

    An observation without any IP is a layer-2 industrial frame: ``protocol``
    then names it (``profinet``, ``ethercat``...) and ``device`` holds any
    station identity the frame carried.
    """

    src_ip: str | None = None
    dst_ip: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    device: dict[str, str] = field(default_factory=dict)


def _as_str(value: object) -> str | None:
    """Coerce a value to ``str`` (or ``None``)."""
    return None if value is None else str(value)


def _as_int(value: Any) -> int | None:
    """Coerce a value (port, EtherType) to ``int`` (or ``None``) without raising."""
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
    the packet has no IP endpoint and is not a layer-2 industrial frame.
    """
    if _looks_flat(pkt):
        obs = PacketObservation(
            src_ip=_as_str(_get(pkt, "src_ip")),
            dst_ip=_as_str(_get(pkt, "dst_ip")),
            src_mac=_as_str(_get(pkt, "src_mac")),
            dst_mac=_as_str(_get(pkt, "dst_mac")),
            dst_port=_as_int(_get(pkt, "dst_port")),
            protocol=_as_str(_get(pkt, "protocol")),
        )
        if obs.src_ip is None and obs.dst_ip is None:
            name = _ot_ethertype_name(_as_int(_get(pkt, "ethertype")))
            if name is None:
                return None
            obs.protocol = name
        return obs
    return _observe_scapy(pkt)


def _ot_ethertype_name(ethertype: int | None) -> str | None:
    """The industrial protocol carried by ``ethertype``, if it is one."""
    return None if ethertype is None else OT_ETHERTYPE_NAMES.get(ethertype)


def _observe_scapy(pkt: Any) -> PacketObservation | None:
    """Decode a real scapy packet into a :class:`PacketObservation`."""
    try:
        from scapy.all import IP, TCP, UDP, Ether, IPv6
    except ImportError:
        return None

    obs = PacketObservation()
    ether = pkt[Ether] if pkt.haslayer(Ether) else None
    if ether is not None:
        obs.src_mac = _as_str(getattr(ether, "src", None))
        obs.dst_mac = _as_str(getattr(ether, "dst", None))

    ip_layer = None
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
    if ip_layer is None:
        return _observe_link(ether, obs)
    obs.src_ip = _as_str(getattr(ip_layer, "src", None))
    obs.dst_ip = _as_str(getattr(ip_layer, "dst", None))

    transport = pkt[TCP] if pkt.haslayer(TCP) else pkt[UDP] if pkt.haslayer(UDP) else None
    if transport is None:
        return obs
    obs.protocol = "tcp" if isinstance(transport, TCP) else "udp"
    sport = _as_int(getattr(transport, "sport", None))
    dport = _as_int(getattr(transport, "dport", None))
    if dport not in _SERVICE_PORTS and sport in OT_PORT_NAMES:
        # A reply from an OT server: credit the service port to its sender,
        # not the client's ephemeral port to the client.
        obs.src_ip, obs.dst_ip = obs.dst_ip, obs.src_ip
        obs.src_mac, obs.dst_mac = obs.dst_mac, obs.src_mac
        dport = sport
    obs.dst_port = dport
    return obs


def _observe_link(ether: Any, obs: PacketObservation) -> PacketObservation | None:
    """Recognise a non-IP Ethernet frame by its industrial EtherType, VLAN tags skipped."""
    if ether is None:
        return None
    ethertype = _as_int(getattr(ether, "type", None))
    layer = ether.payload
    for _ in range(_MAX_VLAN_TAGS):
        if ethertype not in _VLAN_TPIDS:
            break
        ethertype = _as_int(getattr(layer, "type", None))  # Dot1Q/Dot1AD carry the next type
        layer = layer.payload
    name = _ot_ethertype_name(ethertype)
    if name is None:
        return None
    obs.protocol = name
    if ethertype == _PROFINET_ETHERTYPE:
        obs.device = parse_dcp_identify_response(bytes(layer))
    return obs


def parse_dcp_identify_response(payload: bytes) -> dict[str, str]:
    """Read a station's identity from a PROFINET DCP Identify response.

    ``payload`` is the EtherType 0x8892 payload, FrameID first. Returns any of
    ``name_of_station``, ``device_type`` (type of station), ``vendor_id`` and
    ``device_id``; text is reduced to printable characters and capped. Any
    other frame yields ``{}``. Pure and bounded by the frame length; never raises.
    """
    if len(payload) < _DCP_HEADER_LEN:
        return {}
    if struct.unpack_from("!HBB", payload) != _DCP_IDENTIFY_RESPONSE:
        return {}
    (data_length,) = struct.unpack_from("!H", payload, 10)
    end = min(len(payload), _DCP_HEADER_LEN + data_length)
    identity: dict[str, str] = {}
    pos = _DCP_HEADER_LEN
    while pos + 4 <= end:
        option, suboption, length = struct.unpack_from("!BBH", payload, pos)
        value = payload[pos + 6:min(pos + 4 + length, end)]  # after the 2-byte BlockInfo
        if (option, suboption) == (2, 1):
            identity["device_type"] = _printable(value)
        elif (option, suboption) == (2, 2):
            identity["name_of_station"] = _printable(value)
        elif (option, suboption) == (2, 3) and len(value) >= 4:
            vendor_id, device_id = struct.unpack_from("!HH", value)
            identity["vendor_id"] = f"0x{vendor_id:04x}"
            identity["device_id"] = f"0x{device_id:04x}"
        pos += 4 + length + (length & 1)  # blocks are padded to an even length
    return {key: text for key, text in identity.items() if text}


def _printable(raw: bytes) -> str:
    """Decode a device-supplied string to printable characters, capped in length."""
    text = raw.decode("utf-8", "replace")
    return "".join(ch for ch in text if ch.isprintable()).strip()[:_DCP_TEXT_LIMIT]


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
    if observation.src_ip is None and observation.dst_ip is None:
        if observation.protocol:
            inventory.add_link_observation(
                observation.src_mac,
                observation.dst_mac,
                observation.protocol,
                observation.device,
            )
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
    geteuid: Callable[[], int] | None = getattr(os, "geteuid", None)
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
        before the failure is still returned. Cancelling the call stops the
        capture promptly.
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

        try:
            await capture_for(
                seconds,
                lambda pkt: handle_packet(inventory, pkt),
                store=False,
                iface=iface,
                filter=self.bpf_filter,
            )
        except Exception as exc:  # scapy raises many capture errors; degrade safely
            logger.warning("passive_sniff_failed", error=str(exc))
            return inventory

        logger.info("passive_sniff_complete", seconds=seconds, hosts=len(inventory))
        return inventory
