"""Environment profiles and the OT safety interlock.

OT/ICS devices are fragile: aggressive scanning can crash PLCs or disrupt a
process. Profiles set conservative defaults per environment, and the interlock
auto-downgrades to the gentle OT profile when an OT service is detected, unless
the operator explicitly overrides.
"""

from __future__ import annotations

from dataclasses import dataclass

# Well-known OT/ICS service ports and the protocol each one usually carries.
OT_PORT_NAMES: dict[int, str] = {
    102: "s7comm/iec61850-mms",  # Siemens S7, IEC 61850 MMS (ISO-TSAP)
    502: "modbus",
    789: "redlion-crimson",
    1089: "ff-hse", 1090: "ff-hse", 1091: "ff-hse",  # Foundation Fieldbus HSE
    1200: "codesys", 2455: "codesys",
    1911: "niagara-fox", 4911: "niagara-fox-tls",
    1962: "pcworx",  # Phoenix Contact
    2222: "enip-io",  # EtherNet/IP implicit I/O (UDP)
    2404: "iec-104",  # IEC 60870-5-104
    3671: "knxnet-ip",  # KNX building automation (UDP)
    4840: "opcua",
    5006: "melsec", 5007: "melsec",  # Mitsubishi MELSOFT (UDP / TCP)
    5094: "hart-ip",
    9600: "omron-fins",
    18245: "ge-srtp",  # GE / Emerson PACSystems
    20000: "dnp3",
    20547: "proconos",
    34962: "profinet", 34963: "profinet", 34964: "profinet",
    44818: "enip",  # EtherNet/IP explicit messaging (CIP)
    47808: "bacnet",  # BACnet/IP (UDP)
    48898: "beckhoff-ads",
}
OT_PORTS: frozenset[int] = frozenset(OT_PORT_NAMES)

# EtherTypes of layer-2 industrial protocols that never appear as IP traffic.
OT_ETHERTYPE_NAMES: dict[int, str] = {
    0x8892: "profinet",
    0x88A4: "ethercat",
    0x88AB: "powerlink",
    0x88B8: "iec61850-goose",
    0x88BA: "iec61850-sv",
}

# Common IoT service ports.
IOT_PORTS: frozenset[int] = frozenset({
    554,    # RTSP
    1883, 8883,  # MQTT (plain / TLS)
    1900,   # UPnP / SSDP (UDP)
    3702,   # WS-Discovery / ONVIF (UDP)
    5353,   # mDNS (UDP)
    5683, 5684,  # CoAP (UDP / DTLS)
})


@dataclass(frozen=True)
class Profile:
    """Scan behaviour tuned to an environment."""

    name: str
    max_concurrency: int
    scan_delay: float          # seconds between probes to one target
    timing_template: int       # nmap -T value
    version_intensity: int     # nmap -sV --version-intensity (0 = light)
    allow_os_detection: bool
    allow_intrusive: bool      # write/control probes and brute forcing
    passive_preferred: bool


IT = Profile(
    name="it",
    max_concurrency=50,
    scan_delay=0.0,
    timing_template=4,
    version_intensity=7,
    allow_os_detection=True,
    allow_intrusive=True,
    passive_preferred=False,
)

IOT = Profile(
    name="iot",
    max_concurrency=10,
    scan_delay=0.1,
    timing_template=3,
    version_intensity=2,
    allow_os_detection=False,
    allow_intrusive=False,
    passive_preferred=False,
)

OT = Profile(
    name="ot",
    max_concurrency=1,
    scan_delay=0.5,
    timing_template=2,
    version_intensity=0,
    allow_os_detection=False,
    allow_intrusive=False,
    passive_preferred=True,
)

PROFILES: dict[str, Profile] = {p.name: p for p in (IT, IOT, OT)}


def get_profile(name: str) -> Profile:
    """Return a profile by name.

    Raises on an unknown name rather than defaulting: silently falling back to the
    most permissive profile would run an aggressive scan against a network the
    operator had asked to treat as fragile.
    """
    try:
        return PROFILES[name.lower()]
    except KeyError:
        raise ValueError(
            f"unknown profile {name!r}; expected one of: {', '.join(sorted(PROFILES))}"
        ) from None


def classify_ports(ports: set[int]) -> str:
    """Classify a set of open ports as 'ot', 'iot', or 'it'. OT takes precedence."""
    if ports & OT_PORTS:
        return "ot"
    if ports & IOT_PORTS:
        return "iot"
    return "it"


def apply_interlock(profile: Profile, open_ports: set[int], forced: bool) -> Profile:
    """Downgrade to the OT profile when OT ports are present, unless forced.

    ``forced`` means the operator explicitly chose a profile and opts out of the
    automatic safety downgrade.
    """
    if forced:
        return profile
    if open_ports & OT_PORTS and profile.name != "ot":
        return OT
    if open_ports & IOT_PORTS and profile.name == "it":
        return IOT
    return profile
