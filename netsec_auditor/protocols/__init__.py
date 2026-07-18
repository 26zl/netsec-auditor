"""Protocol probe registry — aggregates OT/ICS and IoT probe specs."""

from netsec_auditor.protocols import amplification, iot, ot, smb, snmp
from netsec_auditor.protocols.base import (
    ProbeResult,
    ProbeSpec,
    all_specs,
    ot_ports,
    probers_for_port,
    register,
)

register(ot.SPECS)
register(iot.SPECS)
register(snmp.SPECS)
register(amplification.SPECS)
register(smb.SPECS)

__all__ = [
    "ProbeResult",
    "ProbeSpec",
    "all_specs",
    "ot_ports",
    "probers_for_port",
    "register",
]
