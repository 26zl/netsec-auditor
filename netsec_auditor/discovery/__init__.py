"""Network discovery — passive sniffing and fast large-range sweeps.

Two complementary strategies feed the detailed scanner:

* :mod:`~netsec_auditor.discovery.passive` performs GRASSMARLIN-style passive
  capture that sends zero packets, ideal for fragile OT/ICS networks.
* :mod:`~netsec_auditor.discovery.fast` performs unprivileged TCP-connect sweeps
  across large ranges to quickly narrow down live hosts.

Both submodules import cleanly without scapy (it is imported lazily where used).
"""

from netsec_auditor.discovery.fast import (
    DEFAULT_PROBE_PORTS,
    batched,
    expand_targets,
    fast_discover,
)
from netsec_auditor.discovery.passive import (
    PacketObservation,
    PassiveInventory,
    PassiveSniffer,
    handle_packet,
    observe_packet,
)

__all__ = [
    "DEFAULT_PROBE_PORTS",
    "PacketObservation",
    "PassiveInventory",
    "PassiveSniffer",
    "batched",
    "expand_targets",
    "fast_discover",
    "handle_packet",
    "observe_packet",
]
