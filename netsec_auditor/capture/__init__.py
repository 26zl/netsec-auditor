"""Offline PCAP capture analysis — read-only inspection of saved traffic.

This package reads ``.pcap``/``.pcapng`` files that already exist on disk (for
example a capture exported by an ESP32 Marauder or Flipper WiFi devboard, or a
SPAN/``tcpdump`` dump) and folds them into the same passive host/protocol
inventory used for live capture, adding a cleartext-credential scan on top.

Nothing here sends a single packet — it is pure offline analysis. scapy is only
needed to parse the capture file and is imported lazily, so this package imports
cleanly without it. The credential scanner (:func:`scan_cleartext_credentials`)
is a pure function over raw payload bytes and needs neither scapy nor a network.
"""

from netsec_auditor.capture.pcap import (
    analyze_pcap,
    load_pcap,
    scan_cleartext_credentials,
)

__all__ = [
    "analyze_pcap",
    "load_pcap",
    "scan_cleartext_credentials",
]
