"""Optional external-tool integrations (e.g. nmap NSE).

These integrations enrich the toolkit's native probes when a supported binary is
present, and degrade cleanly to empty results when it is not. Nothing here adds a
hard dependency — availability is always checked at call time.
"""

from netsec_auditor.integrations.nse import (
    DISCOVERY_SCRIPTS,
    ICS_SCRIPTS,
    SCRIPT_SETS,
    SMB_SCRIPTS,
    SNMP_SCRIPTS,
    SUMMARY_RULES,
    TLS_SCRIPTS,
    build_nmap_command,
    nse_available,
    parse_nmap_xml,
    run_nse,
    run_script_set,
    summarize_findings,
)

__all__ = [
    "DISCOVERY_SCRIPTS",
    "ICS_SCRIPTS",
    "SCRIPT_SETS",
    "SMB_SCRIPTS",
    "SNMP_SCRIPTS",
    "SUMMARY_RULES",
    "TLS_SCRIPTS",
    "build_nmap_command",
    "nse_available",
    "parse_nmap_xml",
    "run_nse",
    "run_script_set",
    "summarize_findings",
]
