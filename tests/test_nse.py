"""Tests for the optional nmap NSE integration.

The priority is the pure core — :func:`parse_nmap_xml` and
:func:`summarize_findings`. No network is used and the real nmap binary is never
invoked; a realistic ``-oX`` XML document is parsed directly.
"""

from __future__ import annotations

from netsec_auditor.integrations.nse import (
    SCRIPT_SETS,
    SNMP_SCRIPTS,
    TLS_SCRIPTS,
    build_nmap_command,
    nse_available,
    parse_nmap_xml,
    summarize_findings,
)

# One fully-formed <host> block: a host-level MS17-010 hit plus port-level
# ssl-enum-ciphers (443) and modbus-discover (502) results.
_HOST_A = (
    '<host>'
    '<status state="up" reason="user-set"/>'
    '<address addr="10.0.0.5" addrtype="ipv4"/>'
    '<address addr="00:11:22:33:44:55" addrtype="mac"/>'
    '<ports>'
    '<port protocol="tcp" portid="443">'
    '<state state="open" reason="syn-ack"/>'
    '<service name="https" method="probed"/>'
    '<script id="ssl-enum-ciphers" output="TLSv1.0: ciphers: '
    'TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - weak; least strength: C"/>'
    '</port>'
    '<port protocol="tcp" portid="502">'
    '<state state="open" reason="syn-ack"/>'
    '<service name="mbap" method="table"/>'
    '<script id="modbus-discover" output="sid 0x64: Slave ID data: '
    'Schneider Electric BMXP342020; Device identification present"/>'
    '</port>'
    '</ports>'
    '<hostscript>'
    '<script id="smb-vuln-ms17-010" output="Remote Code Execution vulnerability '
    'in Microsoft SMBv1 servers (ms17-010) State: VULNERABLE IDs: CVE:CVE-2017-0143"/>'
    '</hostscript>'
    '</host>'
)

VALID_XML = (
    f'<?xml version="1.0"?>\n<nmaprun scanner="nmap" version="7.94">\n{_HOST_A}\n</nmaprun>\n'
)

# Host A fully closes, then a second host is truncated mid-attribute (and the
# document is never closed) — exercises "return what parsed; never raise".
PARTIAL_XML = (
    f'<?xml version="1.0"?>\n<nmaprun scanner="nmap" version="7.94">\n{_HOST_A}\n'
    '<host><address addr="10.0.0.9" addrtype="ipv4"/><ports>'
    '<port protocol="tcp" portid="445"><script id="smb-protocols" output="dialects'
)


def _by_id(findings: list[dict]) -> dict[str, dict]:
    return {f["script_id"]: f for f in findings}


def test_nse_available_returns_bool() -> None:
    assert isinstance(nse_available(), bool)


def test_build_nmap_command_with_ports() -> None:
    cmd = build_nmap_command("10.0.0.5", TLS_SCRIPTS, ports="443")
    assert cmd == [
        "nmap", "-Pn", "--script", "ssl-enum-ciphers,ssl-cert",
        "-p", "443", "-oX", "-", "--", "10.0.0.5",
    ]


def test_build_nmap_command_without_ports_and_extra_args() -> None:
    cmd = build_nmap_command("host", SNMP_SCRIPTS, extra_args=["-T2"])
    assert cmd == [
        "nmap", "-Pn", "--script", "snmp-info,snmp-sysdescr",
        "-T2", "-oX", "-", "--", "host",
    ]


def test_build_nmap_command_terminates_options_before_target() -> None:
    # Without "--" nmap would read a dash-prefixed target as a flag.
    cmd = build_nmap_command("-oN/tmp/pwned", SNMP_SCRIPTS)
    assert cmd[-2:] == ["--", "-oN/tmp/pwned"]


def test_build_nmap_command_rejects_non_pacing_extra_args() -> None:
    cmd = build_nmap_command("host", SNMP_SCRIPTS, extra_args=["--script", "evil.nse", "-T3"])
    assert "--script" not in cmd[4:]
    assert "evil.nse" not in cmd
    assert "-T3" in cmd


def test_parse_extracts_host_port_script_output() -> None:
    findings = parse_nmap_xml(VALID_XML)
    by_id = _by_id(findings)
    assert set(by_id) == {"ssl-enum-ciphers", "modbus-discover", "smb-vuln-ms17-010"}

    tls = by_id["ssl-enum-ciphers"]
    assert tls["host"] == "10.0.0.5"  # ipv4 preferred over the mac address
    assert tls["port"] == 443
    assert tls["protocol"] == "tcp"
    assert "TLSv1.0" in tls["output"]
    assert "RC4" in tls["output"]

    modbus = by_id["modbus-discover"]
    assert modbus["port"] == 502
    assert modbus["protocol"] == "tcp"
    assert "Schneider Electric" in modbus["output"]

    ms17 = by_id["smb-vuln-ms17-010"]
    assert ms17["port"] is None  # host-level script has no port
    assert ms17["protocol"] == ""
    assert "VULNERABLE" in ms17["output"]


def test_parse_tolerates_truncated_xml() -> None:
    findings = parse_nmap_xml(PARTIAL_XML)
    assert isinstance(findings, list)
    # Host A parsed fully even though the trailing host is malformed.
    assert "smb-vuln-ms17-010" in _by_id(findings)


def test_parse_empty_and_garbage_return_empty() -> None:
    assert parse_nmap_xml("") == []
    assert parse_nmap_xml("   ") == []
    assert parse_nmap_xml("this is not xml <<<") == []


def test_summarize_flags_ms17_010_critical() -> None:
    summary = summarize_findings(parse_nmap_xml(VALID_XML))
    ms17 = [f for f in summary if f["script_id"] == "smb-vuln-ms17-010"]
    assert len(ms17) == 1
    assert ms17[0]["severity"] == "critical"
    assert "MS17-010" in ms17[0]["name"]
    assert ms17[0]["host"] == "10.0.0.5"


def test_summarize_flags_weak_tls() -> None:
    summary = summarize_findings(parse_nmap_xml(VALID_XML))
    tls = [f for f in summary if f["script_id"] == "ssl-enum-ciphers"]
    assert tls, "weak TLS should produce at least one finding"
    severities = {f["severity"] for f in tls}
    assert "high" in severities   # RC4 -> high
    assert "medium" in severities  # TLSv1.0 / weak -> medium


def test_summarize_ignores_benign_discovery() -> None:
    summary = summarize_findings(parse_nmap_xml(VALID_XML))
    # modbus-discover has no severity rule, so it is not surfaced as a finding.
    assert not any(f["script_id"] == "modbus-discover" for f in summary)


def test_script_sets_shape() -> None:
    assert set(SCRIPT_SETS) == {"tls", "smb", "snmp", "ics", "discovery"}
    assert SCRIPT_SETS["tls"] == TLS_SCRIPTS == ["ssl-enum-ciphers", "ssl-cert"]
    assert "smb-vuln-ms17-010" in SCRIPT_SETS["smb"]
