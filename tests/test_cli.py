"""Tests for CLI helpers."""

from __future__ import annotations

import ipaddress
import stat
from unittest.mock import AsyncMock

import pytest
import typer
import yaml
from typer.testing import CliRunner

from netsec_auditor.cli import _run_nse_checks, _scan_web_targets, _write_scope_file, app
from netsec_auditor.integrations import nse
from netsec_auditor.scanner.scope import Scope, ScopeError
from netsec_auditor.web.scanner import WebScanResult


def _scope() -> Scope:
    return Scope(name="team", cidr_ranges=["10.0.0.0/24"])


def test_write_scope_file_is_private(tmp_path) -> None:
    path = tmp_path / "team-scope.yaml"
    _write_scope_file(_scope(), path)
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_write_scope_file_refuses_to_overwrite(tmp_path) -> None:
    path = tmp_path / "team-scope.yaml"
    _write_scope_file(_scope(), path)
    with pytest.raises(typer.BadParameter):
        _write_scope_file(_scope(), path)


def test_write_scope_file_refuses_symlink(tmp_path) -> None:
    target = tmp_path / "secret.yaml"
    link = tmp_path / "link-scope.yaml"
    link.symlink_to(target)
    with pytest.raises(typer.BadParameter):
        _write_scope_file(_scope(), link)
    # O_NOFOLLOW means the symlink target is never created through the link.
    assert not target.exists()


def _scope_file(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text(
        yaml.safe_dump({
            "name": "t",
            "cidr_ranges": ["10.0.0.0/24"],
            "excluded_ip_addresses": ["10.0.0.9"],
        }),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    ("args", "expected_code"),
    [
        (["--target", "10.0.0.5"], 0),
        (["--target", "8.8.8.8"], 1),
        (["--target", "10.0.0.9"], 1),
    ],
)
def test_scope_validate_exit_code_reflects_authorization(
    tmp_path, args: list[str], expected_code: int
) -> None:
    # Callers gate scans on this exit code, so a rejected target must not exit 0.
    result = CliRunner().invoke(
        app, ["scope", "validate", "--file", str(_scope_file(tmp_path)), *args]
    )
    assert result.exit_code == expected_code


def test_scope_unknown_action_exits_non_zero(tmp_path) -> None:
    result = CliRunner().invoke(
        app, ["scope", "nonsense", "--file", str(_scope_file(tmp_path))]
    )
    assert result.exit_code == 1


def test_display_escapes_attacker_controlled_names(capsys) -> None:
    # An SSID or device name is broadcast by an untrusted radio; rich would
    # otherwise read "[link=...]" as markup and render a live terminal hyperlink.
    from netsec_auditor.cli import _display_ble, _display_wifi
    from netsec_auditor.wireless.base import AccessPoint, BleDevice, WirelessInventory

    inventory = WirelessInventory()
    inventory.add_ap(
        AccessPoint(bssid="AA:BB:CC:DD:EE:FF", ssid="[link=file:///etc/passwd]x[/link]")
    )
    inventory.add_ble(BleDevice(address="00:11:22:33:44:55", name="[blink]y[/blink]"))

    _display_wifi(inventory)
    _display_ble(inventory)
    out = capsys.readouterr().out

    assert "[link=" in out or "[link…" in out or "[link" in out
    assert "[blink]y[/blink]" in out


def test_web_reports_when_no_targets_could_be_audited() -> None:
    # An unusable target (invalid port) must not exit silently with just a banner.
    result = CliRunner().invoke(app, ["web", "http://127.0.0.1:99999"])
    assert result.exit_code == 0
    assert "No web interfaces could be audited" in result.output


@pytest.mark.parametrize(
    ("target", "outcomes", "expected_urls", "expected_index"),
    [
        ("device.example.test", [True], ["https://device.example.test"], 0),
        (
            "device.example.test", [False, True],
            ["https://device.example.test", "http://device.example.test"], 1,
        ),
        (
            "https://device.example.test", [False],
            ["https://device.example.test"], 0,
        ),
        ("http://device.example.test", [False], ["http://device.example.test"], 0),
        (
            "device.example.test", [False, False],
            ["https://device.example.test", "http://device.example.test"], 1,
        ),
        (
            "device.example.test", [ScopeError("Out of scope"), True],
            ["https://device.example.test", "http://device.example.test"], 1,
        ),
        (
            "device.example.test", [False, ScopeError("Out of scope")],
            ["https://device.example.test", "http://device.example.test"], 0,
        ),
        (
            "device.example.test", [ScopeError("Out of scope"), ScopeError("Out of scope")],
            ["https://device.example.test", "http://device.example.test"], None,
        ),
        (
            "https://device.example.test", [ScopeError("Out of scope")],
            ["https://device.example.test"], None,
        ),
    ],
)
async def test_web_protocol_fallback(target, outcomes, expected_urls, expected_index) -> None:
    responses = [
        outcome if isinstance(outcome, Exception) else WebScanResult(url=url, reachable=outcome)
        for url, outcome in zip(expected_urls, outcomes, strict=True)
    ]
    scanner = AsyncMock()
    scanner.scan.side_effect = responses

    results = await _scan_web_targets(scanner, [target], deep=True, concurrency=1)

    expected = [] if expected_index is None else [responses[expected_index]]
    assert results == expected
    assert [call.args[0] for call in scanner.scan.await_args_list] == expected_urls
    assert all(call.kwargs == {"deep": True} for call in scanner.scan.await_args_list)


def test_full_rejects_invalid_scan_type() -> None:
    result = CliRunner().invoke(app, ["full", "127.0.0.1", "--scan-type", "bogus"])
    assert result.exit_code != 0


def test_full_accepts_scan_type_option() -> None:
    # The option must exist so an unprivileged user can request a connect scan.
    # Introspect the command rather than parse --help, whose width-dependent
    # wrapping splits the option name under CI's narrow terminal.
    import typer

    command = typer.main.get_command(app).commands["full"]  # type: ignore[attr-defined]
    option_names = {name for param in command.params for name in param.opts}
    assert "--scan-type" in option_names


def test_weasyprint_status_reflects_native_library(monkeypatch) -> None:
    # doctor must report weasyprint unusable when the GObject/Pango libs are
    # missing, not merely because the Python module is importable.
    from netsec_auditor import cli

    monkeypatch.setattr("ctypes.util.find_library", lambda _name: None)
    ok, detail, _ = cli._weasyprint_status()
    assert ok is None
    assert "Pango" in detail

    monkeypatch.setattr("ctypes.util.find_library", lambda _name: "/usr/lib/libgobject-2.0.so")
    ok, detail, _ = cli._weasyprint_status()
    assert ok is True
    assert detail == "available"


def _open_host(ip: str, *ports: int):
    from netsec_auditor.scanner.engine import HostResult, PortResult, PortState

    return HostResult(
        ip=ip,
        status="up",
        ports=[PortResult(port=p, protocol="tcp", state=PortState.OPEN) for p in ports],
    )


async def test_nse_checks_probe_only_relevant_open_ports_of_in_scope_hosts(monkeypatch) -> None:
    # NSE gets the scanned address and only the ports each set needs, so it never
    # re-resolves a hostname or runs its own top-1000 port discovery.
    from netsec_auditor import cli

    run_nse = AsyncMock(return_value=[])
    monkeypatch.setattr(nse, "nse_available", lambda: True)
    monkeypatch.setattr(nse, "run_nse", run_nse)
    monkeypatch.setattr(cli, "is_privileged", lambda: False)
    scope = Scope(name="t", cidr_ranges=["10.0.0.0/24"])

    await _run_nse_checks(
        scope, [_open_host("10.0.0.1", 22, 445), _open_host("10.9.9.9", 445)], ["smb", "snmp"]
    )

    # The out-of-scope host is skipped, and SNMP needs a UDP scan, which needs root.
    assert [(c.args[0], c.kwargs["ports"]) for c in run_nse.await_args_list] == [
        ("10.0.0.1", "T:445")
    ]


async def test_nse_checks_use_polite_timing_and_udp_for_ot_hosts(monkeypatch) -> None:
    from netsec_auditor import cli

    run_nse = AsyncMock(return_value=[])
    monkeypatch.setattr(nse, "nse_available", lambda: True)
    monkeypatch.setattr(nse, "run_nse", run_nse)
    monkeypatch.setattr(cli, "is_privileged", lambda: True)
    scope = Scope(name="t", ip_addresses=["10.0.0.7"], max_scan_rate=50)

    await _run_nse_checks(scope, [_open_host("10.0.0.7", 502)], ["ics"])

    call = run_nse.await_args_list[0]
    assert call.kwargs["ports"] == "T:502,U:3671,U:47808"
    assert {"-T2", "--max-parallelism=1", "--max-rate=50"} <= set(call.kwargs["extra_args"])


def test_escape_strips_terminal_control_sequences() -> None:
    # Banners and imported MACs can carry OSC/CSI sequences (window title, clipboard).
    from netsec_auditor.cli import escape

    assert escape("a\x1b]0;pwned\x07b\x9b2J[x]\u202e") == "a]0;pwnedb2J\\[x]"


async def test_web_scan_survives_an_unexpected_error_on_one_target() -> None:
    async def fake_scan(url: str, deep: bool) -> WebScanResult:
        if url == "https://bad.example.test":
            raise LookupError("'rot13' is not a text encoding")
        return WebScanResult(url=url, reachable=True)

    scanner = AsyncMock()
    scanner.scan.side_effect = fake_scan

    results = await _scan_web_targets(
        scanner, ["bad.example.test", "ok.example.test"], deep=False, concurrency=2
    )

    assert sorted(r.url for r in results) == [
        "http://bad.example.test",
        "https://ok.example.test",
    ]


def test_identify_probes_the_validated_ip_with_scope_filtered_udp_ports(
    tmp_path, monkeypatch
) -> None:
    # UDP probes follow --protocols and the scope allow-list, and go to the address
    # that passed the scope check rather than a hostname DNS could answer again.
    from netsec_auditor import cli

    calls: list[tuple[str, list[int], list[int]]] = []

    async def fake_identify(host, ports, _profile, **kwargs):
        calls.append((host, sorted(ports), sorted(kwargs["udp_ports"])))
        return []

    monkeypatch.setattr(cli, "identify_services", fake_identify)
    monkeypatch.setattr(
        Scope, "_resolve_to_ips", staticmethod(lambda _h: (ipaddress.ip_address("10.0.0.7"),))
    )
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        yaml.safe_dump({"name": "t", "domains": ["plc.test"], "allowed_ports": [502, 47808]}),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app, ["identify", "plc.test", "--scope", str(scope_file), "--protocols", "ot"]
    )

    assert result.exit_code == 0, result.output
    assert calls == [("10.0.0.7", [502, 47808], [47808])]


def test_vuln_falls_back_to_connect_scan_and_flags_unscanned_targets(monkeypatch) -> None:
    # Without root nmap refuses SYN scans; that must not read as "0 vulnerabilities".
    from netsec_auditor import cli
    from netsec_auditor.scanner.engine import HostResult, PortScanner, ScanResult

    seen: dict[str, str] = {}

    async def fake_scan_network(self, targets, ports=None, scan_type="syn", **_kwargs):
        seen["scan_type"] = scan_type
        return ScanResult(hosts=[HostResult(ip="10.0.0.5", status="error")])

    monkeypatch.setattr(cli, "is_privileged", lambda: False)
    monkeypatch.setattr(PortScanner, "scan_network", fake_scan_network)

    result = CliRunner().invoke(app, ["vuln", "10.0.0.5"])

    assert result.exit_code == 1, result.output  # incomplete results exit non-zero
    assert seen["scan_type"] == "connect"
    assert "could not scan 1 target" in result.output


def test_walk_report_redacts_wireless_identifiers_unless_disabled(tmp_path, monkeypatch) -> None:
    import json

    from netsec_auditor import cli
    from netsec_auditor.wireless.base import AccessPoint, WirelessInventory

    async def no_live_hosts(*_args, **_kwargs):
        return []

    async def fake_wifi(**_kwargs):
        inventory = WirelessInventory()
        inventory.add_ap(AccessPoint(bssid="00:1A:2B:3C:4D:5E", ssid="Corp"))
        return inventory

    monkeypatch.setattr(cli, "fast_discover", no_live_hosts)
    monkeypatch.setattr(cli, "scan_wifi", fake_wifi)

    for extra, expected in (([], "00:1A:2B:xx:xx:xx"), (["--no-redact"], "00:1A:2B:3C:4D:5E")):
        out = tmp_path / ("plain" if extra else "redacted")
        result = CliRunner().invoke(
            app, ["walk", "10.0.0.0/30", "--wifi", "--output", str(out), *extra]
        )
        assert result.exit_code == 0, result.output
        report = json.loads(next(out.glob("*.json")).read_text(encoding="utf-8"))
        assert report["access_points"][0]["bssid"] == expected


def test_discover_skips_arp_without_root_and_rejects_hostnames(monkeypatch) -> None:
    from netsec_auditor import cli
    from netsec_auditor.scanner.engine import NetworkDiscovery

    arp_scan = AsyncMock(return_value=[])
    monkeypatch.setattr(cli, "is_privileged", lambda: False)
    monkeypatch.setattr(NetworkDiscovery, "ping_sweep", AsyncMock(return_value=["10.0.0.1"]))
    monkeypatch.setattr(NetworkDiscovery, "arp_scan", arp_scan)

    result = CliRunner().invoke(app, ["discover", "10.0.0.0/30"])

    assert result.exit_code == 0, result.output
    assert "ARP scan skipped" in result.output
    assert "10.0.0.1" in result.output
    arp_scan.assert_not_awaited()
    assert CliRunner().invoke(app, ["discover", "localhost"]).exit_code == 2


def test_scope_show_reports_an_unreadable_file_without_a_traceback(tmp_path) -> None:
    result = CliRunner().invoke(
        app, ["scope", "show", "--file", str(tmp_path / "missing.yaml")]
    )

    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)
    assert "Cannot load scope file" in result.output


@pytest.mark.parametrize(("ot_answer", "expected_profile"), [(True, "ot"), (False, "it")])
def test_full_probes_ot_udp_first_and_keeps_ot_hosts_on_the_ot_profile(
    monkeypatch, ot_answer: bool, expected_profile: str
) -> None:
    # A BACnet controller shows only 80/tcp to nmap; its OT UDP probes must not run
    # under the IT profile, and an OT answer must keep the remaining probes gentle.
    from netsec_auditor import cli
    from netsec_auditor.protocols.base import ProbeResult
    from netsec_auditor.scanner.engine import PortScanner, ScanResult

    async def fake_scan_network(self, targets, **_kwargs):
        return ScanResult(hosts=[_open_host("10.0.0.5", 80)])

    calls: list[tuple[str, list[int], str, list[int]]] = []

    async def fake_identify(host, ports, profile, **kwargs):
        calls.append((host, sorted(ports), profile.name, sorted(kwargs["udp_ports"])))
        if len(calls) == 1 and ot_answer:
            return [ProbeResult(protocol="bacnet", port=47808, transport="udp", is_ot=True)]
        return []

    monkeypatch.setattr(PortScanner, "scan_network", fake_scan_network)
    monkeypatch.setattr(cli, "identify_services", fake_identify)
    monkeypatch.setattr(cli, "is_privileged", lambda: False)

    result = CliRunner().invoke(app, ["full", "10.0.0.5", "--no-web"])

    from netsec_auditor.protocols import all_specs

    ot_udp = sorted(s.default_port for s in all_specs() if s.transport == "udp" and s.is_ot)
    assert result.exit_code == 0, result.output
    assert 47808 in ot_udp
    assert calls[0] == ("10.0.0.5", [], "ot", ot_udp)
    host, tcp_ports, profile, udp_ports = calls[1]
    assert (host, tcp_ports, profile) == ("10.0.0.5", [], expected_profile)
    assert 47808 not in udp_ports and 161 in udp_ports


def test_unreadable_wardrive_and_capture_files_exit_non_zero(tmp_path) -> None:
    # A file that cannot be parsed must not be reported as a clean, empty result.
    not_a_capture = tmp_path / "notes.pcap"
    not_a_capture.write_text("hello", encoding="utf-8")
    not_wardrive = tmp_path / "notes.csv"
    not_wardrive.write_text("hello\n", encoding="utf-8")

    pcap_result = CliRunner().invoke(app, ["pcap", str(not_a_capture)])
    wardrive_result = CliRunner().invoke(app, ["wardrive", str(not_wardrive)])

    assert pcap_result.exit_code == 1
    assert "Cannot analyze notes.pcap" in pcap_result.output
    assert wardrive_result.exit_code == 1
    assert "Cannot import notes.csv" in wardrive_result.output


def test_passive_table_shows_layer2_stations_and_escapes_their_identity(monkeypatch) -> None:
    # A PROFINET station has no IP, and its DCP name is attacker-chosen text.
    from netsec_auditor import cli

    class FakeInventory:
        @staticmethod
        def hosts():
            return [{
                "ip": "", "mac": "00:0e:8c:00:00:01", "ports": [], "protocols": ["profinet"],
                "is_ot": True, "is_iot": False,
                "device": {"name_of_station": "[bold]plc-line-1", "device_type": "S7-1500"},
            }]

    class FakeSniffer:
        def __init__(self, **_kwargs) -> None:
            pass

        async def sniff_for(self, *_args, **_kwargs):
            return FakeInventory()

    monkeypatch.setattr(cli, "PassiveSniffer", FakeSniffer)
    result = CliRunner().invoke(app, ["passive", "--seconds", "1"], env={"COLUMNS": "200"})

    assert result.exit_code == 0, result.output
    assert "(layer 2)" in result.output
    assert "[bold]plc-line-1" in result.output
    assert "S7-1500" in result.output
