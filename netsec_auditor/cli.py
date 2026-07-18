"""CLI entry point for NetSec Auditor — authorized security scanning toolkit."""

from __future__ import annotations

import asyncio
import ipaddress
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from netsec_auditor.capture.pcap import analyze_pcap
from netsec_auditor.discovery import PassiveSniffer, fast_discover
from netsec_auditor.discovery.masscan import masscan_discover
from netsec_auditor.integrations import nse
from netsec_auditor.intel import EpssClient, InternetDbClient, KevCatalog, enrich_cves
from netsec_auditor.profiles import IOT_PORTS, OT_PORTS, apply_interlock, get_profile
from netsec_auditor.protocols import all_specs
from netsec_auditor.protocols.scan import identify_services
from netsec_auditor.report.generator import ReportGenerator
from netsec_auditor.scanner.engine import (
    COMMON_PORTS,
    TOP_1000_PORTS,
    NetworkDiscovery,
    PortScanner,
    is_privileged,
)
from netsec_auditor.scanner.scope import Scope, ScopeManager
from netsec_auditor.utils.logging import configure_logging, get_logger
from netsec_auditor.vuln.detector import CVEQueryClient, VulnerabilityScanner
from netsec_auditor.web.scanner import WebScanner
from netsec_auditor.wireless import WirelessInventory, detect_evil_twins
from netsec_auditor.wireless.ble import scan_ble
from netsec_auditor.wireless.wifi import scan_wifi
from netsec_auditor.wireless.wigle import load_wardrive

app = typer.Typer(
    name="netsec-auditor",
    help="Network Security Auditor — authorized infrastructure security scanning toolkit",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
logger = get_logger(__name__)

scope_manager = ScopeManager()
_STATE = {"ot_safe": False}


@app.callback()
def callback(
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose logging"),
    ] = False,
    json_logs: Annotated[
        bool,
        typer.Option("--json-logs", help="Output logs in JSON format"),
    ] = False,
    ot_safe: Annotated[
        bool,
        typer.Option("--ot-safe", help="Force the gentle OT-safe profile for all probing"),
    ] = False,
) -> None:
    """NetSec Auditor — authorized security scanning toolkit."""
    level = "DEBUG" if verbose else "INFO"
    configure_logging(level=level, json_output=json_logs)
    _STATE["ot_safe"] = ot_safe


def _probe_profile(open_ports: set[int]):
    """Pick the identification profile, honouring a forced --ot-safe."""
    if _STATE["ot_safe"]:
        return get_profile("ot")
    return apply_interlock(get_profile("it"), open_ports, forced=False)


@app.command()
def scan(
    targets: Annotated[
        list[str],
        typer.Argument(help="Target IPs, CIDR ranges, or hostnames to scan"),
    ],
    scope_file: Annotated[
        Path | None,
        typer.Option(
            "--scope", "-s",
            exists=True,
            help="Path to scope definition YAML file",
        ),
    ] = None,
    ports: Annotated[
        str,
        typer.Option(
            "--ports", "-p",
            help="Ports to scan (comma-separated, 'common', 'top1000', or 'all')",
        ),
    ] = "common",
    scan_type: Annotated[
        str,
        typer.Option(
            "--scan-type", "-t",
            help="Scan type: syn, connect, udp",
        ),
    ] = "syn",
    service_detection: Annotated[
        bool,
        typer.Option(
            "--service-detection/--no-service-detection",
            help="Enable service version detection",
        ),
    ] = True,
    os_detection: Annotated[
        bool,
        typer.Option("--os-detection/--no-os-detection", help="Enable OS fingerprinting"),
    ] = False,
    concurrency: Annotated[
        int,
        typer.Option("--concurrency", "-c", help="Max concurrent scans"),
    ] = 10,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output directory for reports"),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Report format: json, html, pdf, all"),
    ] = "all",
) -> None:
    """Run a network port scan against authorized targets."""
    scope = _load_scope(scope_file, targets)

    port_list = _parse_ports(ports)

    console.print(Panel.fit(
        f"[bold cyan]NetSec Auditor — Network Scan[/bold cyan]\n"
        f"Targets: {len(targets)} | Ports: {len(port_list)} | "
        f"Type: {scan_type} | Service detection: {service_detection}",
        border_style="cyan",
    ))

    scanner = PortScanner(scope=scope)

    async def _run() -> None:
        result = await scanner.scan_network(
            targets=targets,
            ports=port_list,
            scan_type=scan_type,
            service_detection=service_detection,
            os_detection=os_detection,
            concurrency=concurrency,
        )
        _display_scan_results(result)

        if output or format != "none":
            report_gen = ReportGenerator(output_dir=output)
            paths = report_gen.generate_all(
                scan_result=result,
                title="Network Scan Report",
                scope_name=scope.name,
            )
            console.print("\n[green]Reports generated:[/green]")
            for fmt_name, path in paths.items():
                console.print(f"  {fmt_name}: {path}")

    asyncio.run(_run())


@app.command()
def discover(
    cidr: Annotated[
        str,
        typer.Argument(help="CIDR range to discover (e.g., 192.168.1.0/24)"),
    ],
    scope_file: Annotated[
        Path | None,
        typer.Option("--scope", "-s", exists=True, help="Scope definition YAML"),
    ] = None,
    method: Annotated[
        str,
        typer.Option("--method", "-m", help="Discovery method: ping, arp, both"),
    ] = "both",
    fast: Annotated[
        bool,
        typer.Option("--fast", help="Fast connect-sweep for large ranges (unprivileged)"),
    ] = False,
) -> None:
    """Discover live hosts on a network."""
    scope = _load_scope(scope_file, [cidr])

    console.print(f"[cyan]Discovering hosts on {cidr}...[/cyan]")

    discovery = NetworkDiscovery(scope=scope)

    async def _run() -> None:
        if fast:
            scope.validate_target(cidr)
            # masscan needs root; use it only when privileged, else connect-sweep.
            hosts = await masscan_discover([cidr]) if is_privileged() else None
            source = "masscan"
            if hosts is None:
                hosts = await fast_discover([cidr])
                source = "connect-sweep"
            console.print(f"[green]Fast discovery ({source}): {len(hosts)} live hosts[/green]")
            if hosts:
                table = Table(title="Discovered Hosts")
                table.add_column("IP Address", style="cyan")
                for host in hosts:
                    table.add_row(host)
                console.print(table)
            else:
                console.print("[yellow]No live hosts discovered.[/yellow]")
            return

        live_hosts: list[str] = []

        if method in ("ping", "both"):
            hosts = await discovery.ping_sweep(cidr)
            live_hosts.extend(hosts)
            console.print(f"[green]Ping sweep: {len(hosts)} hosts found[/green]")

        if method in ("arp", "both"):
            arp_results = await discovery.arp_scan(cidr)
            for r in arp_results:
                if r["ip"] not in live_hosts:
                    live_hosts.append(r["ip"])
            console.print(f"[green]ARP scan: {len(arp_results)} hosts found[/green]")

        if live_hosts:
            table = Table(title="Discovered Hosts")
            table.add_column("IP Address", style="cyan")
            table.add_column("MAC Address", style="green")
            for host in sorted(set(live_hosts)):
                mac = next(
                    (r["mac"] for r in arp_results if r["ip"] == host), "N/A"
                ) if method in ("arp", "both") else "N/A"
                table.add_row(host, mac)
            console.print(table)
        else:
            console.print("[yellow]No live hosts discovered.[/yellow]")

    asyncio.run(_run())


@app.command()
def vuln(
    targets: Annotated[
        list[str],
        typer.Argument(help="Target IPs or hostnames to scan for vulnerabilities"),
    ],
    scope_file: Annotated[
        Path | None,
        typer.Option("--scope", "-s", exists=True, help="Scope definition YAML"),
    ] = None,
    ports: Annotated[
        str,
        typer.Option("--ports", "-p", help="Ports to scan"),
    ] = "common",
    cve_check: Annotated[
        bool,
        typer.Option("--cve-check/--no-cve-check", help="Query NVD for CVEs"),
    ] = False,
    nvd_api_key: Annotated[
        str | None,
        typer.Option("--nvd-api-key", help="NVD API key for CVE queries"),
    ] = None,
    use_nse: Annotated[
        bool,
        typer.Option("--nse", help="Also run curated nmap NSE deep checks (needs nmap)"),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output directory for reports"),
    ] = None,
) -> None:
    """Scan targets for known vulnerabilities and misconfigurations."""
    scope = _load_scope(scope_file, targets)
    port_list = _parse_ports(ports)

    console.print(Panel.fit(
        f"[bold red]NetSec Auditor — Vulnerability Scan[/bold red]\n"
        f"Targets: {len(targets)} | Ports: {len(port_list)} | CVE check: {cve_check}",
        border_style="red",
    ))

    scanner = PortScanner(scope=scope)
    vuln_scanner = VulnerabilityScanner()
    cve_client = CVEQueryClient(api_key=nvd_api_key or "") if cve_check else None

    async def _run() -> None:
        scan_result = await scanner.scan_network(
            targets=targets,
            ports=port_list,
            service_detection=True,
            concurrency=10,
        )

        vuln_results = await vuln_scanner.scan_hosts(scan_result.hosts)

        if cve_client:
            for vr in vuln_results:
                for vuln in vr.vulnerabilities:
                    if vuln.cve_id:
                        cve_detail = await cve_client.get_cve(vuln.cve_id)
                        if cve_detail:
                            vuln.cvss_score = cve_detail.get("cvss_score", 0.0)
                            vuln.cvss_vector = cve_detail.get("cvss_vector", "")
                            vuln.references = cve_detail.get("references", [])

        _display_vuln_results(vuln_results)
        await _display_cve_priorities(vuln_results)

        if use_nse:
            await _run_nse_checks(targets, ["smb", "snmp", "ics", "tls"])

        if output:
            report_gen = ReportGenerator(output_dir=output)
            paths = report_gen.generate_all(
                scan_result=scan_result,
                vuln_results=vuln_results,
                title="Vulnerability Assessment Report",
                scope_name=scope.name,
            )
            console.print("\n[green]Reports generated:[/green]")
            for fmt_name, path in paths.items():
                console.print(f"  {fmt_name}: {path}")

        if cve_client:
            await cve_client.close()

    asyncio.run(_run())


@app.command()
def web(
    urls: Annotated[
        list[str],
        typer.Argument(help="URLs to scan for web vulnerabilities"),
    ],
    scope_file: Annotated[
        Path | None,
        typer.Option("--scope", "-s", exists=True, help="Scope definition YAML"),
    ] = None,
    deep: Annotated[
        bool,
        typer.Option("--deep/--quick", help="Deep scan with directory enumeration and crawling"),
    ] = False,
    concurrency: Annotated[
        int,
        typer.Option("--concurrency", "-c", help="Max concurrent requests"),
    ] = 10,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output directory for reports"),
    ] = None,
) -> None:
    """Scan web applications for security vulnerabilities."""
    scope = _load_scope(scope_file, urls)

    console.print(Panel.fit(
        f"[bold magenta]NetSec Auditor — Web Application Scan[/bold magenta]\n"
        f"URLs: {len(urls)} | Deep scan: {deep}",
        border_style="magenta",
    ))

    web_scanner = WebScanner(scope=scope, concurrency=concurrency)

    async def _run() -> None:
        results = []
        for url in urls:
            result = await web_scanner.scan(url, deep=deep)
            results.append(result)
            _display_web_result(result)

        if output:
            report_gen = ReportGenerator(output_dir=output)
            paths = report_gen.generate_all(
                web_results=results,
                title="Web Application Security Report",
                scope_name=scope.name,
            )
            console.print("\n[green]Reports generated:[/green]")
            for fmt_name, path in paths.items():
                console.print(f"  {fmt_name}: {path}")

        await web_scanner.close()

    asyncio.run(_run())


@app.command()
def full(
    targets: Annotated[
        list[str],
        typer.Argument(help="Target IPs, CIDR ranges, hostnames, or URLs"),
    ],
    scope_file: Annotated[
        Path | None,
        typer.Option("--scope", "-s", exists=True, help="Scope definition YAML"),
    ] = None,
    ports: Annotated[
        str,
        typer.Option("--ports", "-p", help="Ports to scan"),
    ] = "common",
    web_scan: Annotated[
        bool,
        typer.Option("--web/--no-web", help="Include web application scan"),
    ] = True,
    deep_web: Annotated[
        bool,
        typer.Option("--deep-web", help="Deep web scan with enumeration"),
    ] = False,
    cve_check: Annotated[
        bool,
        typer.Option("--cve-check/--no-cve-check", help="Query NVD for CVEs"),
    ] = False,
    nvd_api_key: Annotated[
        str | None,
        typer.Option("--nvd-api-key", help="NVD API key"),
    ] = None,
    concurrency: Annotated[
        int,
        typer.Option("--concurrency", "-c", help="Max concurrent operations"),
    ] = 10,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output directory for reports"),
    ] = None,
) -> None:
    """Run a full security audit — network scan, vulnerability assessment, and web scan."""
    scope = _load_scope(scope_file, targets)
    port_list = _parse_ports(ports)

    console.print(Panel.fit(
        "[bold yellow]NetSec Auditor — Full Security Audit[/bold yellow]\n"
        f"Targets: {len(targets)} | Ports: {len(port_list)} | "
        f"Web: {web_scan} | CVE: {cve_check}",
        border_style="yellow",
    ))

    scanner = PortScanner(scope=scope)
    vuln_scanner = VulnerabilityScanner()
    cve_client = CVEQueryClient(api_key=nvd_api_key or "") if cve_check else None
    web_scanner = WebScanner(scope=scope, concurrency=concurrency) if web_scan else None

    async def _run() -> None:
        console.print("\n[bold]Phase 1/4: Network Discovery & Port Scanning[/bold]")
        scan_result = await scanner.scan_network(
            targets=targets,
            ports=port_list,
            service_detection=True,
            os_detection=True,
            concurrency=concurrency,
        )
        _display_scan_results(scan_result)

        console.print("\n[bold]Phase 2/4: Vulnerability Assessment[/bold]")
        vuln_results = await vuln_scanner.scan_hosts(scan_result.hosts)

        if cve_client:
            console.print("  Querying NVD for CVE details...")
            for vr in vuln_results:
                for vuln in vr.vulnerabilities:
                    if vuln.cve_id:
                        cve_detail = await cve_client.get_cve(vuln.cve_id)
                        if cve_detail:
                            vuln.cvss_score = cve_detail.get("cvss_score", 0.0)
                            vuln.cvss_vector = cve_detail.get("cvss_vector", "")
                            vuln.references = cve_detail.get("references", [])

        _display_vuln_results(vuln_results)
        cve_priorities = await _display_cve_priorities(vuln_results)

        web_results = []
        if web_scanner:
            console.print("\n[bold]Phase 3/4: Web Application Scan[/bold]")
            for target in targets:
                for scheme in ("https://", "http://"):
                    url = f"{scheme}{target}"
                    try:
                        result = await web_scanner.scan(url, deep=deep_web)
                        web_results.append(result)
                        _display_web_result(result)
                        break
                    except Exception:
                        continue

        console.print("\n[bold]Phase 4/4: OT/IoT Device Identification[/bold]")
        identified = []
        tcp_probe = {s.default_port for s in all_specs() if s.transport == "tcp"}
        udp_probe = sorted({s.default_port for s in all_specs() if s.transport == "udp"})
        for host in scan_result.hosts:
            host_ports = [p.port for p in host.open_ports if p.port in tcp_probe] + udp_probe
            prof = _probe_profile(set(host_ports))
            for probe in await identify_services(host.ip, host_ports, prof):
                probe.extra["host"] = host.ip
                identified.append(probe)
        for probe in identified:
            info = ", ".join(f"{k}={v}" for k, v in list(probe.device_info.items())[:3])
            console.print(
                f"  [green]{probe.extra.get('host')}[/green] "
                f"{probe.protocol} {probe.port}/{probe.transport} — {info}"
            )

        if output:
            report_gen = ReportGenerator(output_dir=output)
            paths = report_gen.generate_all(
                scan_result=scan_result,
                vuln_results=vuln_results,
                web_results=web_results if web_results else None,
                identified_services=identified or None,
                cve_priorities=cve_priorities or None,
                title="Full Security Audit Report",
                scope_name=scope.name,
            )
            console.print("\n[green]Reports generated:[/green]")
            for fmt_name, path in paths.items():
                console.print(f"  {fmt_name}: {path}")

        if cve_client:
            await cve_client.close()
        if web_scanner:
            await web_scanner.close()

    asyncio.run(_run())


@app.command()
def scope(
    action: Annotated[
        str,
        typer.Argument(help="Action: create, validate, show"),
    ],
    scope_file: Annotated[
        Path | None,
        typer.Option("--file", "-f", help="Scope YAML file"),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option("--target", "-t", help="Target to validate against scope"),
    ] = None,
) -> None:
    """Manage and validate scanning scopes."""
    if action == "create":
        _create_scope(scope_file)
    elif action == "validate":
        if not scope_file or not target:
            console.print("[red]--file and --target are required for validation[/red]")
            raise typer.Exit(1)
        scope = Scope.from_yaml(scope_file)
        try:
            scope.validate_target(target)
            console.print(f"[green]Target {target} is within authorized scope.[/green]")
        except Exception as e:
            console.print(f"[red]{e}[/red]")
    elif action == "show":
        if not scope_file:
            console.print("[red]--file is required[/red]")
            raise typer.Exit(1)
        scope = Scope.from_yaml(scope_file)
        console.print_json(data=scope.to_dict())
    else:
        console.print(f"[red]Unknown action: {action}[/red]")


@app.command()
def cve(
    query: Annotated[
        str,
        typer.Argument(help="CVE ID or search keyword"),
    ],
    api_key: Annotated[
        str | None,
        typer.Option("--api-key", help="NVD API key"),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-l", help="Max results"),
    ] = 10,
) -> None:
    """Query the NVD for CVE information."""
    client = CVEQueryClient(api_key=api_key or "")

    async def _run() -> None:
        if query.upper().startswith("CVE-"):
            result = await client.get_cve(query.upper())
            if result:
                console.print_json(data=result)
            else:
                console.print(f"[yellow]CVE {query} not found.[/yellow]")
        else:
            results = await client.search_cve(query, limit=limit)
            if results:
                table = Table(title=f"CVEs matching '{query}'")
                table.add_column("CVE ID", style="cyan")
                table.add_column("Severity", style="red")
                table.add_column("Score")
                table.add_column("Description")
                for r in results:
                    table.add_row(
                        r["cve_id"],
                        r["severity"].upper(),
                        str(r["cvss_score"]),
                        r["description"][:100] + "...",
                    )
                console.print(table)
            else:
                console.print(f"[yellow]No CVEs found for '{query}'.[/yellow]")

        await client.close()

    asyncio.run(_run())


@app.command()
def identify(
    targets: Annotated[
        list[str],
        typer.Argument(help="Target IPs or hostnames to identify"),
    ],
    scope_file: Annotated[
        Path | None,
        typer.Option("--scope", "-s", exists=True, help="Scope definition YAML"),
    ] = None,
    protocols: Annotated[
        str,
        typer.Option("--protocols", help="Which probes to run: ot, iot, all"),
    ] = "all",
    profile: Annotated[
        str,
        typer.Option("--profile", help="Safety profile: auto, it, ot, iot"),
    ] = "auto",
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Per-probe timeout in seconds"),
    ] = 5.0,
) -> None:
    """Identify OT/ICS and IoT devices via read-only protocol probes (safe by default)."""
    scope = _load_scope(scope_file, targets)

    if protocols == "ot":
        ports = sorted(OT_PORTS)
    elif protocols == "iot":
        ports = sorted(IOT_PORTS)
    else:
        ports = sorted({spec.default_port for spec in all_specs()})

    forced = profile != "auto"
    base_profile = get_profile(profile if forced else "it")
    # Probing industrial ports defaults to the gentle OT profile unless overridden.
    prof = apply_interlock(base_profile, set(ports), forced=forced)
    if _STATE["ot_safe"]:
        prof = get_profile("ot")

    console.print(Panel.fit(
        "[bold cyan]NetSec Auditor — Device Identification[/bold cyan]\n"
        f"Targets: {len(targets)} | Probes: {len(ports)} | "
        f"Profile: [bold]{prof.name}[/bold] "
        f"(concurrency {prof.max_concurrency}, delay {prof.scan_delay}s)",
        border_style="cyan",
    ))
    if prof.name == "ot":
        console.print("[yellow]OT-safe mode: read-only probes only, gentle timing.[/yellow]")

    async def _run() -> None:
        table = Table(title="Identified Services")
        table.add_column("Host", style="cyan")
        table.add_column("Protocol", style="green")
        table.add_column("Port")
        table.add_column("Type")
        table.add_column("Device Info")

        found = False
        for target in targets:
            try:
                scope.validate_target(target)
            except Exception as e:
                console.print(f"[red]{e}[/red]")
                continue
            results = await identify_services(target, ports, prof, timeout=timeout)
            for r in results:
                found = True
                info = ", ".join(f"{k}={v}" for k, v in list(r.device_info.items())[:4])
                table.add_row(
                    target, r.protocol, f"{r.port}/{r.transport}",
                    "OT" if r.is_ot else "IoT", info or (r.banner[:60] or "—"),
                )

        if found:
            console.print(table)
        else:
            console.print("[yellow]No OT/IoT services identified.[/yellow]")

    asyncio.run(_run())


@app.command()
def enrich(
    items: Annotated[
        list[str],
        typer.Argument(help="CVE IDs (CVE-YYYY-NNNN) and/or IP addresses"),
    ],
    nvd_api_key: Annotated[
        str | None,
        typer.Option("--nvd-api-key", help="NVD API key (for CVE CVSS lookup)"),
    ] = None,
) -> None:
    """Enrich CVEs with EPSS + CISA KEV priority, or look up an IP's passive exposure."""
    cves = [x.upper() for x in items if x.upper().startswith("CVE-")]
    ips = [x for x in items if not x.upper().startswith("CVE-")]

    async def _run() -> None:
        if ips:
            idb = InternetDbClient()
            table = Table(title="Passive Exposure — Shodan InternetDB (no packets sent to target)")
            table.add_column("IP", style="cyan")
            table.add_column("Open Ports")
            table.add_column("Tags")
            table.add_column("Known Vulns", style="red")
            for ip in ips:
                data = await idb.lookup(ip)
                if data:
                    ports = ", ".join(str(p) for p in data.get("ports", [])[:15])
                    tags = ", ".join(data.get("tags", [])[:6])
                    vulns = ", ".join(data.get("vulns", [])[:6]) or "—"
                    table.add_row(ip, ports or "—", tags or "—", vulns)
                else:
                    table.add_row(ip, "[dim]no data[/dim]", "—", "—")
            console.print(table)
            await idb.close()

        if cves:
            cve_client = CVEQueryClient(api_key=nvd_api_key or "")
            cvss_by_cve: dict[str, float] = {}
            for cve_id in cves:
                detail = await cve_client.get_cve(cve_id)
                cvss_by_cve[cve_id] = detail.get("cvss_score", 0.0) if detail else 0.0
            await cve_client.close()

            epss_client = EpssClient()
            kev_catalog = KevCatalog()
            enriched = await enrich_cves(cves, cvss_by_cve, epss_client, kev_catalog)
            await epss_client.close()
            await kev_catalog.close()

            order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            rows = sorted(enriched.values(), key=lambda r: order.get(r["priority"], 9))

            table = Table(title="CVE Prioritization (CVSS + EPSS + CISA KEV)")
            table.add_column("CVE", style="cyan")
            table.add_column("Priority")
            table.add_column("CVSS")
            table.add_column("EPSS %ile")
            table.add_column("KEV")
            colors = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue"}
            for r in rows:
                color = colors.get(r["priority"], "white")
                table.add_row(
                    r["cve_id"],
                    f"[{color}]{r['priority'].upper()}[/{color}]",
                    f"{r['cvss']:.1f}",
                    f"{r['percentile'] * 100:.0f}%",
                    "[red]YES[/red]" if r["in_kev"] else "no",
                )
            console.print(table)

    asyncio.run(_run())


@app.command()
def passive(
    seconds: Annotated[
        float,
        typer.Option("--seconds", "-t", help="Capture duration in seconds"),
    ] = 30.0,
    iface: Annotated[
        str | None,
        typer.Option("--iface", "-i", help="Network interface to sniff"),
    ] = None,
    bpf: Annotated[
        str | None,
        typer.Option("--filter", help="BPF capture filter"),
    ] = None,
) -> None:
    """Passively inventory hosts by sniffing traffic — zero packets sent (requires root)."""
    console.print(Panel.fit(
        "[bold green]NetSec Auditor — Passive Discovery[/bold green]\n"
        f"Capturing {seconds}s | Interface: {iface or 'default'} | Zero packets sent",
        border_style="green",
    ))

    sniffer = PassiveSniffer(bpf_filter=bpf)

    async def _run() -> None:
        inventory = await sniffer.sniff_for(seconds, iface=iface)
        hosts = inventory.hosts()
        if not hosts:
            console.print(
                "[yellow]No hosts observed. Passive capture needs root + scapy; "
                "check the interface.[/yellow]"
            )
            return

        table = Table(title=f"Passive Inventory ({len(hosts)} hosts)")
        table.add_column("IP", style="cyan")
        table.add_column("MAC")
        table.add_column("Ports")
        table.add_column("Protocols")
        table.add_column("Class")
        for host in hosts:
            cls = "OT" if host["is_ot"] else ("IoT" if host["is_iot"] else "IT")
            table.add_row(
                host["ip"],
                host["mac"] or "—",
                ", ".join(str(p) for p in host["ports"][:10]) or "—",
                ", ".join(host["protocols"][:6]) or "—",
                cls,
            )
        console.print(table)

    asyncio.run(_run())


@app.command()
def wifi(
    iface: Annotated[
        str | None,
        typer.Option("--iface", "-i", help="Wireless interface (monitor mode for full capture)"),
    ] = None,
    duration: Annotated[
        float,
        typer.Option("--duration", "-t", help="Scan duration in seconds"),
    ] = 15.0,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output directory for a report"),
    ] = None,
) -> None:
    """Passive Wi-Fi recon — enumerate APs, encryption, WPS and clients (read-only)."""
    console.print(Panel.fit(
        "[bold magenta]NetSec Auditor — Wi-Fi Recon[/bold magenta]\n"
        f"Interface: {iface or 'auto'} | Duration: {duration}s | Passive/read-only",
        border_style="magenta",
    ))

    async def _run() -> None:
        inventory = await scan_wifi(iface=iface, duration=duration)
        detect_evil_twins(inventory.aps())
        _display_wifi(inventory)
        if output:
            ReportGenerator(output_dir=output).generate_all(
                wireless=inventory, title="Wi-Fi Recon Report"
            )
            console.print(f"\n[green]Report written to {output}[/green]")

    asyncio.run(_run())


@app.command()
def ble(
    duration: Annotated[
        float,
        typer.Option("--duration", "-t", help="Scan duration in seconds"),
    ] = 10.0,
    adapter: Annotated[
        str | None,
        typer.Option("--adapter", help="Bluetooth adapter (e.g. hci0)"),
    ] = None,
) -> None:
    """Passive BLE recon — enumerate advertising IoT devices (read-only)."""
    console.print(Panel.fit(
        "[bold blue]NetSec Auditor — BLE Recon[/bold blue]\n"
        f"Duration: {duration}s | Passive advertisement scan",
        border_style="blue",
    ))

    async def _run() -> None:
        inventory = WirelessInventory()
        for device in await scan_ble(duration=duration, adapter=adapter):
            inventory.add_ble(device)
        _display_ble(inventory)

    asyncio.run(_run())


@app.command()
def wardrive(
    file: Annotated[
        Path,
        typer.Argument(exists=True, help="WiGLE CSV / GPX / Kismet netxml export"),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output directory for a report"),
    ] = None,
) -> None:
    """Import and audit wardriving data exported by ESP32/Flipper/Kismet gadgets."""
    inventory = WirelessInventory()
    for ap in load_wardrive(file):
        inventory.add_ap(ap)
    detect_evil_twins(inventory.aps())

    console.print(Panel.fit(
        "[bold magenta]NetSec Auditor — Wardrive Import[/bold magenta]\n"
        f"Source: {file.name} | Access points: {len(inventory.aps())}",
        border_style="magenta",
    ))
    _display_wifi(inventory)
    if output:
        ReportGenerator(output_dir=output).generate_all(
            wireless=inventory, title="Wardrive Audit Report"
        )
        console.print(f"\n[green]Report written to {output}[/green]")


@app.command()
def walk(
    cidr: Annotated[
        str,
        typer.Argument(help="Local network CIDR to sweep (e.g. 192.168.1.0/24)"),
    ],
    scope_file: Annotated[
        Path | None,
        typer.Option("--scope", "-s", exists=True, help="Scope definition YAML"),
    ] = None,
    wifi_scan: Annotated[
        bool,
        typer.Option("--wifi", help="Include Wi-Fi recon"),
    ] = False,
    ble_scan: Annotated[
        bool,
        typer.Option("--ble", help="Include BLE recon"),
    ] = False,
    iface: Annotated[
        str | None,
        typer.Option("--iface", "-i", help="Wireless interface for Wi-Fi recon"),
    ] = None,
    duration: Annotated[
        float,
        typer.Option("--duration", "-t", help="Wireless scan duration in seconds"),
    ] = 15.0,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output directory for the combined report"),
    ] = None,
) -> None:
    """Walk-around audit: discover, scan, identify OT/IoT, and optionally Wi-Fi/BLE."""
    scope = _load_scope(scope_file, [cidr])
    console.print(Panel.fit(
        "[bold yellow]NetSec Auditor — Walk-Around Audit[/bold yellow]\n"
        f"Network: {cidr} | Wi-Fi: {wifi_scan} | BLE: {ble_scan}",
        border_style="yellow",
    ))

    async def _run() -> None:
        scope.validate_target(cidr)
        console.print("\n[bold]Discovering live hosts...[/bold]")
        hosts = await fast_discover([cidr])
        console.print(f"[green]{len(hosts)} live hosts[/green]")

        scan_result = None
        vuln_results = []
        identified = []
        cve_priorities = []
        if hosts:
            scanner = PortScanner(scope=scope)
            scan_result = await scanner.scan_network(
                targets=hosts, ports=COMMON_PORTS, scan_type="connect", concurrency=20
            )
            _display_scan_results(scan_result)

            vuln_scanner = VulnerabilityScanner()
            vuln_results = await vuln_scanner.scan_hosts(scan_result.hosts)
            _display_vuln_results(vuln_results)
            cve_priorities = await _display_cve_priorities(vuln_results)

            probe_ports = OT_PORTS | IOT_PORTS
            for host in scan_result.hosts:
                host_ports = [p.port for p in host.open_ports if p.port in probe_ports]
                if not host_ports:
                    continue
                prof = apply_interlock(get_profile("it"), set(host_ports), forced=False)
                for probe in await identify_services(host.ip, host_ports, prof):
                    probe.extra["host"] = host.ip
                    identified.append(probe)

        inventory = WirelessInventory()
        if wifi_scan:
            console.print("\n[bold]Wi-Fi recon...[/bold]")
            inventory = await scan_wifi(iface=iface, duration=duration)
            detect_evil_twins(inventory.aps())
            _display_wifi(inventory)
        if ble_scan:
            console.print("\n[bold]BLE recon...[/bold]")
            for device in await scan_ble(duration=duration):
                inventory.add_ble(device)
            _display_ble(inventory)

        if output:
            ReportGenerator(output_dir=output).generate_all(
                scan_result=scan_result,
                vuln_results=vuln_results or None,
                identified_services=identified or None,
                wireless=inventory,
                cve_priorities=cve_priorities or None,
                title="Walk-Around Audit Report",
                scope_name=scope.name,
            )
            console.print(f"\n[green]Combined report written to {output}[/green]")

    asyncio.run(_run())


@app.command()
def doctor() -> None:
    """Check the runtime environment and which capabilities are available."""
    import importlib.util
    import platform
    import shutil

    table = Table(title="NetSec Auditor — Environment")
    table.add_column("Capability", style="cyan")
    table.add_column("Status")
    table.add_column("Enables")

    marks = {True: "[green]✓[/green]", None: "[yellow]—[/yellow]", False: "[red]✗[/red]"}

    def row(name: str, ok: bool | None, detail: str, enables: str) -> None:
        table.add_row(f"{marks[ok]} {name}", detail, enables)

    version = platform.python_version_tuple()
    py_ok = (int(version[0]), int(version[1])) >= (3, 11)
    row("Python 3.11+", py_ok, platform.python_version(), "core")
    row("Platform", True, f"{platform.system()} {platform.machine()}", "—")
    has_nmap = shutil.which("nmap")
    row("nmap", has_nmap is not None, has_nmap or "missing", "scan / vuln / full")
    priv = is_privileged()
    row("Root/privileged", priv or None, "yes" if priv else "no", "privileged scans, sniff")

    for module, enables in (
        ("scapy", "Wi-Fi monitor, ARP, passive"),
        ("bleak", "BLE recon"),
        ("cryptography", "TLS certificate analysis"),
        ("weasyprint", "PDF reports"),
    ):
        present = importlib.util.find_spec(module) is not None
        row(module, present, "available" if present else "not installed", enables)

    wifi_tool = next(
        (t for t in ("nmcli", "iw", "system_profiler") if shutil.which(t)), None
    )
    row("Wi-Fi scan tool", wifi_tool is not None, wifi_tool or "none", "wifi fallback")

    for tool, enables in (
        ("masscan", "line-rate discovery (discover --fast)"),
        ("tshark", "richer pcap dissection"),
    ):
        present = shutil.which(tool) is not None
        row(tool, present or None, "available" if present else "optional", enables)

    is_wsl = "microsoft" in platform.release().lower()
    if is_wsl:
        row("WSL", None, "detected", "Linux-level scanning; USB passthrough for radios")

    console.print(table)


def _display_wifi(inventory: WirelessInventory) -> None:
    """Display Wi-Fi access points and their security findings."""
    aps = inventory.aps()
    if not aps:
        console.print(
            "[yellow]No access points found (Wi-Fi recon needs a capable adapter).[/yellow]"
        )
        return
    table = Table(title=f"Wi-Fi Access Points ({len(aps)})")
    table.add_column("SSID", style="cyan")
    table.add_column("BSSID")
    table.add_column("Ch")
    table.add_column("Encryption")
    table.add_column("Signal")
    table.add_column("Issues", style="red")
    for ap in aps:
        enc = ap.encryption.upper() + (" +WPS" if ap.wps else "")
        table.add_row(
            ap.ssid or "[dim](hidden)[/dim]", ap.bssid, str(ap.channel or "—"),
            enc, f"{ap.signal_dbm} dBm" if ap.signal_dbm else "—",
            "; ".join(ap.issues) or "—",
        )
    console.print(table)


def _display_ble(inventory: WirelessInventory) -> None:
    """Display BLE devices and their security findings."""
    devices = inventory.ble()
    if not devices:
        console.print(
            "[yellow]No BLE devices found (needs bleak, a Bluetooth adapter, and OS "
            "Bluetooth permission — on macOS grant it in Privacy settings).[/yellow]"
        )
        return
    table = Table(title=f"BLE Devices ({len(devices)})")
    table.add_column("Name", style="cyan")
    table.add_column("Address")
    table.add_column("RSSI")
    table.add_column("Vendor")
    table.add_column("Issues", style="red")
    for device in devices:
        table.add_row(
            device.name or "[dim](unnamed)[/dim]", device.address, str(device.rssi),
            device.vendor or "—", "; ".join(device.issues) or "—",
        )
    console.print(table)


@app.command()
def pcap(
    file: Annotated[
        Path,
        typer.Argument(exists=True, help="PCAP/PCAPNG capture (e.g. a gadget export)"),
    ],
) -> None:
    """Analyze an offline capture — host inventory and cleartext credentials."""
    result = analyze_pcap(file)
    hosts = result["hosts"]
    creds = result["credentials"]
    console.print(Panel.fit(
        "[bold green]NetSec Auditor — PCAP Analysis[/bold green]\n"
        f"File: {file.name} | Packets: {result['packet_count']} | "
        f"Hosts: {len(hosts)} | Cleartext creds: {len(creds)}",
        border_style="green",
    ))

    if hosts:
        table = Table(title="Hosts")
        table.add_column("IP", style="cyan")
        table.add_column("MAC")
        table.add_column("Ports")
        table.add_column("Protocols")
        for host in hosts[:50]:
            table.add_row(
                host["ip"], host.get("mac", "") or "—",
                ", ".join(str(p) for p in host.get("ports", [])[:8]) or "—",
                ", ".join(host.get("protocols", [])[:6]) or "—",
            )
        console.print(table)

    if creds:
        ctable = Table(title="Cleartext Credentials (passwords redacted)")
        ctable.add_column("Protocol", style="red")
        ctable.add_column("Host")
        ctable.add_column("Port")
        ctable.add_column("Evidence")
        for cred in creds[:50]:
            ctable.add_row(cred["protocol"], cred["host"], str(cred["port"]), cred["evidence"])
        console.print(ctable)
    else:
        console.print("[green]No cleartext credentials found.[/green]")


async def _run_nse_checks(targets: list[str], script_sets: list[str]) -> None:
    """Run curated nmap NSE script sets and display the summarized findings."""
    if not nse.nse_available():
        console.print("[yellow]nmap not found — NSE deep checks skipped.[/yellow]")
        return
    console.print("\n[bold]Running nmap NSE deep checks...[/bold]")
    findings: list[dict] = []
    for target in targets:
        for set_name in script_sets:
            raw = await nse.run_nse(target, nse.SCRIPT_SETS.get(set_name, []))
            findings.extend(nse.summarize_findings(raw))
    if not findings:
        console.print("[green]NSE checks found nothing notable.[/green]")
        return
    table = Table(title="NSE Findings")
    table.add_column("Severity")
    table.add_column("Host", style="cyan")
    table.add_column("Finding")
    colors = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue"}
    for f in findings:
        color = colors.get(f.get("severity", ""), "white")
        table.add_row(
            f"[{color}]{f.get('severity', '').upper()}[/{color}]",
            str(f.get("host", "")),
            f.get("name", ""),
        )
    console.print(table)


def _load_scope(scope_file: Path | None, targets: list[str]) -> Scope:
    """Load scope from file or build a default ad-hoc scope from CLI targets."""
    if scope_file:
        return Scope.from_yaml(scope_file)

    cidrs: list[str] = []
    ips: list[str] = []
    domains: list[str] = []
    for raw in targets:
        host = urlparse(raw).hostname if "://" in raw else raw
        host = (host or raw).strip()
        if "/" in host:
            try:
                ipaddress.ip_network(host, strict=False)
                cidrs.append(host)
                continue
            except ValueError:
                pass
        try:
            ipaddress.ip_address(host)
            ips.append(host)
            continue
        except ValueError:
            pass
        domains.append(host)

    return Scope(
        name="ad-hoc-scan",
        description=f"Ad-hoc scan of {', '.join(targets[:3])}",
        cidr_ranges=cidrs,
        domains=domains,
        ip_addresses=ips,
        authorized_by="CLI operator",
        authorization_date="",
    )


def _parse_ports(ports: str) -> list[int]:
    """Parse port specification string."""
    ports = ports.lower().strip()
    if ports == "common":
        return COMMON_PORTS
    if ports == "top1000":
        return TOP_1000_PORTS
    if ports == "all":
        return list(range(1, 65536))
    try:
        result: list[int] = []
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                result.extend(range(int(start), int(end) + 1))
            else:
                result.append(int(part))
        return result
    except ValueError:
        console.print(f"[red]Invalid port specification: {ports}[/red]")
        raise typer.Exit(1) from None


def _display_scan_results(result) -> None:
    """Display scan results in a rich table."""
    table = Table(title="Scan Results")
    table.add_column("Host", style="cyan")
    table.add_column("Hostname")
    table.add_column("OS")
    table.add_column("Open Ports")
    table.add_column("Status")
    table.add_column("Duration")

    for host in result.hosts:
        ports_str = ", ".join(
            f"{p.port}/{p.protocol}"
            for p in host.open_ports[:10]
        )
        if len(host.open_ports) > 10:
            ports_str += f" ... (+{len(host.open_ports) - 10})"

        status_color = "green" if host.status == "up" else "red"
        table.add_row(
            host.ip,
            host.hostname or "N/A",
            host.os or "Unknown",
            ports_str or "None",
            f"[{status_color}]{host.status}[/{status_color}]",
            f"{host.scan_duration:.1f}s",
        )

    console.print(table)
    console.print(
        f"\n[bold]Summary:[/bold] {result.hosts_up} up, "
        f"{result.hosts_down} down | Duration: {result.duration:.1f}s"
    )

    open_ports = {p.port for h in result.hosts for p in h.open_ports}
    if open_ports & OT_PORTS:
        console.print(
            "[yellow]OT/ICS ports detected — run 'identify --profile ot' for "
            "safe read-only device identification.[/yellow]"
        )
    elif open_ports & IOT_PORTS:
        console.print(
            "[cyan]IoT ports detected — run 'identify --protocols iot' to "
            "fingerprint devices.[/cyan]"
        )


def _display_vuln_results(vuln_results) -> None:
    """Display vulnerability results."""
    total_vulns = sum(len(vr.vulnerabilities) for vr in vuln_results)
    total_critical = sum(vr.critical_count for vr in vuln_results)
    total_high = sum(vr.high_count for vr in vuln_results)
    total_medium = sum(vr.medium_count for vr in vuln_results)
    total_low = sum(vr.low_count for vr in vuln_results)

    table = Table(title="Vulnerability Summary")
    table.add_column("Host", style="cyan")
    table.add_column("Critical", style="red")
    table.add_column("High", style="orange3")
    table.add_column("Medium", style="yellow")
    table.add_column("Low", style="blue")
    table.add_column("Risk Score")

    for vr in vuln_results:
        table.add_row(
            vr.host,
            str(vr.critical_count),
            str(vr.high_count),
            str(vr.medium_count),
            str(vr.low_count),
            f"{vr.risk_score:.1f}",
        )

    console.print(table)
    console.print(
        f"\n[bold]Total:[/bold] {total_vulns} vulnerabilities "
        f"([red]{total_critical} critical[/red], "
        f"[orange3]{total_high} high[/orange3], "
        f"[yellow]{total_medium} medium[/yellow], "
        f"[blue]{total_low} low[/blue])"
    )

    if total_vulns > 0:
        console.print("\n[bold]Top Findings:[/bold]")
        all_vulns = []
        for vr in vuln_results:
            all_vulns.extend(vr.vulnerabilities)
        all_vulns.sort(key=lambda v: v.severity.to_score(), reverse=True)

        for vuln in all_vulns[:10]:
            severity_color = {
                "critical": "red",
                "high": "orange3",
                "medium": "yellow",
                "low": "blue",
                "info": "dim",
            }.get(vuln.severity.value, "white")

            console.print(
                f"  [{severity_color}]{vuln.severity.value.upper():8}[/{severity_color}] "
                f"{vuln.name} ({vuln.affected_host}:{vuln.affected_port})"
            )


async def _display_cve_priorities(vuln_results) -> list[dict]:
    """Enrich CVE-bearing findings with EPSS + CISA KEV and display priorities."""
    cvss_by_cve: dict[str, float] = {}
    for vr in vuln_results:
        for vuln in vr.vulnerabilities:
            if vuln.cve_id:
                cvss_by_cve[vuln.cve_id] = max(
                    cvss_by_cve.get(vuln.cve_id, 0.0), vuln.cvss_score
                )
    if not cvss_by_cve:
        return []

    epss_client = EpssClient()
    kev_catalog = KevCatalog()
    enriched = await enrich_cves(list(cvss_by_cve), cvss_by_cve, epss_client, kev_catalog)
    await epss_client.close()
    await kev_catalog.close()

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows = sorted(enriched.values(), key=lambda r: order.get(r["priority"], 9))

    table = Table(title="CVE Prioritization (CVSS + EPSS + CISA KEV)")
    table.add_column("CVE", style="cyan")
    table.add_column("Priority")
    table.add_column("EPSS %ile")
    table.add_column("KEV")
    colors = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue"}
    for r in rows:
        color = colors.get(r["priority"], "white")
        table.add_row(
            r["cve_id"],
            f"[{color}]{r['priority'].upper()}[/{color}]",
            f"{r['percentile'] * 100:.0f}%",
            "[red]YES[/red]" if r["in_kev"] else "no",
        )
    console.print(table)
    return rows


def _display_web_result(result) -> None:
    """Display web scan result."""
    console.print(f"\n[bold magenta]{result.url}[/bold magenta]")
    console.print(f"  Server: {result.server or 'Unknown'}")
    console.print(f"  Technologies: {', '.join(result.technologies) or 'None detected'}")

    if result.ssl_certificate:
        ssl = result.ssl_certificate
        if ssl.is_expired:
            console.print("  [red]SSL: EXPIRED[/red]")
        elif ssl.days_until_expiry < 30:
            console.print(f"  [yellow]SSL: {ssl.days_until_expiry} days until expiry[/yellow]")
        else:
            console.print(f"  [green]SSL: Valid ({ssl.days_until_expiry} days)[/green]")
        if ssl.issues:
            for issue in ssl.issues:
                console.print(f"    [yellow]- {issue}[/yellow]")

    if result.vulnerabilities:
        console.print(f"  [red]Vulnerabilities: {len(result.vulnerabilities)}[/red]")
        for vuln in result.vulnerabilities[:5]:
            console.print(f"    [{vuln.severity}]{vuln.name}[/{vuln.severity}]")

    if result.discovered_directories:
        console.print(f"  [cyan]Directories found: {len(result.discovered_directories)}[/cyan]")


def _create_scope(scope_file: Path | None) -> None:
    """Interactive scope creation."""
    console.print("[bold]Create New Scan Scope[/bold]\n")

    name = typer.prompt("Scope name")
    description = typer.prompt("Description", default="")
    cidr_ranges = typer.prompt("CIDR ranges (comma-separated)", default="").split(",")
    cidr_ranges = [c.strip() for c in cidr_ranges if c.strip()]
    domains = typer.prompt("Domains (comma-separated)", default="").split(",")
    domains = [d.strip() for d in domains if d.strip()]
    ip_addresses = typer.prompt("Individual IPs (comma-separated)", default="").split(",")
    ip_addresses = [i.strip() for i in ip_addresses if i.strip()]
    excluded = typer.prompt("Excluded CIDR ranges (comma-separated)", default="").split(",")
    excluded = [e.strip() for e in excluded if e.strip()]
    authorized_by = typer.prompt("Authorized by (name/email)", default="")
    authorization_ref = typer.prompt("Authorization reference (ticket/contract #)", default="")

    scope = Scope(
        name=name,
        description=description,
        cidr_ranges=cidr_ranges,
        domains=domains,
        ip_addresses=ip_addresses,
        excluded_cidr_ranges=excluded,
        authorized_by=authorized_by,
        authorization_ref=authorization_ref,
    )

    output_path = scope_file or Path(f"{name.replace(' ', '_').lower()}-scope.yaml")
    import yaml

    with open(output_path, "w") as f:
        yaml.dump(scope.to_dict(), f, default_flow_style=False, sort_keys=False)

    console.print(f"\n[green]Scope saved to {output_path}[/green]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
