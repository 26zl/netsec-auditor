# NetSec Auditor

[![CI](https://github.com/26zl/netsec-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/26zl/netsec-auditor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

One CLI to audit a whole network — IT, cloud, **OT/ICS**, **IoT**, and **Wi-Fi/BLE**
— from a laptop or a **Kali NetHunter** phone. It performs host discovery, port and
service scanning, vulnerability heuristics with EPSS + CISA KEV prioritization,
web-application checks, read-only OT/IoT device identification, passive Wi-Fi/BLE
recon, and wardrive-data import — and writes JSON / HTML / PDF reports.

> **Authorized use only.** Every scan is validated against a defined *scope*.
> Only run this tool against systems you own or have explicit, written
> permission to test.

## Features

- Scope-gated targeting (IPs, hostnames, URLs, CIDR ranges) with include/exclude
  rules and per-scope port allow-lists and scan-rate limits.
- Async port scanning (SYN / connect / UDP) with service and OS detection, plus
  fast connect-sweep discovery for large ranges.
- **OT/ICS + IoT device identification** via read-only protocol probes (Modbus,
  Siemens S7, EtherNet/IP, BACnet, DNP3, OPC-UA, MQTT, CoAP, UPnP/SSDP, mDNS,
  RTSP) — see [Safety](#ot-safety) below.
- **Enterprise service checks:** SNMP default community strings (`public`/
  `private`), SMB dialect + **SMBv1/EternalBlue** detection and signing posture,
  and UDP amplification/reflector exposure (NTP monlist, memcached, chargen, SSDP).
- **Passive discovery** (GRASSMARLIN-style sniffing) that sends zero packets —
  ideal for fragile OT networks.
- Vulnerability heuristics plus a built-in, customizable signature ruleset
  (`netsec_auditor/data/vuln-rules.yaml`), NVD CVE enrichment, and **CVE
  prioritization with EPSS + CISA KEV**.
- Passive external exposure lookups via Shodan InternetDB (no packets to target).
- Web checks: security headers, cookie flags, TLS certificate analysis
  (expiry / self-signed / hostname mismatch), **TLS protocol & weak-cipher
  scanning** (deprecated TLS 1.0/1.1, RC4/3DES), HTTP methods, info disclosure.
- JSON / HTML / PDF reports; `doctor` environment check; `--ot-safe` global mode.

## OT safety

OT/ICS devices are fragile — aggressive scanning can disrupt a PLC or a process.
The toolkit is **safe by default**: environment profiles (`it` / `ot` / `iot`)
set conservative timing, and an interlock automatically downgrades to the gentle
OT profile (single-threaded, delayed, read-only) when an OT service is detected.
All OT/IoT probes are read-only identification only; write/control functions are
never sent.

## Requirements

- Python **3.11+**
- The **`nmap`** binary must be installed and on `PATH` (port scanning is a
  wrapper around nmap via `python-nmap`).
- **Root/sudo** is required for SYN scans (`-sS`, the default), UDP scans, OS
  fingerprinting, ARP discovery, Wi-Fi monitor mode, and passive sniffing. For
  unprivileged scans use `--scan-type connect`.
- The **core install has no system-library requirements.** Optional extras:
  `[wireless]` (BLE, needs BlueZ on Linux) and `[pdf]` (PDF reports, needs
  Pango/HarfBuzz). JSON and HTML reports always work without them.
- Run `netsec-auditor doctor` to see which capabilities are available on the host.

## Platform support

| Platform | Level | Notes |
|---|---|---|
| **Linux / Kali NetHunter** | **Full** | scapy raw sockets, Wi-Fi monitor mode, `nmcli`/`iw`, BLE via BlueZ. Primary target. |
| **WSL2 (Windows)** | **Near-full** | Real Linux kernel: all scanning + pcap ingest work. Wi-Fi monitor needs a USB adapter via `usbipd-win`; BLE usually unavailable; passive LAN sniffing needs Win11 "mirrored" networking (WSL2 NATs by default). |
| **macOS** | Partial | nmap/web/OT/IoT/BLE work; Wi-Fi is read-only via `system_profiler`; BLE returns UUIDs (not MACs). |
| **Windows (native)** | Limited | nmap/web/IP/OT/IoT scanning work; scapy needs Npcap; no monitor mode / `nmcli`. |

IP-layer scanning, vulnerability intel, web/TLS, OT/ICS + IoT identification, and
reporting are cross-platform. Full wireless capability is Linux/NetHunter (or
WSL2 with a USB adapter). Optional external tools — `masscan` (line-rate
discovery), `tshark`, `testssl.sh`, nmap **NSE** scripts — are used automatically
when present; run `doctor` to see what's detected.

**On a plain laptop with built-in Wi-Fi/Bluetooth (no external hardware):**
everything works except monitor-mode 802.11 capture. The `wifi` command
enumerates nearby APs, encryption, WPS and evil-twins through the OS scan
(`nmcli`/`iw`/`system_profiler`) — unprivileged and with the built-in adapter.
`ble` uses the built-in Bluetooth (grant OS Bluetooth permission on macOS). An
external monitor-mode adapter is only needed for frame-level passive capture
(client tracking, `passive` sniffing).

## Installation

```bash
# Recommended — isolated install with pipx
pipx install netsec-auditor
# With BLE recon (bleak) and/or PDF reports (weasyprint)
pipx install "netsec-auditor[wireless]"     # BLE
pipx install "netsec-auditor[all]"          # BLE + PDF

# From source
pip install .
pip install -e ".[dev]"        # for development

# One-liner installer (pipx + nmap hint)
curl -fsSL https://raw.githubusercontent.com/26zl/netsec-auditor/main/scripts/install.sh | sh

# Docker (nmap bundled)
docker run --rm --net=host ghcr.io/26zl/netsec-auditor scan 10.0.0.5 --scan-type connect
```

## Usage

```bash
# Port scan (unprivileged TCP connect scan)
netsec-auditor scan 10.0.0.5 --ports common --scan-type connect

# Host discovery on a network range
netsec-auditor discover 192.168.1.0/24 --method both

# Vulnerability assessment, optionally enriched with NVD CVE data
netsec-auditor vuln 10.0.0.5 --cve-check --nvd-api-key "$NVD_API_KEY"

# Web application scan
netsec-auditor web https://example.com --deep

# Full audit: network + vulnerabilities + web
netsec-auditor full 10.0.0.0/24 --output ./reports

# Fast connect-sweep discovery for a large range
netsec-auditor discover 10.0.0.0/16 --fast

# Identify OT/ICS + IoT devices (read-only, OT-safe profile auto-selected)
netsec-auditor identify 10.0.0.5 --protocols ot

# Prioritize CVEs (EPSS + CISA KEV), or look up an IP's passive exposure
netsec-auditor enrich CVE-2021-44228 CVE-2019-0708
netsec-auditor enrich 203.0.113.10

# Passive inventory — sniff traffic, send nothing (requires root)
sudo netsec-auditor passive --seconds 30 --iface eth0

# Wi-Fi recon — APs, encryption, WPS, evil-twin detection (read-only)
sudo netsec-auditor wifi --iface wlan1mon --duration 20

# BLE recon — advertising IoT devices (no root on Linux/BlueZ)
netsec-auditor ble --duration 10

# Import wardriving data from your ESP32/Flipper/Kismet gadgets
netsec-auditor wardrive capture.wigle.csv --output ./reports

# Walk-around audit — discover + scan + OT/IoT/SNMP + Wi-Fi/BLE → one report
sudo netsec-auditor walk 192.168.1.0/24 --wifi --ble --output ./reports

# Force the gentle OT-safe profile everywhere (fragile ICS networks)
netsec-auditor --ot-safe walk 10.10.0.0/24

# Check the runtime environment (nmap, root, scapy, bleak, Wi-Fi tools)
netsec-auditor doctor

# Query the NVD for a CVE
netsec-auditor cve CVE-2021-44228
```

Global flags: `-v/--verbose` for debug logging and `--json-logs` for structured
JSON log output.

## NetHunter / walk-around use

Built to run on a **Kali NetHunter** phone so a network/cyber engineer can walk a
site and audit as they go:

- **Works unprivileged where it can** — `ble`, `wardrive` import, `discover --fast`,
  and connect-scans need no root. Monitor-mode Wi-Fi (`wifi`, `passive`) and SYN/OS
  scans need root and, for 802.11, an external adapter in monitor mode.
- **OT-safe by default** — the OT profile (gentle, read-only, single-threaded) is
  auto-selected when industrial ports appear, so fragile PLCs aren't disturbed.
- **Gadget integration** — imports **WiGLE CSV (1.4/1.6), GPX and Kismet** exports
  from the ESP32/Flipper tools in the companion
  [gadgets-tools](https://github.com/26zl/gadgets-tools) project.
- **Read-only / passive only** — it receives and catalogs; it never transmits
  deauth/attack frames or cracks handshakes.

### Install on Kali NetHunter (e.g. Galaxy S10)

Kali blocks bare `pip` (PEP 668), so use **pipx** inside the chroot:

```bash
apt install -y nmap pipx bluez           # add: fonts-dejavu libpango-1.0-0 libharfbuzz0b  (only if you want PDF)
pipx install "netsec-auditor[wireless]"  # or [all] to include PDF
netsec-auditor doctor                    # confirm what's available
```

- **Wi-Fi monitor mode:** the **S10 supports internal monitor mode + injection via
  Nexmon** (`nexutil`/`airmon-ng`), so an external adapter isn't strictly required
  — though an AR9271/RTL8812AU adapter is more robust. Run as root inside the chroot.
- **BLE:** needs `bluetoothd` running; in a user-namespaced chroot, export
  `BLEAK_DBUS_AUTH_UID=<host-uid>` so bleak can reach the host D-Bus.
- All aarch64 wheels install cleanly — no compiler/toolchain needed.

## Scope files

A scope defines the authorized targets and exclusions. See
[`config/example-scope.yaml`](config/example-scope.yaml) for the full schema.

```bash
netsec-auditor scope create --file my-scope.yaml   # interactive
netsec-auditor scope validate --file my-scope.yaml --target 10.0.0.5
netsec-auditor scope show --file my-scope.yaml
```

Pass a scope to any scan with `--scope my-scope.yaml`. Without one, an *ad-hoc*
scope authorizing exactly the targets given on the command line is used.

## Development

```bash
pip install -e ".[dev]"
pytest        # run the test suite
ruff check .  # lint
mypy .        # type-check
```

## License

MIT
