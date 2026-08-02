<div align="center">

<img src="docs/logo.png" alt="NetSec Auditor" width="120">

<img src="docs/wordmark.png" alt="NetSec Auditor" width="500">

**authorized network · OT/ICS · web · wireless security auditor**

[![CI](https://github.com/26zl/netsec-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/26zl/netsec-auditor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

</div>

# NetSec Auditor

One CLI to audit a whole network — IT, cloud, **OT/ICS**, **IoT**, and **Wi-Fi/BLE**
— from a laptop or a **Kali NetHunter** phone. It performs host discovery, port and
service scanning, vulnerability heuristics with EPSS + CISA KEV prioritization,
device web-interface checks, read-only OT/IoT device identification, passive Wi-Fi/BLE
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
- **Device web-interface audit** (router / camera / NAS / printer / PLC / HMI /
  BMS panels): security headers, cookie flags, TLS certificate analysis
  (expiry / self-signed / hostname mismatch), **TLS protocol & weak-cipher
  scanning** (deprecated TLS 1.0/1.1, RC4/3DES), HTTP methods, info disclosure.
  Strictly read-only — a posture check of the device's admin UI, not web-app pentesting.
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
WSL2 with a USB adapter). Optional `masscan` accelerates privileged
`discover --fast` runs. Curated nmap **NSE** checks are available with
`vuln --nse`; run `doctor` to see which runtime capabilities are available.

**On a plain laptop with built-in Wi-Fi/Bluetooth (no external hardware):**
everything works except monitor-mode 802.11 capture. The `wifi` command
enumerates nearby APs, encryption, WPS and evil-twins through the OS scan
(`nmcli`/`iw`/`system_profiler`) — unprivileged and with the built-in adapter.
`ble` uses the built-in Bluetooth (grant OS Bluetooth permission on macOS). An
external monitor-mode adapter is only needed for frame-level passive capture
(client tracking, `passive` sniffing).

## Installation

```bash
pipx install git+https://github.com/26zl/netsec-auditor.git
```

That is the whole install. It is not on PyPI — installing straight from the
repository keeps one source of truth and means a release is just a tag.

```bash
# With the optional extras (BLE + PDF)
pipx install "netsec-auditor[all] @ git+https://github.com/26zl/netsec-auditor.git"

# Pin to a released version
pipx install git+https://github.com/26zl/netsec-auditor.git@v1.0.0

# From a checkout
pip install .
pip install -e ".[dev]"        # for development

# Local Docker image (nmap bundled)
docker build -t netsec-auditor:local .
docker run --rm --net=host netsec-auditor:local scan 10.0.0.5 --scan-type connect
```

Every [release](https://github.com/26zl/netsec-auditor/releases) also carries a
built wheel and sdist if you would rather install the artifact directly.

`scripts/install.sh` wraps the same command and adds an `nmap` check.

## Usage

```bash
# Port scan (unprivileged TCP connect scan)
netsec-auditor scan 10.0.0.5 --ports common --scan-type connect

# Host discovery on a network range
netsec-auditor discover 192.168.1.0/24 --method both

# Vulnerability assessment, optionally enriched with NVD CVE data
# Export NVD_API_KEY in the environment first; avoid placing secrets in shell history.
netsec-auditor vuln 10.0.0.5 --cve-check
# --nse runs the curated SMB/SNMP/TLS scripts; --nse-ics adds the ICS/OT scripts,
# which nmap classes as intrusive because they send protocol requests to PLCs.
netsec-auditor vuln 10.0.0.5 --nse --nse-ics

# Device web-interface audit (router / camera / NAS / PLC / HMI admin panels)
netsec-auditor web https://192.168.1.1 --deep

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
netsec-auditor wardrive capture.wigle.csv --ssid ACME- --no-redact  # narrow + full detail

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
- **OT-aware safety interlock** — scans that include registered industrial ports
  and protocol identification use gentle timing, read-only probes and one worker.
  Validate the profile against the target environment before scanning fragile PLCs.
- **Gadget integration** — imports **WiGLE CSV (1.4/1.6), GPX and Kismet** exports
  from the ESP32/Flipper tools in the companion
  [gadgets-tools](https://github.com/26zl/gadgets-tools) project.
- **Read-only** — it receives and catalogs; it never transmits deauth/attack
  frames or cracks handshakes. Monitor-mode capture is fully passive; the
  `nmcli`/`iw`/`system_profiler` fallback and BLE scanning delegate to the OS,
  which performs a normal active scan (probe requests / SCAN_REQ).

### Install on Kali NetHunter (e.g. Galaxy S10)

Kali blocks bare `pip` (PEP 668), so use **pipx** inside the chroot:

```bash
apt install -y nmap pipx bluez           # add: fonts-dejavu libpango-1.0-0 libharfbuzz0b  (only if you want PDF)
pipx install ".[wireless]"               # from the source checkout; use [all] for PDF
netsec-auditor doctor                    # confirm what's available
```

- **Wi-Fi monitor mode:** the **S10 supports internal monitor mode + injection via
  Nexmon** (`nexutil`/`airmon-ng`), so an external adapter isn't strictly required
  — though an AR9271/RTL8812AU adapter is more robust. Run as root inside the chroot.
- **BLE:** needs `bluetoothd` running; in a user-namespaced chroot, export
  `BLEAK_DBUS_AUTH_UID=<host-uid>` so bleak can reach the host D-Bus.
- Verify wheel and native-library availability on the specific aarch64/NetHunter
  image before deployment.

## Third-party data

Wi-Fi and wardrive captures record every network in range, most belonging to
people who are not the audit subject. Reports therefore **redact by default**:
BSSIDs and client MACs are truncated to their vendor OUI and GPS coordinates are
rounded to ~1 km. Use `--no-redact` when the engagement covers the full detail,
and `--ssid` on `wardrive` to import only the networks in question.

`enrich <ip>` sends the address to Shodan InternetDB — a third party. Non-global
addresses are never sent; public ones leave your network, so check that this is
acceptable under the engagement's confidentiality terms.

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
