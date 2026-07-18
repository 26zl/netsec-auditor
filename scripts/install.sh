#!/usr/bin/env bash
#
# netsec-auditor installer.
#
# Installs the `netsec-auditor` CLI, preferring pipx (isolated, PEP 668-safe)
# and falling back to `pip install --user`. Idempotent: safe to re-run to
# upgrade. Also checks for the `nmap` runtime dependency and prints an
# OS-specific install hint if it is missing.
#
# Usage:
#   ./scripts/install.sh
#   curl -fsSL https://raw.githubusercontent.com/26zl/netsec-auditor/main/scripts/install.sh | bash
#
set -euo pipefail

PACKAGE="netsec-auditor"
BINARY="netsec-auditor"

info() { printf '\033[0;34m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[0;33mwarn:\033[0m %s\n' "$1" >&2; }
err()  { printf '\033[0;31merror:\033[0m %s\n' "$1" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

nmap_hint() {
  case "$(uname -s)" in
    Linux)
      if   have apt-get; then echo "sudo apt-get install -y nmap"
      elif have dnf;     then echo "sudo dnf install -y nmap"
      elif have pacman;  then echo "sudo pacman -S --noconfirm nmap"
      elif have zypper;  then echo "sudo zypper install -y nmap"
      elif have apk;     then echo "sudo apk add nmap"
      else                    echo "install the 'nmap' package with your package manager"
      fi ;;
    Darwin)  echo "brew install nmap" ;;
    FreeBSD) echo "sudo pkg install -y nmap" ;;
    *)       echo "install the 'nmap' package with your package manager" ;;
  esac
}

check_nmap() {
  if have nmap; then
    info "nmap found: $(command -v nmap)"
  else
    warn "'nmap' is not on PATH — port scanning needs it. Install with:"
    printf '        %s\n' "$(nmap_hint)" >&2
  fi
}

install_with_pipx() {
  info "Installing ${PACKAGE} with pipx (isolated)..."
  # pipx install fails if it is already installed; upgrade in that case.
  if ! pipx install "${PACKAGE}"; then
    info "${PACKAGE} already installed via pipx — upgrading..."
    pipx upgrade "${PACKAGE}"
  fi
  pipx ensurepath >/dev/null 2>&1 || true
}

install_with_pip() {
  local py=python3
  have python3 || py=python
  have "$py" || { err "Neither pipx nor python3/python found. Install Python 3.11+ first."; exit 1; }

  info "pipx not found — installing ${PACKAGE} with ${py} -m pip (--user)..."
  if ! "$py" -m pip install --user --upgrade "${PACKAGE}"; then
    err "pip install failed."
    err "On Debian / Kali / NetHunter the system Python is externally managed."
    err "Install pipx and retry:"
    printf '        %s\n' "sudo apt-get install -y pipx && pipx install ${PACKAGE}" >&2
    exit 1
  fi
}

main() {
  if have pipx; then
    install_with_pipx
  else
    install_with_pip
  fi

  echo
  check_nmap

  echo
  if have "${BINARY}"; then
    info "Done. '${BINARY}' is on your PATH:"
    printf '        %s\n' "$(command -v "${BINARY}")"
  else
    info "Done. If '${BINARY}' is not found, add your user bin dir to PATH:"
    # shellcheck disable=SC2016  # intentional: print the literal command, unexpanded
    printf '        %s\n' 'export PATH="$HOME/.local/bin:$PATH"'
    printf '        %s\n' "(then restart your shell, or run: pipx ensurepath)"
  fi
}

main "$@"
