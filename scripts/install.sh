#!/usr/bin/env bash
#
# netsec-auditor installer.
#
# Installs a released version of the `netsec-auditor` CLI from the Git repository
# (it is not on PyPI), preferring pipx (isolated, PEP 668-safe) and falling back to
# `pip install --user`. Idempotent: safe to re-run. Also checks for the `nmap`
# runtime dependency and prints an OS-specific install hint if it is missing.
#
# Usage:
#   ./scripts/install.sh
#   NETSEC_AUDITOR_REF=v1.0.9 ./scripts/install.sh   # another tag, or "main"
#
set -euo pipefail

# The release workflow checks that this default matches the tag being published.
REF="${NETSEC_AUDITOR_REF:-v1.0.9}"
PACKAGE="git+https://github.com/26zl/netsec-auditor.git@${REF}"
BINARY="netsec-auditor"

if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
  BLUE=$'\033[0;34m' YELLOW=$'\033[0;33m' RED=$'\033[0;31m' RESET=$'\033[0m'
else
  BLUE="" YELLOW="" RED="" RESET=""
fi

info() { printf '%s==>%s %s\n' "$BLUE" "$RESET" "$1"; }
warn() { printf '%swarn:%s %s\n' "$YELLOW" "$RESET" "$1" >&2; }
err()  { printf '%serror:%s %s\n' "$RED" "$RESET" "$1" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

if [[ ! "$REF" =~ ^[A-Za-z0-9._/-]+$ ]]; then
  err "NETSEC_AUDITOR_REF must be a tag or branch name, got: $REF"
  exit 1
fi

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
  # pipx install fails if it is already installed. "pipx upgrade" takes a package
  # name rather than a URL, so reinstall to pick up the requested ref.
  if ! pipx install "${PACKAGE}"; then
    info "already installed via pipx — reinstalling ${REF}..."
    pipx install --force "${PACKAGE}"
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
    printf '        %s\n' "sudo apt-get install -y pipx && pipx install '${PACKAGE}'" >&2
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
