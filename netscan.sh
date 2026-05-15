#!/usr/bin/env bash
# ============================================================
#  Home Network Security Scanner (Bash)
#  Uses nmap to find open ports, then gobuster on port-80 hosts
#
#  Usage:
#    sudo bash network_scanner.sh
#    sudo bash network_scanner.sh -r 192.168.1.0/24
#    sudo bash network_scanner.sh -r 192.168.1.0/24 -w /path/to/wordlist.txt
# ============================================================

set -euo pipefail

# ── Colours ────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Defaults ───────────────────────────────────────────────
IP_RANGE=""
WORDLIST=""
DEFAULT_WORDLISTS=(
  "/usr/share/wordlists/dirb/common.txt"
  "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
  "/usr/share/seclists/Discovery/Web-Content/common.txt"
)

# ── Helpers ────────────────────────────────────────────────
banner() {
  local text="$1" char="${2:-=}"
  local line; line="$(printf '%0.s'"$char" {1..60})"
  echo -e "\n${BOLD}${CYAN}${line}\n  ${text}\n${line}${RESET}"
}

info()    { echo -e "${GREEN}[*]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
err()     { echo -e "${RED}[!]${RESET} $*" >&2; }

# ── Root check ─────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "nmap port scanning requires root privileges."
  err "Re-run with: sudo bash $0"
  exit 1
fi

# ── Argument parsing ───────────────────────────────────────
usage() {
  echo "Usage: sudo bash $0 [-r <CIDR>] [-w <wordlist>]"
  echo "  -r  IP range in CIDR notation  (e.g. 192.168.1.0/24)"
  echo "  -w  Path to gobuster wordlist   (auto-detected if omitted)"
  exit 0
}

while getopts ":r:w:h" opt; do
  case $opt in
    r) IP_RANGE="$OPTARG" ;;
    w) WORDLIST="$OPTARG" ;;
    h) usage ;;
    :) err "Option -$OPTARG requires an argument."; exit 1 ;;
    \?) err "Unknown option: -$OPTARG"; exit 1 ;;
  esac
done

# ── Prompt for IP range if not supplied ────────────────────
if [[ -z "$IP_RANGE" ]]; then
  read -rp "Enter IP range to scan (e.g. 192.168.1.0/24): " IP_RANGE
  [[ -z "$IP_RANGE" ]] && { err "No IP range provided. Exiting."; exit 1; }
fi

# ── Dependency checks / auto-install ──────────────────────
check_or_install() {
  local tool="$1" pkg="${2:-$1}"
  if ! command -v "$tool" &>/dev/null; then
    warn "'$tool' not found — attempting to install '$pkg'…"
    if command -v apt-get &>/dev/null; then
      apt-get update -qq && apt-get install -y "$pkg" -qq
    elif command -v dnf &>/dev/null; then
      dnf install -y "$pkg" -q
    elif command -v pacman &>/dev/null; then
      pacman -Sy --noconfirm "$pkg"
    else
      err "No supported package manager found. Install '$pkg' manually."
      return 1
    fi
    info "'$pkg' installed successfully."
  fi
}

check_or_install nmap nmap
check_or_install gobuster gobuster

# ── Auto-detect wordlist ───────────────────────────────────
if [[ -z "$WORDLIST" ]]; then
  for path in "${DEFAULT_WORDLISTS[@]}"; do
    if [[ -f "$path" ]]; then
      WORDLIST="$path"
      break
    fi
  done
fi

if [[ -z "$WORDLIST" ]]; then
  warn "No wordlist found. Trying to install 'wordlists' package…"
  if apt-get install -y wordlists -qq 2>/dev/null; then
    for path in "${DEFAULT_WORDLISTS[@]}"; do
      if [[ -f "$path" ]]; then
        WORDLIST="$path"; break
      fi
    done
    # Many distros ship wordlists gzipped — unpack if needed
    if [[ -z "$WORDLIST" ]]; then
      local gz_common="/usr/share/wordlists/dirb/common.txt.gz"
      if [[ -f "$gz_common" ]]; then
        gunzip "$gz_common"
        WORDLIST="${gz_common%.gz}"
      fi
    fi
  fi
fi

if [[ -z "$WORDLIST" ]]; then
  warn "Could not locate a wordlist. gobuster scans will be skipped."
  warn "Supply one manually with -w /path/to/wordlist.txt"
fi

# ── nmap scan ─────────────────────────────────────────────
run_nmap() {
  banner "nmap scan  →  ${IP_RANGE}"
  info "Scanning top 1000 ports (-sV -T4). This may take a few minutes…"
  echo ""

  # Capture nmap output; also print it live
  local tmp; tmp="$(mktemp)"

  nmap -sV -T4 --top-ports 1000 -oG "$tmp" "$IP_RANGE" \
    | grep -E "^(Host|Ports|#)" || true

  echo ""

  # Parse the grepable output to collect port-80 hosts
  HTTP_HOSTS=()
  while IFS= read -r line; do
    # Only lines that contain at least one open port
    [[ "$line" =~ ^Host: ]] || continue
    host=$(echo "$line" | awk '{print $2}')
    if echo "$line" | grep -q "80/open"; then
      HTTP_HOSTS+=("$host")
    fi
  done < "$tmp"

  rm -f "$tmp"
}

# ── gobuster scan ─────────────────────────────────────────
run_gobuster() {
  local host="$1"
  local url="http://${host}"
  banner "gobuster  →  ${url}" "-"
  info "Wordlist : ${WORDLIST}"
  echo ""

  local found=0
  while IFS= read -r line; do
    [[ -n "$line" ]] && { echo "  $line"; found=1; }
  done < <(
    gobuster dir \
      -u "$url" \
      -w "$WORDLIST" \
      -t 20 \
      --no-error \
      -q 2>/dev/null
  )

  [[ $found -eq 0 ]] && info "(no directories/files found)"
}

# ── Main flow ─────────────────────────────────────────────
HTTP_HOSTS=()   # populated by run_nmap
run_nmap

if [[ ${#HTTP_HOSTS[@]} -eq 0 ]]; then
  echo ""
  info "No hosts with port 80 open found. Skipping gobuster."
else
  banner "Found ${#HTTP_HOSTS[@]} host(s) with port 80 open → running gobuster"
  if [[ -z "$WORDLIST" ]]; then
    warn "No wordlist available — skipping gobuster scans."
  else
    for host in "${HTTP_HOSTS[@]}"; do
      run_gobuster "$host"
    done
  fi
fi

banner "Scan complete" "*"
