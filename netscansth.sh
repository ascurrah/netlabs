#!/usr/bin/env bash
# ============================================================
#  Home Network Security Scanner (Lower-Noise Version)
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

USER_AGENTS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"
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

random_user_agent() {
  echo "${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}"
}

# ── Root check ─────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "nmap SYN scanning requires root privileges."
  err "Re-run with: sudo bash $0"
  exit 1
fi

# ── Argument parsing ───────────────────────────────────────
usage() {
  echo "Usage: sudo bash $0 [-r <CIDR>] [-w <wordlist>]"
  echo "  -r  IP range in CIDR notation  (e.g. 192.168.1.0/24)"
  echo "  -w  Path to gobuster wordlist"
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
  [[ -z "$IP_RANGE" ]] && {
    err "No IP range provided. Exiting."
    exit 1
  }
fi

# ── Dependency checks ──────────────────────────────────────
check_or_install() {
  local tool="$1" pkg="${2:-$1}"

  if ! command -v "$tool" &>/dev/null; then
    warn "'$tool' not found — attempting install..."

    if command -v apt-get &>/dev/null; then
      apt-get update -qq && apt-get install -y "$pkg" -qq
    elif command -v dnf &>/dev/null; then
      dnf install -y "$pkg" -q
    elif command -v pacman &>/dev/null; then
      pacman -Sy --noconfirm "$pkg"
    else
      err "No supported package manager found."
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
  warn "No wordlist found. Gobuster scans will be skipped."
fi

# ── Initial discovery scan ─────────────────────────────────
run_nmap() {
  banner "Low-noise SYN scan → ${IP_RANGE}"
  info "Running SYN scan with slower timing and randomized host order"
  echo ""

  local tmp
  tmp="$(mktemp)"

  nmap \
    -sS \
    -T2 \
    --top-ports 1000 \
    --randomize-hosts \
    --max-retries 2 \
    --scan-delay 100ms \
    -oG "$tmp" \
    "$IP_RANGE" \
    | grep -E "^(Host|Ports|#)" || true

  echo ""

  HTTP_HOSTS=()

  while IFS= read -r line; do
    [[ "$line" =~ ^Host: ]] || continue

    host=$(echo "$line" | awk '{print $2}')

    if echo "$line" | grep -q "80/open"; then
      HTTP_HOSTS+=("$host")
    fi
  done < "$tmp"

  rm -f "$tmp"
}

# ── Targeted follow-up scan ────────────────────────────────
run_followup_scan() {
  local host="$1"

  banner "Targeted follow-up scan → ${host}" "-"

  nmap \
    -sS \
    -T2 \
    -Pn \
    -p 80,443 \
    "$host"
}

# ── gobuster scan ──────────────────────────────────────────
run_gobuster() {
  local host="$1"
  local url="http://${host}"
  local ua

  ua="$(random_user_agent)"

  banner "Gobuster → ${url}" "-"
  info "Using reduced thread count and delayed requests"
  echo ""

  local found=0

  while IFS= read -r line; do
    [[ -n "$line" ]] && {
      echo "  $line"
      found=1
    }
  done < <(
    gobuster dir \
      -u "$url" \
      -w "$WORDLIST" \
      -t 5 \
      --delay 750ms \
      -a "$ua" \
      --no-error \
      -q 2>/dev/null
  )

  [[ $found -eq 0 ]] && info "(no directories/files found)"
}

# ── Main flow ──────────────────────────────────────────────
HTTP_HOSTS=()

run_nmap

if [[ ${#HTTP_HOSTS[@]} -eq 0 ]]; then
  echo ""
  info "No hosts with port 80 open found."
else
  banner "Found ${#HTTP_HOSTS[@]} HTTP host(s)"

  for host in "${HTTP_HOSTS[@]}"; do
    run_followup_scan "$host"

    if [[ -n "$WORDLIST" ]]; then
      run_gobuster "$host"
    fi
  done
fi

banner "Scan complete" "*"
```

## Key Changes

### nmap

* Replaced `-sV` with `-sS`
* Changed timing from `-T4` to `-T2`
* Added `--randomize-hosts`
* Added `--scan-delay 100ms`
* Added `--max-retries 2`
* Added targeted follow-up scans only after host discovery

### gobuster

* Reduced threads from `20` to `5`
* Added `--delay 750ms`
* Added rotating/random User-Agent support
* Kept quiet mode enabled
