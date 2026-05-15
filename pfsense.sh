#!/usr/bin/env bash
# ============================================================
#  pfSense Lab Setup — Open Red Team → Target Network
#
#  Adds a firewall PASS rule allowing all traffic from the
#  red team subnet (192.168.1.0/24) to the target subnet
#  (10.30.0.0/24), and removes any blocking rules between
#  the two. Operates over SSH using pfSense's PHP shell.
#
#  Prerequisites on your Kali machine:
#    sudo apt install sshpass
#
#  Usage:
#    bash pfsense_open_redteam.sh
#    bash pfsense_open_redteam.sh -H 192.168.1.1 -u labadmin -p labadmin
# ============================================================

set -euo pipefail

# ── Defaults (match your topology) ────────────────────────
PFSENSE_HOST="192.168.1.1"
PFSENSE_USER="labadmin"
PFSENSE_PASS="labadmin"
RED_SUBNET="192.168.1.0/24"
TARGET_SUBNET="10.30.0.0/24"

# ── Colours ────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${GREEN}[*]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
banner(){ echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════\n  $*\n══════════════════════════════════════════════════════════${RESET}"; }

# ── Argument parsing ───────────────────────────────────────
while getopts ":H:u:p:" opt; do
  case $opt in
    H) PFSENSE_HOST="$OPTARG" ;;
    u) PFSENSE_USER="$OPTARG" ;;
    p) PFSENSE_PASS="$OPTARG" ;;
    \?) warn "Unknown option -$OPTARG"; exit 1 ;;
  esac
done

# ── Dependency check ───────────────────────────────────────
if ! command -v sshpass &>/dev/null; then
  warn "sshpass not found — installing…"
  apt-get install -y sshpass -qq
fi

banner "pfSense Lab Setup — Red Team Firewall Rules"
info "Target pfSense : ${PFSENSE_HOST}"
info "Red subnet     : ${RED_SUBNET}"
info "Target subnet  : ${TARGET_SUBNET}"

# ── SSH helper ─────────────────────────────────────────────
# Runs a PHP snippet in pfSense's built-in PHP shell (-c /usr/local/sbin/pfSsh.php)
pf_php() {
  sshpass -p "${PFSENSE_PASS}" ssh \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=10 \
    "${PFSENSE_USER}@${PFSENSE_HOST}" \
    "pfSsh.php playback listsync" \
    <<< "$1" 2>/dev/null || true
}

# Simpler: run a raw shell command on pfSense
pf_cmd() {
  sshpass -p "${PFSENSE_PASS}" ssh \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=10 \
    "${PFSENSE_USER}@${PFSENSE_HOST}" \
    "$1" 2>/dev/null
}

# ── Step 1: Test connectivity ──────────────────────────────
banner "Step 1 — Testing SSH connectivity"
if pf_cmd "echo 'SSH OK'" | grep -q "SSH OK"; then
  info "SSH connection successful."
else
  warn "Cannot reach pfSense over SSH."
  warn "Make sure SSH is enabled: pfSense GUI → System → Advanced → Admin Access → Secure Shell"
  exit 1
fi

# ── Step 2: Remove blocking rules via PHP shell ────────────
banner "Step 2 — Removing block rules between red team and target"

# PHP payload — injected into pfSense's PHP shell.
# Iterates all firewall rules and disables any that:
#   - have type "block" or "reject"
#   - and whose source or destination overlaps our two subnets
READ_RULES_PHP=$(cat <<'PHP'
<?php
require_once("guiconfig.inc");
require_once("filter.inc");

$config = parse_config();
$rules  = &$config['filter']['rule'];
$changed = 0;

$red_net    = "192.168.1.0/24";
$target_net = "10.30.0.0/24";

foreach ($rules as $idx => &$rule) {
    $type = $rule['type'] ?? 'pass';
    if (!in_array($type, ['block','reject'])) continue;

    $src  = $rule['source']['network']  ?? ($rule['source']['address']  ?? '');
    $dst  = $rule['destination']['network'] ?? ($rule['destination']['address'] ?? '');

    // Match rules that block traffic between our two subnets (either direction)
    $match = (
        (str_contains($src, "192.168.1") && str_contains($dst, "10.30.0")) ||
        (str_contains($src, "10.30.0")   && str_contains($dst, "192.168.1"))
    );

    if ($match) {
        echo "  Disabling rule #{$idx}: {$type}  {$src} → {$dst}\n";
        $rules[$idx]['disabled'] = true;
        $changed++;
    }
}

if ($changed > 0) {
    write_config("Lab setup: disabled {$changed} block rule(s) red<->target");
    echo "[*] Disabled {$changed} blocking rule(s).\n";
} else {
    echo "[*] No matching block rules found (may already be open).\n";
}
PHP
)

pf_php "$READ_RULES_PHP"

# ── Step 3: Add an explicit PASS rule ─────────────────────
banner "Step 3 — Adding PASS rule: ${RED_SUBNET} → ${TARGET_SUBNET}"

ADD_RULE_PHP=$(cat <<'PHP'
<?php
require_once("guiconfig.inc");
require_once("filter.inc");

$config = parse_config();
$rules  = &$config['filter']['rule'];

// Check if the rule already exists
foreach ($rules as $rule) {
    $src = $rule['source']['network']      ?? '';
    $dst = $rule['destination']['network'] ?? '';
    if ($src === "192.168.1.0/24" && $dst === "10.30.0.0/24" && $rule['type'] === 'pass') {
        echo "[*] PASS rule already exists — nothing to add.\n";
        exit(0);
    }
}

// Build the new rule
$new_rule = [
    'type'        => 'pass',
    'ipprotocol'  => 'inet',
    'protocol'    => 'any',
    'interface'   => 'lan',        // adjust to your red-team-facing interface name if different
    'source'      => ['network' => '192.168.1.0/24'],
    'destination' => ['network' => '10.30.0.0/24'],
    'descr'       => 'Lab setup: Red team -> Target network',
    'tracker'     => (int)(microtime(true) * 1000),
];

// Prepend so it is evaluated before any default deny
array_unshift($rules, $new_rule);

write_config("Lab setup: added red-team → target PASS rule");
echo "[*] PASS rule added successfully.\n";
PHP
)

pf_php "$ADD_RULE_PHP"

# ── Step 4: Reload the firewall filter ─────────────────────
banner "Step 4 — Reloading pfSense firewall filter"
pf_cmd "pfSsh.php playback svc restart filterlog" 2>/dev/null || true
pf_cmd "/etc/rc.filter_configure_sync" 2>/dev/null \
  && info "Filter reloaded." \
  || warn "Could not reload filter automatically — apply changes manually in the GUI."

# ── Step 5: Verify ────────────────────────────────────────
banner "Step 5 — Verification"
info "Testing ping from pfSense → 10.30.0.235 (Metasploitable)…"
if pf_cmd "ping -c 3 -W 2 10.30.0.235" | grep -q "bytes from"; then
  info "pfSense can reach the target network. ✓"
else
  warn "pfSense ping to target failed — check routing on the target subnet."
fi

echo ""
info "Done. Test from your Kali machine with:"
echo "      ping 10.30.0.235"
echo "      ping 10.30.0.236"
echo "      ping 10.30.0.237"
echo ""
warn "Remember to re-enable SSH on pfSense if it was off before this run."
