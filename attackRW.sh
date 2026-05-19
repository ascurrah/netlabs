#!/bin/bash

# =========================================================
# IRTx Interactive Attack Framework
# Author: Student Red Team Framework
# Purpose:
#   Guided low-noise reconnaissance and exploitation workflow
# =========================================================

clear

# -------------------------------
# Colours
# -------------------------------

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
NC="\e[0m"

# -------------------------------
# Functions
# -------------------------------

pause() {
    echo
    read -rp "Press ENTER to continue..."
}

section() {
    echo
    echo -e "${BLUE}=================================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${BLUE}=================================================${NC}"
    echo
}

# -------------------------------
# Root Check
# -------------------------------

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Run this script as root${NC}"
    exit 1
fi

# -------------------------------
# Dependency Check
# -------------------------------

section "Checking Required Tools"

TOOLS=(
    nmap
    gobuster
    hydra
    curl
    ssh
    smbclient
)

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "${GREEN}[+]${NC} $tool installed"
    else
        echo -e "${RED}[-]${NC} $tool missing"
    fi
done

pause

# =========================================================
# PHASE 1 — Target Discovery
# =========================================================

section "PHASE 1 — Low Noise Network Discovery"

read -rp "Enter target subnet/range: " TARGET_RANGE
read -rp "Enter ports to scan (comma separated): " TARGET_PORTS
read -rp "Enter excluded hosts (comma separated or blank): " EXCLUDE_HOSTS

echo
echo -e "${YELLOW}[+] Starting low-noise SYN scan...${NC}"
echo

if [[ -n "$EXCLUDE_HOSTS" ]]; then
    nmap -Pn -sS -T1 \
    --max-retries 1 \
    --scan-delay 1s \
    --randomize-hosts \
    --exclude "$EXCLUDE_HOSTS" \
    -p "$TARGET_PORTS" \
    "$TARGET_RANGE"
else
    nmap -Pn -sS -T1 \
    --max-retries 1 \
    --scan-delay 1s \
    --randomize-hosts \
    -p "$TARGET_PORTS" \
    "$TARGET_RANGE"
fi

pause

# =========================================================
# PHASE 2 — Target Validation
# =========================================================

section "PHASE 2 — Target Validation"

read -rp "Enter target IP discovered: " TARGET_IP
read -rp "Enter ports to validate: " VALIDATION_PORTS

echo
echo -e "${YELLOW}[+] Running focused validation scan...${NC}"
echo

nmap -Pn -sS -sV -sC -T1 \
--max-retries 1 \
-p "$VALIDATION_PORTS" \
"$TARGET_IP"

pause

# =========================================================
# PHASE 3 — Web Enumeration
# =========================================================

section "PHASE 3 — Web Enumeration"

read -rp "Enter HTTP/HTTPS port: " WEB_PORT
read -rp "Enter Gobuster wordlist path: " WORDLIST

echo
echo -e "${YELLOW}[+] Running low-noise web enumeration...${NC}"
echo

gobuster dir \
-u "http://$TARGET_IP:$WEB_PORT" \
-w "$WORDLIST" \
-t 5

pause

# =========================================================
# PHASE 4 — Manual Information Extraction
# =========================================================

section "PHASE 4 — Manual Information Extraction"

echo "Review enumeration results manually."
echo "Look for:"
echo "- Usernames"
echo "- Passwords"
echo "- Hidden directories"
echo "- robots.txt"
echo "- Admin portals"
echo "- SSH ports"
echo "- SMB shares"

pause

# =========================================================
# PHASE 5 — Credential Input
# =========================================================

section "PHASE 5 — Credential Validation"

read -rp "Enter discovered username: " USERNAME
read -rsp "Enter discovered password: " PASSWORD
echo

read -rp "Select validation service (ssh/smb/http): " AUTH_SERVICE

# =========================================================
# PHASE 6 — SSH Validation
# =========================================================

if [[ "$AUTH_SERVICE" == "ssh" ]]; then

    section "SSH Credential Validation"

    read -rp "Enter SSH port: " SSH_PORT

    echo
    echo -e "${YELLOW}[+] Testing SSH access...${NC}"
    echo

    ssh -p "$SSH_PORT" "$USERNAME@$TARGET_IP"

    pause
fi

# =========================================================
# PHASE 7 — SMB Validation
# =========================================================

if [[ "$AUTH_SERVICE" == "smb" ]]; then

    section "SMB Share Enumeration"

    echo
    echo -e "${YELLOW}[+] Enumerating SMB shares...${NC}"
    echo

    smbclient -L "//$TARGET_IP/" -U "$USERNAME"

    pause

    read -rp "Enter SMB share to access: " SMB_SHARE

    smbclient "//$TARGET_IP/$SMB_SHARE" -U "$USERNAME"

    pause
fi

# =========================================================
# PHASE 8 — Hydra Password Testing
# =========================================================

section "PHASE 8 — Optional Low-Noise Password Testing"

read -rp "Run password testing? (y/n): " RUN_HYDRA

if [[ "$RUN_HYDRA" == "y" ]]; then

    read -rp "Enter target service: " HYDRA_SERVICE
    read -rp "Enter username: " HYDRA_USER
    read -rp "Enter wordlist path: " HYDRA_WORDLIST
    read -rp "Enter target port: " HYDRA_PORT

    echo
    echo -e "${YELLOW}[+] Starting low-noise password testing...${NC}"
    echo

    hydra -t 1 -W 15 -f \
    -l "$HYDRA_USER" \
    -P "$HYDRA_WORDLIST" \
    "$HYDRA_SERVICE://$TARGET_IP:$HYDRA_PORT"

    pause
fi

# =========================================================
# PHASE 9 — Local Enumeration
# =========================================================

section "PHASE 9 — Local Enumeration"

echo "Suggested Linux enumeration commands:"
echo
echo "sudo -l"
echo "find / -perm -4000 2>/dev/null"
echo "getcap -r / 2>/dev/null"
echo "find / -iname '*flag*' 2>/dev/null"
echo

echo "Suggested Windows enumeration commands:"
echo
echo "net user"
echo "net localgroup administrators"
echo "netsh advfirewall show allprofiles"
echo "dir C:\\*flag* /s /b"
echo

pause

# =========================================================
# PHASE 10 — Reporting
# =========================================================

section "PHASE 10 — Reporting and Documentation"

echo "Record the following:"
echo
echo "- Timeline of events"
echo "- Commands executed"
echo "- Credentials discovered"
echo "- Open ports"
echo "- Shares discovered"
echo "- Privilege escalation paths"
echo "- Detection opportunities"
echo "- MITRE ATT&CK mappings"
echo

pause

# =========================================================
# End
# =========================================================

section "IRTx Workflow Complete"

echo -e "${GREEN}[+] Session complete${NC}"
echo