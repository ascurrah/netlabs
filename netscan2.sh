#!/bin/bash

# ================================
# Network Scanner + Gobuster Script
# ================================

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "nmap is not installed."
    echo "Install it with: sudo apt install nmap"
    exit 1
fi

# Check if gobuster is installed
if ! command -v gobuster &> /dev/null; then
    echo "gobuster is not installed."
    echo "Install it with: sudo apt install gobuster"
    exit 1
fi

# ================================
# Validate IPv4 Address
# ================================
validate_ip() {

    local ip=$1

    IFS='.' read -r -a octets <<< "$ip"

    # Ensure 4 octets
    if [ ${#octets[@]} -ne 4 ]; then
        return 1
    fi

    # Validate each octet
    for octet in "${octets[@]}"; do

        if ! [[ "$octet" =~ ^[0-9]+$ ]] || \
           [ "$octet" -lt 0 ] || \
           [ "$octet" -gt 255 ]; then
            return 1
        fi

    done

    return 0
}

# ================================
# Validate CIDR
# ================================
validate_cidr() {

    local cidr=$1

    if ! [[ "$cidr" =~ ^[0-9]+$ ]] || \
       [ "$cidr" -lt 0 ] || \
       [ "$cidr" -gt 32 ]; then
        return 1
    fi

    return 0
}

# ================================
# Prompt User for Target Network
# ================================
echo "Please enter the target network (e.g., 192.168.1.0/24):"
read -r TARGET_NETWORK

# Ensure input exists
if [ -z "$TARGET_NETWORK" ]; then
    echo "Error: No target network provided."
    exit 1
fi

# Split IP/CIDR
IFS='/' read -r ip_part cidr_part <<< "$TARGET_NETWORK"

# Validate IP
if ! validate_ip "$ip_part"; then
    echo "Error: '$ip_part' is not a valid IPv4 address."
    exit 1
fi

# Validate CIDR
if ! validate_cidr "$cidr_part"; then
    echo "Error: '/$cidr_part' is not a valid subnet mask."
    exit 1
fi

# ================================
# Variables
# ================================
TIMESTAMP=$(date +%F_%H-%M-%S)

NMAP_OUTPUT_DIR="nmap_scans_$TIMESTAMP"
GOBUSTER_OUTPUT_DIR="gobuster_scans_$TIMESTAMP"

LIVE_HOSTS="live_hosts_$TIMESTAMP.txt"

# Wordlist path
WORDLIST="/usr/share/wordlists/dirb/common.txt"

# Create output directories
mkdir -p "$NMAP_OUTPUT_DIR"
mkdir -p "$GOBUSTER_OUTPUT_DIR"

# ================================
# Host Discovery
# ================================
echo ""
echo "Starting host discovery on $TARGET_NETWORK..."
echo ""

nmap -sn \
-D 192.168.0.114,192.168.0.115,192.168.0.116,192.168.0.117,192.168.0.118 \
--spoof-mac 00:50:56:9D:E3:F9 \
-n "$TARGET_NETWORK" | \
grep "Nmap scan report for" | \
awk '{print $5}' | \
sort -u > "$LIVE_HOSTS"

# ================================
# Check for Live Hosts
# ================================
if [ ! -s "$LIVE_HOSTS" ]; then
    echo "No live hosts found on $TARGET_NETWORK."
    rm -f "$LIVE_HOSTS"
    exit 1
fi

echo "Found $(wc -l < "$LIVE_HOSTS") live hosts."
echo ""

# ================================
# Nmap Stealth Scans
# ================================
echo "Starting Nmap stealth scans in parallel..."
echo ""

cat "$LIVE_HOSTS" | xargs -P 5 -I {} sh -c '

TARGET="$1"
OUTPUT_DIR="$2"

echo "[*] Scanning $TARGET"

nmap -n \
-p 1-1000,3000-4000,8000,8080,8443 \
-D 192.168.0.114,192.168.0.115,192.168.0.116,192.168.0.117,192.168.0.118 \
--spoof-mac 00:50:56:9D:3C:C6 \
-sS \
-sV \
-O \
-T3 \
--host-timeout 5m \
"$TARGET" \
-oN "$OUTPUT_DIR/nmap_scan_$TARGET.txt"

echo "[+] Completed scan for $TARGET"

' _ {} "$NMAP_OUTPUT_DIR"

echo ""
echo "All Nmap scans completed."
echo "Results stored in:"
echo "$NMAP_OUTPUT_DIR/"
echo ""

# ================================
# Gobuster Scans
# ================================
echo "Starting Gobuster scans on hosts with web services..."
echo ""

for scanfile in "$NMAP_OUTPUT_DIR"/*.txt; do

    host=$(basename "$scanfile" | sed 's/nmap_scan_//' | sed 's/.txt//')

    # ============================
    # Port 80
    # ============================
    if grep -q "80/tcp open" "$scanfile"; then

        echo "[*] Running Gobuster against http://$host"

        gobuster dir \
            -u "http://$host" \
            -w "$WORDLIST" \
            -t 20 \
            --no-error \
            -q \
            -o "$GOBUSTER_OUTPUT_DIR/gobuster_http_$host.txt"

        echo "[+] Saved:"
        echo "    $GOBUSTER_OUTPUT_DIR/gobuster_http_$host.txt"
        echo ""

    fi

    # ============================
    # Port 8080
    # ============================
    if grep -q "8080/tcp open" "$scanfile"; then

        echo "[*] Running Gobuster against http://$host:8080"

        gobuster dir \
            -u "http://$host:8080" \
            -w "$WORDLIST" \
            -t 20 \
            --no-error \
            -q \
            -o "$GOBUSTER_OUTPUT_DIR/gobuster_8080_$host.txt"

        echo "[+] Saved:"
        echo "    $GOBUSTER_OUTPUT_DIR/gobuster_8080_$host.txt"
        echo ""

    fi

    # ============================
    # Port 443
    # ============================
    if grep -q "443/tcp open" "$scanfile"; then

        echo "[*] Running Gobuster against https://$host"

        gobuster dir \
            -u "https://$host" \
            -k \
            -w "$WORDLIST" \
            -t 20 \
            --no-error \
            -q \
            -o "$GOBUSTER_OUTPUT_DIR/gobuster_https_$host.txt"

        echo "[+] Saved:"
        echo "    $GOBUSTER_OUTPUT_DIR/gobuster_https_$host.txt"
        echo ""

    fi

    # ============================
    # Port 8443
    # ============================
    if grep -q "8443/tcp open" "$scanfile"; then

        echo "[*] Running Gobuster against https://$host:8443"

        gobuster dir \
            -u "https://$host:8443" \
            -k \
            -w "$WORDLIST" \
            -t 20 \
            --no-error \
            -q \
            -o "$GOBUSTER_OUTPUT_DIR/gobuster_8443_$host.txt"

        echo "[+] Saved:"
        echo "    $GOBUSTER_OUTPUT_DIR/gobuster_8443_$host.txt"
        echo ""

    fi

done

echo "All Gobuster scans completed."
echo ""
echo "==============================="
echo "Scan Summary"
echo "==============================="
echo "Live hosts file:"
echo "  $LIVE_HOSTS"
echo ""
echo "Nmap scans:"
echo "  $NMAP_OUTPUT_DIR/"
echo ""
echo "Gobuster scans:"
echo "  $GOBUSTER_OUTPUT_DIR/"
echo ""

exit 0