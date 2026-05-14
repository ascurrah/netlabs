#!/bin/bash

# Fail fast and enable safer bash semantics
set -euo pipefail

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "nmap is not installed. Please install it."
    exit 1
fi

# Function to validate IPv4 address (robust regex for 0-255)
validate_ip() {
    local ip=$1

    IFS='.' read -r -a octets <<< "$ip"
    if [ ${#octets[@]} -ne 4 ]; then
        return 1
    fi

    local octet_regex='^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
    for octet in "${octets[@]}"; do
        if ! [[ $octet =~ $octet_regex ]]; then
            return 1
        fi
    done

    return 0
}

# Function to validate CIDR notation (0-32)
validate_cidr() {
    local cidr=$1
    if ! [[ $cidr =~ ^([0-9]|[12][0-9]|3[0-2])$ ]]; then
        return 1
    fi
    return 0
}

# Prompt for target network
echo "Please enter the target network (e.g., 192.168.1.0/24):"
read -r TARGET_NETWORK

if [ -z "$TARGET_NETWORK" ]; then
    echo "Error: No target network provided."
    exit 1
fi

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

TIMESTAMP=$(date +%F_%H-%M-%S)

# Configurable variables (adjust as needed)
DECOYS="192.168.0.114,192.168.0.115,192.168.0.116,192.168.0.117,192.168.0.118"
SPOOF_MAC="00:50:56:9D:E3:F9"
CONCURRENCY=5

NMAP_OUTPUT_DIR="nmap_scans_$TIMESTAMP"

mkdir -p "$NMAP_OUTPUT_DIR"

# Live hosts temp file (use mktemp for safety)
LIVE_HOSTS=$(mktemp)
trap 'rm -f "$LIVE_HOSTS"' EXIT

# Export values so child sh -c can access them
export DECOYS SPOOF_MAC

echo "Starting device scan on $TARGET_NETWORK..."

# Host discovery
nmap -sn \
    -D "$DECOYS" \
    --spoof-mac "$SPOOF_MAC" \
    -n "$TARGET_NETWORK" | \
    awk '/Nmap scan report for/ {print $NF}' | tr -d '()' | sort -u > "$LIVE_HOSTS"

# Check for live hosts
if [ ! -s "$LIVE_HOSTS" ]; then
    echo "No live hosts found on $TARGET_NETWORK."
    rm -f "$LIVE_HOSTS"
    exit 1
fi

echo "Found $(wc -l < "$LIVE_HOSTS") live hosts."

{} \
echo "Starting Nmap stealth scans in parallel..."

cat "$LIVE_HOSTS" | xargs -P "$CONCURRENCY" -I {} sh -c '
    nmap -n \
        -p 1-1000,3000-4000 \
        -D "$DECOYS" \
        --spoof-mac "$SPOOF_MAC" \
        -sS -sV -O \
        --host-timeout 5m \
        "$1" \
        -oN "$2/nmap_scan_$1.txt"
' _ {} "$NMAP_OUTPUT_DIR"

echo "All scans completed."
echo "Results stored in $NMAP_OUTPUT_DIR/"

exit 0