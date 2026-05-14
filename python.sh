#!/bin/bash

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

# Function to validate IPv4 address
validate_ip() {
    local ip=$1

    IFS='.' read -r -a octets <<< "$ip"

    if [ ${#octets[@]} -ne 4 ]; then
        return 1
    fi

    for octet in "${octets[@]}"; do
        if ! [[ "$octet" =~ ^[0-9]+$ ]] || \
           [ "$octet" -lt 0 ] || \
           [ "$octet" -gt 255 ]; then
            return 1
        fi
    done

    return 0
}

# Function to validate CIDR notation
validate_cidr() {
    local cidr=$1

    if ! [[ "$cidr" =~ ^[0-9]+$ ]] || \
       [ "$cidr" -lt 0 ] || \
       [ "$cidr" -gt 32 ]; then
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

NMAP_OUTPUT_DIR="nmap_scans_$TIMESTAMP"
LIVE_HOSTS="live_hosts_$TIMESTAMP.txt"

mkdir -p "$NMAP_OUTPUT_DIR"

echo "Starting device scan on $TARGET_NETWORK..."

# Host discovery
nmap -sn \
-D 192.168.0.114,192.168.0.115,192.168.0.116,192.168.0.117,192.168.0.118 \
--spoof-mac 00:50:56:9D:E3:F9 \
-n "$TARGET_NETWORK" | \
grep "Nmap scan report for" | \
awk '{print $5}' | \
sort -u > "$LIVE_HOSTS"

# Check for live hosts
if [ ! -s "$LIVE_HOSTS" ]; then
    echo "No live hosts found on $TARGET_NETWORK."
    rm "$LIVE_HOSTS"
    exit 1
fi

echo "Found $(wc -l < "$LIVE_HOSTS") live hosts."

echo "Starting Nmap stealth scans in parallel..."

cat "$LIVE_HOSTS" | xargs -P 5 -I {} sh -c '
nmap -n \
-p 1-1000,3000-4000 \
-D 192.168.0.114,192.168.0.115,192.168.0.116,192.168.0.117,192.168.0.118 \
--spoof-mac 00:50:56:9D:3C:C6 \
-sS -sV -O \
--host-timeout 5m \
{} \
-oN "'"$NMAP_OUTPUT_DIR"'/nmap_scan_{}.txt"
'

echo "All scans completed."
echo "Results stored in $NMAP_OUTPUT_DIR/"

exit 0