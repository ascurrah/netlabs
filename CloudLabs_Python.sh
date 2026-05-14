#!/bin/bash
# Check if the script is run as root (required for arp-scan
and nmap)
if [[ $EUID -ne 0 ]]; then
echo "This script must be run as root. Please use sudo."
exit 1
fi
if ! command -v nmap &> /dev/null; then
echo "nmap is not installed. Please install it (e.g.,
sudo apt install nmap)."
exit 1
fi
# Function to validate IPv4 address
validate_ip() {
local ip=$1
# Split IP into octets
IFS='.' read -r -a octets <<< "$ip"
# Check if we have exactly 4 octets
if [ ${#octets[@]} -ne 4 ]; then
return 1
fi
# Check each octet
for octet in "${octets[@]}"; do
# Ensure octet is a number and within 0-255
if ! [[ "$octet" =~ ^[0-9]+$ ]] || [ "$octet" -lt 0 ]
|| [ "$octet" -gt 255 ]; then
return 1
fi
done
return 0
}
# Function to validate CIDR notation
validate_cidr() {
local cidr=$1
# Check if CIDR is a number and within 0-32
if ! [[ "$cidr" =~ ^[0-9]+$ ]] || [ "$cidr" -lt 0 ] || [
"$cidr" -gt 32 ]; then
return 1
fi
return 0
}
# Prompt user for the target network
echo "Please enter the target network (e.g.,
192.168.1.0/24):"
read -r TARGET_NETWORK
# Validate that the target network is not empty
if [ -z "$TARGET_NETWORK" ]; then
echo "Error: No target network provided."
exit 1
fi
# Split input into IP and CIDR parts
IFS='/' read -r ip_part cidr_part <<< "$TARGET_NETWORK"
# Validate IP address
if ! validate_ip "$ip_part"; then
echo "Error: '$ip_part' is not a valid IPv4 address."
exit 1
fi
# Validate CIDR
if ! validate_cidr "$cidr_part"; then
echo "Error: '/$cidr_part' is not a valid subnet mask
(must be 0-32)."
exit 1
fi
TIMESTAMP=$(date +%F_%H-%M-%S)
# ARP_OUTPUT="arp_scan_$TIMESTAMP.txt"
NMAP_OUTPUT_DIR="nmap_scans_$TIMESTAMP"
LIVE_HOSTS="live_hosts_$TIMESTAMP.txt"
# Create a directory for Nmap output
mkdir -p "$NMAP_OUTPUT_DIR"
echo "Starting device scan on $TARGET_NETWORK..."
# Run ping scan and extract IP addresses of live hosts
nmap -sn -D
192.168.0.114,192.168.0.115,192.168.0.116,192.168.0.117,192.1
68.0.118 --spoof-man 00:50:56:9D:E3:F9 -n "$TARGET_NETWORK" |
grep "Nmap scan report for" | awk '{print $5}' | sort -u >
"$LIVE_HOSTS"
# Check if any live hosts were found
if [ ! -s "$LIVE_HOSTS" ]; then
echo "No live hosts found on $TARGET_NETWORK."
rm "$LIVE_HOSTS"
exit 1
fi
echo "Found $(wc -l < "$LIVE_HOSTS") live hosts. Saving to
$LIVE_HOSTS."
if [ -s "$LIVE_HOSTS" ]; then
echo "Starting Nmap stealth scans in parallel..."
cat "$LIVE_HOSTS" | xargs -P 5 -I {} nmap -n –p 1-1000,
3000-4000 -D
192.168.0.114,192.168.0.115,192.168.0.116,192.168.0.117,192.1
68.0.118 --spoof-man 00:50:56:9D:3C:C6 -sS -sV -O --host-
timeout 5m {} -oN "$NMAP_OUTPUT_DIR/nmap_scan_{}.txt"
echo "All scans completed. Nmap results are stored in
$NMAP_OUTPUT_DIR/"
else
echo "No live hosts found in $TARGET_NETWORK."
fi
echo "All scans completed. Nmap results are stored in
$NMAP_OUTPUT_DIR/"
exit 0