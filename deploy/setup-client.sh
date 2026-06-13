#!/bin/bash
set -euo pipefail

# MorphVPN Client Setup Script
# Run as root

echo "=== MorphVPN Client Setup ==="

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root"
    exit 1
fi

apt-get update -qq
apt-get install -y -qq iproute2

mkdir -p /etc/morphvpn
cp ../target/release/morphvpn /usr/local/bin/
chmod 755 /usr/local/bin/morphvpn

# Generate client keys
morphvpn keygen --private-out /etc/morphvpn/client.key --public-out /etc/morphvpn/client.pub
chmod 600 /etc/morphvpn/client.key

# Generate PSK (must match server)
echo "Enter server PSK (hex):"
read -r PSK
echo "$PSK" > /etc/morphvpn/client.psk
chmod 600 /etc/morphvpn/client.psk

cp config/client.toml /etc/morphvpn/

echo ""
echo "=== Setup Complete ==="
echo "Client public key: $(cat /etc/morphvpn/client.pub)"
echo "Add this to server's ACL config as inner_ip: 10.8.0.X"
echo ""
echo "Edit /etc/morphvpn/client.toml:"
echo "- Set server = \"SERVER_IP:51820\""
echo "- Set server_public_key = server's public key hex"
echo ""
echo "Run: morphvpn --config /etc/morphvpn/client.toml client"