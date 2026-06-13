#!/bin/bash
set -euo pipefail

# MorphVPN Server Setup Script
# Run as root on Ubuntu/Debian

echo "=== MorphVPN Server Setup ==="

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Install dependencies
echo "[1/7] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq iproute2 iptables-persistent

# Enable IP forwarding
echo "[2/7] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-morphvpn.conf
sysctl --system

# Create directories
echo "[3/7] Creating directories..."
mkdir -p /etc/morphvpn /var/lib/morphvpn

# Copy binary
echo "[4/7] Installing binary..."
cp ../target/release/morphvpn /usr/local/bin/
chmod 755 /usr/local/bin/morphvpn

# Generate keys
echo "[5/7] Generating keys..."
morphvpn keygen --private-out /etc/morphvpn/server.key --public-out /etc/morphvpn/server.pub
chmod 600 /etc/morphvpn/server.key

# Generate PSK
echo "[6/7] Generating PSK..."
python3 -c "import secrets; print(secrets.token_hex(32))" > /etc/morphvpn/server.psk
chmod 600 /etc/morphvpn/server.psk

# Generate cookie key
echo "[7/7] Generating cookie key..."
COOKIE_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
sed -i "s/REPLACE_WITH_RANDOM_64_HEX_CHARS/$COOKIE_KEY/" /etc/morphvpn/server.toml

# Copy config
cp config/server.toml /etc/morphvpn/
cp config/acl.example.toml /etc/morphvpn/acl.toml

# Install systemd unit
cp morphvpn.service /etc/systemd/system/
systemctl daemon-reload

echo ""
echo "=== Setup Complete ==="
echo "Server public key: $(cat /etc/morphvpn/server.pub)"
echo ""
echo "Next steps:"
echo "1. Edit /etc/morphvpn/acl.toml - add your client public keys"
echo "2. Edit /etc/morphvpn/server.toml - set server IP in client configs"
echo "3. Start service: systemctl start morphvpn"
echo "4. Enable on boot: systemctl enable morphvpn"
echo "5. Check status: systemctl status morphvpn"
echo "6. View logs: journalctl -u morphvpn -f"