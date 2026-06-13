#!/bin/bash
set -euo pipefail

# MorphVPN Server Setup Script
# Run as root on Ubuntu/Debian

DRY_RUN=false
BACKUP_DIR="/var/backups/morphvpn-$(date +%Y%m%d-%H%M%S)"

usage() {
    echo "Usage: $0 [--dry-run]"
    echo ""
    echo "Options:"
    echo "  --dry-run    Show what would be done without making changes"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

confirm() {
    local prompt="$1"
    if $DRY_RUN; then
        echo "[DRY RUN] Would ask: $prompt"
        return 0
    fi
    read -r -p "$prompt [y/N]: " response
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

run_cmd() {
    if $DRY_RUN; then
        echo "[DRY RUN] $*"
        return 0
    fi
    "$@"
}

echo "=== MorphVPN Server Setup ==="
if $DRY_RUN; then
    echo "[DRY RUN MODE - No changes will be made]"
    echo ""
fi

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root"
    exit 1
fi

echo ""
echo "This script will make the following system changes:"
echo "  1. Install packages: iproute2, iptables-persistent"
echo "  2. Enable IPv4 forwarding (sysctl net.ipv4.ip_forward=1)"
echo "  3. Create /etc/sysctl.d/99-morphvpn.conf"
echo "  4. Install binary to /usr/local/bin/morphvpn"
echo "  5. Generate keys in /etc/morphvpn/"
echo "  6. Install systemd service"
echo ""

if ! confirm "Proceed with setup?"; then
    echo "Setup cancelled."
    exit 0
fi

# Backup current state
echo ""
echo "[*] Creating backup..."
run_cmd mkdir -p "$BACKUP_DIR"
if ! $DRY_RUN; then
    sysctl net.ipv4.ip_forward > "$BACKUP_DIR/sysctl-ip_forward.txt" 2>/dev/null || true
    iptables-save > "$BACKUP_DIR/iptables-rules.txt" 2>/dev/null || true
    ip6tables-save > "$BACKUP_DIR/ip6tables-rules.txt" 2>/dev/null || true
    echo "Backup saved to: $BACKUP_DIR"
fi

# Install dependencies
echo ""
echo "[1/7] Installing dependencies..."
if confirm "Install packages: iproute2, iptables-persistent?"; then
    run_cmd apt-get update -qq
    run_cmd apt-get install -y -qq iproute2 iptables-persistent
else
    echo "Skipping package installation"
fi

# Enable IP forwarding
echo ""
echo "[2/7] Enabling IP forwarding..."
if confirm "Enable IPv4 forwarding? This modifies sysctl and creates /etc/sysctl.d/99-morphvpn.conf"; then
    run_cmd sysctl -w net.ipv4.ip_forward=1
    run_cmd bash -c 'echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-morphvpn.conf'
    run_cmd sysctl --system
else
    echo "Skipping IP forwarding setup"
fi

# Create directories
echo ""
echo "[3/7] Creating directories..."
run_cmd mkdir -p /etc/morphvpn /var/lib/morphvpn

# Copy binary
echo ""
echo "[4/7] Installing binary..."
run_cmd cp ../target/release/morphvpn /usr/local/bin/
run_cmd chmod 755 /usr/local/bin/morphvpn

# Generate keys
echo ""
echo "[5/7] Generating keys..."
if confirm "Generate new server keypair?"; then
    run_cmd morphvpn keygen --private-out /etc/morphvpn/server.key --public-out /etc/morphvpn/server.pub
    run_cmd chmod 600 /etc/morphvpn/server.key
else
    echo "Skipping key generation"
fi

# Generate PSK
echo ""
echo "[6/7] Generating PSK..."
if confirm "Generate new PSK (pre-shared key)?"; then
    run_cmd python3 -c "import secrets; print(secrets.token_hex(32))" > /etc/morphvpn/server.psk
    run_cmd chmod 600 /etc/morphvpn/server.psk
else
    echo "Skipping PSK generation"
fi

# Generate cookie key
echo ""
echo "[7/7] Generating cookie key..."
COOKIE_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
if confirm "Generate cookie key and copy config files?"; then
    run_cmd sed -i "s/REPLACE_WITH_RANDOM_64_HEX_CHARS/$COOKIE_KEY/" /etc/morphvpn/server.toml
    run_cmd cp config/server.toml /etc/morphvpn/
    run_cmd cp config/acl.example.toml /etc/morphvpn/acl.toml
else
    echo "Skipping config setup"
fi

# Install systemd unit
echo ""
echo "[*] Installing systemd service..."
if confirm "Install and reload systemd service?"; then
    run_cmd cp morphvpn.service /etc/systemd/system/
    run_cmd systemctl daemon-reload
else
    echo "Skipping systemd installation"
fi

echo ""
echo "=== Setup Complete ==="
if ! $DRY_RUN; then
    echo "Server public key: $(cat /etc/morphvpn/server.pub)"
fi
echo ""
echo "Backup location: $BACKUP_DIR"
echo ""
echo "Next steps:"
echo "1. Edit /etc/morphvpn/acl.toml - add your client public keys"
echo "2. Edit /etc/morphvpn/server.toml - set server IP in client configs"
echo "3. Start service: systemctl start morphvpn"
echo "4. Enable on boot: systemctl enable morphvpn"
echo "5. Check status: systemctl status morphvpn"
echo "6. View logs: journalctl -u morphvpn -f"
echo ""
echo "To restore original configuration:"
echo "  sysctl -f $BACKUP_DIR/sysctl-ip_forward.txt"
echo "  iptables-restore < $BACKUP_DIR/iptables-rules.txt"
echo "  ip6tables-restore < $BACKUP_DIR/ip6tables-rules.txt"
