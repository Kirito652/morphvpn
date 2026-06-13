#!/bin/bash
set -euo pipefail

# MorphVPN Client Setup Script
# Run as root

DRY_RUN=false
BACKUP_DIR="/var/backups/morphvpn-client-$(date +%Y%m%d-%H%M%S)"

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

echo "=== MorphVPN Client Setup ==="
if $DRY_RUN; then
    echo "[DRY RUN MODE - No changes will be made]"
    echo ""
fi

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root"
    exit 1
fi

echo ""
echo "This script will make the following system changes:"
echo "  1. Install packages: iproute2"
echo "  2. Install binary to /usr/local/bin/morphvpn"
echo "  3. Generate client keys in /etc/morphvpn/"
echo "  4. Create client configuration"
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
    ip route show > "$BACKUP_DIR/routes.txt" 2>/dev/null || true
    echo "Backup saved to: $BACKUP_DIR"
fi

# Install dependencies
echo ""
echo "[1/5] Installing dependencies..."
if confirm "Install packages: iproute2?"; then
    run_cmd apt-get update -qq
    run_cmd apt-get install -y -qq iproute2
else
    echo "Skipping package installation"
fi

# Install binary
echo ""
echo "[2/5] Installing binary..."
run_cmd mkdir -p /etc/morphvpn
run_cmd cp ../target/release/morphvpn /usr/local/bin/
run_cmd chmod 755 /usr/local/bin/morphvpn

# Generate client keys
echo ""
echo "[3/5] Generating client keys..."
if confirm "Generate new client keypair?"; then
    run_cmd morphvpn keygen --private-out /etc/morphvpn/client.key --public-out /etc/morphvpn/client.pub
    run_cmd chmod 600 /etc/morphvpn/client.key
else
    echo "Skipping key generation"
fi

# Get PSK
echo ""
echo "[4/5] Configuring PSK..."
if confirm "Enter server PSK (hex) now?"; then
    if ! $DRY_RUN; then
        echo "Enter server PSK (hex, will be hidden):"
        read -rs PSK
        echo ""
        echo "$PSK" > /etc/morphvpn/client.psk
        chmod 600 /etc/morphvpn/client.psk
    else
        echo "[DRY RUN] Would prompt for PSK and save to /etc/morphvpn/client.psk"
    fi
else
    echo "You'll need to manually create /etc/morphvpn/client.psk"
fi

# Copy config
echo ""
echo "[5/5] Setting up configuration..."
if confirm "Copy client configuration template?"; then
    run_cmd cp config/client.toml /etc/morphvpn/
else
    echo "Skipping config setup"
fi

echo ""
echo "=== Setup Complete ==="
if ! $DRY_RUN; then
    echo "Client public key: $(cat /etc/morphvpn/client.pub)"
fi
echo ""
echo "Backup location: $BACKUP_DIR"
echo ""
echo "Add this public key to server's ACL config as inner_ip: 10.8.0.X"
echo ""
echo "Edit /etc/morphvpn/client.toml:"
echo "  - Set server = \"SERVER_IP:51820\""
echo "  - Set server_public_key = server's public key hex"
echo ""
echo "Run: morphvpn --config /etc/morphvpn/client.toml client"
