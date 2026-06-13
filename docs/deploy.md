# MorphVPN Deployment Guide

## Quick Start (Server)

### Requirements
- Linux (Ubuntu 20.04+, Debian 11+, or similar)
- Root access
- Rust toolchain (for building)

### 1. Build

```bash
cargo build --release
```

### 2. Setup

```bash
cd deploy
sudo ./setup.sh
```

This will:
- Install dependencies (iproute2, iptables)
- Enable IP forwarding
- Generate server keys and PSK
- Install binary and config
- Install systemd service

### 3. Configure ACL

Edit `/etc/morphvpn/acl.toml` to add authorized clients:

```toml
[[clients]]
name = "my-laptop"
public_key = "CLIENT_PUBLIC_KEY_HEX"
inner_ip = "10.8.0.5"
```

### 4. Start

```bash
systemctl start morphvpn
systemctl enable morphvpn
systemctl status morphvpn
```

### 5. Get Client Config

Copy these files to the client:
- `/etc/morphvpn/server.pub` (server public key)
- `/etc/morphvpn/server.psk` (PSK — transmit securely!)

## Quick Start (Client)

### 1. Build

```bash
cargo build --release
```

### 2. Setup

```bash
cd deploy
sudo ./setup-client.sh
```

### 3. Configure

Edit `/etc/morphvpn/client.toml`:
- Set `server = "SERVER_IP:51820"`
- Set `server_public_key = "SERVER_PUB_KEY_HEX"`

### 4. Run

```bash
morphvpn --config /etc/morphvpn/client.toml client
```

## Firewall Rules

The setup script configures NAT automatically. If you need manual rules:

```bash
# Allow VPN traffic
iptables -A INPUT -p udp --dport 51820 -j ACCEPT
iptables -A INPUT -p tcp --dport 51821 -j ACCEPT

# NAT for VPN clients
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
iptables -A FORWARD -d 10.8.0.0/24 -j ACCEPT
```

## Troubleshooting

### TUN device not found

Ensure the `tun` kernel module is loaded:
```bash
modprobe tun
```

### Permission denied

Run with sudo or ensure the user has CAP_NET_ADMIN.

### No connectivity after connecting

1. Check server IP forwarding: `sysctl net.ipv4.ip_forward`
2. Check iptables: `iptables -L -n -v`
3. Check logs: `journalctl -u morphvpn`