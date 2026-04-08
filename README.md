# MorphVPN

> Experimental Rust VPN tunnel prototype.  
> Beta software. Built by one self-taught developer. Shared as-is.

[Russian version](README.ru.md)

## Overview

MorphVPN is a small command-line VPN/tunnel project written in Rust.  
It explores handshake flow, packet transport, TUN integration, ACL-based access control, and basic cross-platform network setup logic.

This repository is public to show the work, document the idea, and invite feedback.

## Important Notice

MorphVPN is still a beta project.

- No guarantees
- No security audit
- No promise of production readiness
- No claim that this is safe for real-world sensitive traffic

It was written by one self-taught developer. If you have suggestions, corrections, or practical advice, feedback is very welcome.

## What Is Actually In This Repo

- Rust source code for the tunnel prototype in `src/`
- Example ACL configuration in `examples/`
- Architecture notes and RFC-style documentation in `docs/`
- Cargo project files for building with Rust

## What This Project Tries To Do

- Run a server/client tunnel over UDP
- Generate key pairs from the CLI
- Work with TUN devices
- Apply basic peer authorization through an ACL file
- Explore transport and protocol ideas in a real codebase

## What It Does Not Claim

- It does not claim to be production-ready
- It does not claim to be audited
- It does not claim to be finished
- It does not claim to outperform mature VPN solutions

## Quick Start

Build:

```bash
cargo build
```

Generate keys:

```bash
cargo run -- keygen --private-out server.key --public-out server.pub
cargo run -- keygen --private-out client.key --public-out client.pub
```

Run the example server:

```bash
cargo run -- server --bind 0.0.0.0:51820 --psk <HEX32> --private-key server.key --acl examples/acl.example.toml --tun tun0
```

Run the example client:

```bash
cargo run -- client --server 203.0.113.10:51820 --psk <HEX32> --private-key client.key --server-public-key server.pub --tun tun1 --tun-ip 10.8.0.5
```

## Requirements

- Rust toolchain with `cargo`
- Administrator or root privileges for TUN and route changes
- Windows or Linux environment supported by the current code

## Repository Layout

```text
publish/
|- src/        Rust source code
|- examples/   Example ACL file
|- docs/       Notes and RFC-style docs
|- Cargo.toml
|- Cargo.lock
`- README.md
```

## Why It Is Public

This repository is public because progress matters, feedback matters, and learning in the open matters.

If you are more experienced and see weak spots, bad assumptions, or cleaner approaches, that kind of feedback is appreciated.

## Safety Reminder

Do not commit:

- Real private keys
- Real server IP addresses
- Personal logs
- Tokens, secrets, or local machine data

## License

Released under the MIT License. See [LICENSE](LICENSE).
