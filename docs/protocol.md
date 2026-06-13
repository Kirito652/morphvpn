# MorphVPN Protocol Specification v1

> Version: 0.8-draft
> Status: Working Draft
> Last Updated: 2026-06-13

## 1. Overview

MorphVPN is a UDP-based VPN tunnel protocol using the Noise Protocol Framework
for key establishment and transport encryption. The protocol supports:

- Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s handshake pattern
- Two-layer transport encryption (outer XChaCha20-Poly1305, inner ChaCha20-Poly1305)
- Header masking for traffic obfuscation
- Stateless cookie-based anti-DoS mechanism
- Path MTU Discovery (PMTUD)
- Epoch-based key rotation (rekey)

## 2. Wire Format

### 2.1 Packet Types

All packets begin with a 12-byte **Routing Tag** used for shard routing.

| Packet Type       | Discriminant | Description                    |
|------------------|-------------|--------------------------------|
| Handshake Init   | 0x01        | Client initiation              |
| Handshake Resp   | 0x02        | Server response                |
| Handshake Finish | 0x03        | Client completion              |
| Cookie Reply     | 0x04        | Anti-DoS cookie response       |
| Transport        | -           | Encrypted data/control         |

### 2.2 Handshake Frame

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Routing Tag (12 bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Outer Nonce (24 bytes)                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Kind (1B)  |         Payload Length (2B)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Payload (variable)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Padding (variable)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     MAC1 (16 bytes)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     MAC2 (16 bytes, optional)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 2.3 Transport Envelope

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Routing Tag (12 bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Outer Nonce (24 bytes)                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Masked Header (24 bytes)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Encrypted Body (variable)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Protected Header (24 bytes, before masking)

| Offset | Length | Field         | Description                    |
|--------|--------|---------------|--------------------------------|
| 0      | 1      | Version       | Protocol version (1)           |
| 1      | 1      | Transport     | 1=Control, 2=Data              |
| 2      | 1      | Flags         | Reserved                       |
| 3      | 1      | Reserved      | Must be zero                   |
| 4      | 4      | Epoch         | Key epoch number               |
| 8      | 8      | Packet No     | Monotonic packet counter       |
| 16     | 2      | Body Length   | Encrypted body length          |
| 18     | 2      | Pad Length    | Padding length                 |
| 20     | 2      | Probe ID      | PMTUD probe identifier         |
| 22     | 2      | Probe Size    | PMTUD probe target size        |

## 3. Cryptography

### 3.1 Noise Handshake

Pattern: `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`

- **DH**: X25519 (x25519-dalek)
- **Cipher**: ChaCha20-Poly1305
- **Hash**: BLAKE2s-256
- **PSK**: Inserted at phase 3 (psk3)

Handshake flow:
1. Client -> Server: `e` (ephemeral key)
2. Server -> Client: `e, ee, s, es` (ephemeral + static + DH)
3. Client -> Server: `s, se, psk` (static + DH + PSK)

### 3.2 Transport Keys

Derived via HKDF-SHA256 from handshake hash + PSK:

```
epoch_key_material = HKDF(handshake_hash || epoch_number, PSK, label="morphvpn/v1/session")
```

Two independent key sets derived per epoch:
- **Client TX / Server RX** (same keys)
- **Server TX / Client RX** (same keys)

Each set contains:
- `data_key` (32 bytes) - ChaCha20-Poly1305 for payload
- `outer_key` (32 bytes) - XChaCha20-Poly1305 for transport envelope
- `mask_key` (32 bytes) - ChaCha20 for header masking
- `base_nonce` (12 bytes) - XOR base for packet counter

### 3.3 Header Masking

Header is masked with ChaCha20 keystream:
```
mask_key = keys.mask_key
nonce = outer_nonce[..12]
masked_header = header XOR ChaCha20(mask_key, nonce)
```

This makes the header indistinguishable from random bytes.

### 3.4 Rekey

When `data_tx_nonce` approaches `u64::MAX - 4096`:
1. Sender sends `RekeyInit { epoch, public_key }`
2. Receiver derives new keys for `epoch + 1`, sends `RekeyResp`
3. Both sides rotate to new epoch keys, reset nonces to 0

## 4. Anti-DoS

### 4.1 Cookie Mechanism

MAC1 = BLAKE2s(responder_public_key, packet_without_macs)
MAC2 = HMAC-SHA256(cookie, packet_without_mac2)

Cookie = HMAC-SHA256(master_key, persona || bucket || source_addr || routing_tag)

When source exceeds rate threshold (>8 init/second), server responds with CookieReply.

### 4.2 Rate Limiting

Per-source sliding window: 8 init packets per second.
Excess inits receive CookieReply instead of Response.

## 5. Path MTU Discovery

Probe frames use `PmtudProbe` / `PmtudAck` control frames:
- Probe contains target_size (desired MTU)
- Ack confirms the size
- Timeout (3s) reduces MTU by 100 bytes
- Range: 576 - 1600 bytes

## 6. Control Frames

| Code | Frame           | Payload                         |
|------|-----------------|----------------------------------|
| 0x01 | BootstrapInit   | requested_ip (4B)               |
| 0x02 | BootstrapResp   | assigned_ip (4B)                |
| 0x03 | RekeyInit       | epoch (4B) + public_key (32B)   |
| 0x04 | RekeyResp       | epoch (4B) + public_key (32B)   |
| 0x05 | Keepalive       | (empty)                         |
| 0x06 | KeepaliveAck    | (empty)                         |
| 0x07 | PmtudProbe      | probe_id (2B) + target_size (2B)|
| 0x08 | PmtudAck        | probe_id (2B) + confirmed_size (2B)|
| 0x09 | Close           | reason (1B)                     |
| 0x0A | AuthInit        | cert_fingerprint (32B)          |
| 0x0B | AuthResp        | cert_fingerprint (32B)          |

## 7. Replay Protection

2048-bit sliding window. Packets with sequence numbers outside the window or
already seen are silently dropped.

## 8. Security Considerations

- PSK must be at least 256 bits
- Cookie master key must be random and secret
- Private keys must be stored with restricted permissions (0600)
- IPv6 must be disabled on TUN to prevent leaks
- DNS must be routed through tunnel
- Certificate fingerprints provide secondary authentication
