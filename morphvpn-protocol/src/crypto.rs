use crate::handshake::Seed;
use crate::wire::{
    apply_header_mask, OuterNonce, ProtectedHeader, RoutingTag, DATA_NONCE_LEN,
};
use anyhow::{anyhow, Result};
use bytes::{BufMut, Bytes, BytesMut};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, Rng};
use sha2::Sha256;

pub const EPOCH_KEY_MATERIAL_LEN: usize = 108;
pub const SESSION_DERIVE_LABEL: &[u8] = b"morphvpn/v1/session";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionRole {
    Client,
    Server,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochKeys {
    pub epoch: u32,
    pub data_key: Seed,
    pub outer_key: Seed,
    pub mask_key: Seed,
    pub base_nonce: [u8; DATA_NONCE_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedTransport {
    pub routing_tag: RoutingTag,
    pub outer_nonce: OuterNonce,
    pub header: ProtectedHeader,
    pub body: Bytes,
}

pub fn derive_epoch_keys(
    role: SessionRole,
    epoch: u32,
    psk: &Seed,
    handshake_hash: &[u8],
) -> Result<(EpochKeys, EpochKeys)> {
    let mut salt = BytesMut::with_capacity(handshake_hash.len() + 4);
    salt.extend_from_slice(handshake_hash);
    salt.put_u32(epoch);
    let hk = Hkdf::<Sha256>::new(Some(&salt), psk);
    let mut okm = [0u8; EPOCH_KEY_MATERIAL_LEN * 2];
    hk.expand(SESSION_DERIVE_LABEL, &mut okm)
        .map_err(|_| anyhow!("failed to derive epoch keys"))?;

    let client_tx = EpochKeys {
        epoch,
        data_key: okm[0..32]
            .try_into()
            .map_err(|_| anyhow!("client data key length mismatch"))?,
        outer_key: okm[32..64]
            .try_into()
            .map_err(|_| anyhow!("client outer key length mismatch"))?,
        mask_key: okm[64..96]
            .try_into()
            .map_err(|_| anyhow!("client mask key length mismatch"))?,
        base_nonce: okm[96..108]
            .try_into()
            .map_err(|_| anyhow!("client base nonce length mismatch"))?,
    };
    let server_tx = EpochKeys {
        epoch,
        data_key: okm[108..140]
            .try_into()
            .map_err(|_| anyhow!("server data key length mismatch"))?,
        outer_key: okm[140..172]
            .try_into()
            .map_err(|_| anyhow!("server outer key length mismatch"))?,
        mask_key: okm[172..204]
            .try_into()
            .map_err(|_| anyhow!("server mask key length mismatch"))?,
        base_nonce: okm[204..216]
            .try_into()
            .map_err(|_| anyhow!("server base nonce length mismatch"))?,
    };

    Ok(match role {
        SessionRole::Client => (client_tx, server_tx),
        SessionRole::Server => (server_tx, client_tx),
    })
}

pub fn generate_outer_nonce() -> OuterNonce {
    let mut nonce = [0u8; 24];
    OsRng.fill(&mut nonce);
    nonce
}

pub fn random_padding_len(range: std::ops::RangeInclusive<usize>) -> usize {
    OsRng.gen_range(range)
}

pub fn encrypt_data(keys: &EpochKeys, packet_no: u64, plaintext: &[u8]) -> Result<Bytes> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.data_key));
    let nonce_bytes = nonce_from_counter(&keys.base_nonce, packet_no);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &packet_no.to_be_bytes(),
            },
        )
        .map_err(|err| anyhow!("data encrypt failed: {err}"))?;
    Ok(Bytes::from(ciphertext))
}

pub fn decrypt_data(keys: &EpochKeys, packet_no: u64, ciphertext: &[u8]) -> Result<Bytes> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.data_key));
    let nonce_bytes = nonce_from_counter(&keys.base_nonce, packet_no);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &packet_no.to_be_bytes(),
            },
        )
        .map_err(|err| anyhow!("data decrypt failed: {err}"))?;
    Ok(Bytes::from(plaintext))
}

pub fn seal_transport_packet(
    routing_tag: RoutingTag,
    keys: &EpochKeys,
    header: &ProtectedHeader,
    body: Bytes,
    padding_len: usize,
) -> Result<Bytes> {
    let outer_nonce = generate_outer_nonce();
    let mut masked_header = header.encode().to_vec();
    apply_header_mask(&keys.mask_key, &outer_nonce, &mut masked_header)?;

    let mut plaintext =
        BytesMut::with_capacity(1 + masked_header.len() + body.len() + padding_len);
    plaintext.put_u8(masked_header.len() as u8);
    plaintext.extend_from_slice(&masked_header);
    plaintext.extend_from_slice(&body);
    if padding_len > 0 {
        let start = plaintext.len();
        plaintext.resize(start + padding_len, 0);
        OsRng.fill(&mut plaintext[start..]);
    }

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&keys.outer_key));
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&outer_nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: &routing_tag,
            },
        )
        .map_err(|err| anyhow!("outer transport encrypt failed: {err}"))?;

    let mut packet = BytesMut::with_capacity(routing_tag.len() + outer_nonce.len() + sealed.len());
    packet.extend_from_slice(&routing_tag);
    packet.extend_from_slice(&outer_nonce);
    packet.extend_from_slice(&sealed);
    Ok(packet.freeze())
}

pub fn open_transport_packet(packet: Bytes, keys: &EpochKeys) -> Result<OpenedTransport> {
    let min_len = crate::wire::ROUTING_TAG_LEN + crate::wire::OUTER_NONCE_LEN + 16;
    if packet.len() < min_len {
        return Err(anyhow!("transport packet too short: {}", packet.len()));
    }

    let mut routing_tag = [0u8; crate::wire::ROUTING_TAG_LEN];
    routing_tag.copy_from_slice(&packet[..crate::wire::ROUTING_TAG_LEN]);

    let mut outer_nonce = [0u8; crate::wire::OUTER_NONCE_LEN];
    outer_nonce.copy_from_slice(
        &packet[crate::wire::ROUTING_TAG_LEN
            ..crate::wire::ROUTING_TAG_LEN + crate::wire::OUTER_NONCE_LEN],
    );

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&keys.outer_key));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&outer_nonce),
            Payload {
                msg: &packet[crate::wire::ROUTING_TAG_LEN + crate::wire::OUTER_NONCE_LEN..],
                aad: &routing_tag,
            },
        )
        .map_err(|err| anyhow!("outer transport decrypt failed: {err}"))?;

    if plaintext.is_empty() {
        return Err(anyhow!("transport plaintext is empty"));
    }

    let header_len = plaintext[0] as usize;
    if header_len == 0 {
        return Err(anyhow!("masked header length is zero"));
    }
    if plaintext.len() < 1 + header_len {
        return Err(anyhow!("transport plaintext truncates masked header"));
    }

    let mut header_bytes = plaintext[1..1 + header_len].to_vec();
    apply_header_mask(&keys.mask_key, &outer_nonce, &mut header_bytes)?;
    let header = ProtectedHeader::decode(&header_bytes)?;

    let body_start = 1 + header_len;
    let body_end = body_start + header.body_len as usize;
    let padding_end = body_end + header.pad_len as usize;
    if padding_end > plaintext.len() {
        return Err(anyhow!("transport plaintext truncates body or padding"));
    }

    Ok(OpenedTransport {
        routing_tag,
        outer_nonce,
        header,
        body: Bytes::copy_from_slice(&plaintext[body_start..body_end]),
    })
}

pub fn nonce_from_counter(base_nonce: &[u8; DATA_NONCE_LEN], counter: u64) -> [u8; DATA_NONCE_LEN] {
    let mut nonce = *base_nonce;
    let counter_bytes = counter.to_le_bytes();
    let mut index = 0usize;
    while index < 8 {
        nonce[index] ^= counter_bytes[index];
        index += 1;
    }
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ProtectedHeader, TransportKind};

    const TEST_PSK: Seed = [0x77; 32];

    #[test]
    fn base_nonce_xor_counter_changes_nonce() {
        let (tx, _) = derive_epoch_keys(SessionRole::Client, 0, &TEST_PSK, b"hash")
            .unwrap_or_else(|err| panic!("{err}"));
        let zero = nonce_from_counter(&tx.base_nonce, 0);
        let one = nonce_from_counter(&tx.base_nonce, 1);
        let max = nonce_from_counter(&tx.base_nonce, u64::MAX);
        assert_ne!(zero, one);
        assert_ne!(one, max);
        assert_ne!(zero, max);
    }

    #[test]
    fn transport_packet_roundtrip() {
        let (tx, _) = derive_epoch_keys(SessionRole::Client, 0, &TEST_PSK, b"hash")
            .unwrap_or_else(|err| panic!("{err}"));
        let header = ProtectedHeader {
            version: 1,
            transport_kind: TransportKind::Data,
            flags: 0,
            epoch: 0,
            packet_no: 9,
            body_len: 5,
            pad_len: 7,
            probe_id: 0,
            probe_size: 0,
        };
        let packet = seal_transport_packet(
            [0x55; crate::wire::ROUTING_TAG_LEN],
            &tx,
            &header,
            Bytes::from_static(b"hello"),
            7,
        )
        .unwrap_or_else(|err| panic!("{err}"));
        let opened = open_transport_packet(packet, &tx).unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(opened.header.packet_no, 9);
        assert_eq!(opened.body, Bytes::from_static(b"hello"));
    }
}
