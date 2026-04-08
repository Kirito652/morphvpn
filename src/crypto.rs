use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use snow::{params::NoiseParams, Builder, HandshakeState, StatelessTransportState};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub type Seed = [u8; 32];
pub type RoutingTag = [u8; 8];

pub const NOISE_PATTERN: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const ROUTING_TAG_LEN: usize = 8;
pub const OUTER_NONCE_LEN: usize = 24;
pub const DATA_NONCE_LEN: usize = 12;

const COMPAT_SERVER_LABEL: &[u8] = b"morphvpn/compat-static/server";
const COMPAT_CLIENT_LABEL: &[u8] = b"morphvpn/compat-static/client";
const BOOTSTRAP_OBFS_LABEL: &[u8] = b"morphvpn/bootstrap-obfs/v1";
const EPOCH_DERIVE_LABEL: &[u8] = b"morphvpn/epoch-derive/v1";
const HEADER_MASK_LABEL: &[u8] = b"morphvpn/header-mask/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

impl Role {
    pub fn compat_label(self) -> &'static [u8] {
        match self {
            Self::Initiator => COMPAT_CLIENT_LABEL,
            Self::Responder => COMPAT_SERVER_LABEL,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StaticIdentity {
    pub private: Seed,
    pub public: Seed,
}

#[derive(Clone, Debug)]
pub struct EpochSecret {
    pub data_key: Seed,
    pub obfs_key: Seed,
    pub mask_key: Seed,
}

#[derive(Debug)]
pub struct HandshakeOutput {
    pub control: StatelessTransportState,
    pub handshake_hash: Vec<u8>,
    pub remote_static: Option<Seed>,
}

#[allow(dead_code)]
pub fn generate_static_identity() -> StaticIdentity {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    StaticIdentity {
        private: secret.to_bytes(),
        public: public.to_bytes(),
    }
}

pub fn derive_compat_identity(seed: &Seed, role: Role) -> Result<StaticIdentity> {
    let hk = Hkdf::<Sha256>::new(Some(b"morphvpn/compat-static/v1"), seed);
    let mut private = [0u8; 32];
    hk.expand(role.compat_label(), &mut private)
        .map_err(|_| anyhow!("HKDF expand failed for compat identity"))?;
    let secret = StaticSecret::from(private);
    let public = PublicKey::from(&secret);
    Ok(StaticIdentity {
        private: secret.to_bytes(),
        public: public.to_bytes(),
    })
}

#[allow(dead_code)]
pub fn parse_hex_32(hex: &str, what: &str) -> Result<Seed> {
    let bytes = hex::decode(hex.trim())
        .with_context(|| format!("invalid {what} hex, expected 64 hex chars"))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "{what} must be exactly 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        ));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn generate_routing_tag() -> RoutingTag {
    let mut tag = [0u8; ROUTING_TAG_LEN];
    OsRng.fill_bytes(&mut tag);
    tag
}

pub fn generate_outer_nonce() -> [u8; OUTER_NONCE_LEN] {
    let mut nonce = [0u8; OUTER_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn build_initiator_handshake(
    identity: &StaticIdentity,
    remote_public_key: &Seed,
    psk: &Seed,
) -> Result<HandshakeState> {
    let params: NoiseParams = NOISE_PATTERN.parse().context("invalid Noise params")?;
    Builder::new(params)
        .local_private_key(&identity.private)?
        .remote_public_key(remote_public_key)?
        .psk(2, psk)
        .context("failed to attach psk to initiator handshake")?
        .build_initiator()
        .context("failed to build initiator handshake")
}

pub fn build_responder_handshake(identity: &StaticIdentity, psk: &Seed) -> Result<HandshakeState> {
    let params: NoiseParams = NOISE_PATTERN.parse().context("invalid Noise params")?;
    Builder::new(params)
        .local_private_key(&identity.private)?
        .psk(2, psk)
        .context("failed to attach psk to responder handshake")?
        .build_responder()
        .context("failed to build responder handshake")
}

pub fn write_handshake_message(state: &mut HandshakeState, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; 1024];
    let written = state
        .write_message(payload, &mut out)
        .context("failed to write Noise handshake message")?;
    out.truncate(written);
    Ok(out)
}

pub fn read_handshake_message(state: &mut HandshakeState, input: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; 1024];
    let read = state
        .read_message(input, &mut out)
        .context("failed to read Noise handshake message")?;
    out.truncate(read);
    Ok(out)
}

pub fn finish_handshake(state: HandshakeState) -> Result<HandshakeOutput> {
    let mut remote_static = None;
    if let Some(remote) = state.get_remote_static() {
        if remote.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(remote);
            remote_static = Some(key);
        }
    }

    let handshake_hash = state.get_handshake_hash().to_vec();
    let control = state
        .into_stateless_transport_mode()
        .context("failed to enter Noise stateless transport mode")?;

    Ok(HandshakeOutput {
        control,
        handshake_hash,
        remote_static,
    })
}

pub fn derive_bootstrap_obfs_key(
    psk: &Seed,
    handshake_hash: &[u8],
    routing_tag: &RoutingTag,
) -> Result<Seed> {
    let hk = Hkdf::<Sha256>::new(Some(psk), handshake_hash);
    let mut key = [0u8; 32];
    let mut info = Vec::with_capacity(BOOTSTRAP_OBFS_LABEL.len() + routing_tag.len());
    info.extend_from_slice(BOOTSTRAP_OBFS_LABEL);
    info.extend_from_slice(routing_tag);
    hk.expand(&info, &mut key)
        .map_err(|_| anyhow!("failed to derive bootstrap obfuscation key"))?;
    Ok(key)
}

pub fn derive_epoch_material(
    role: Role,
    epoch: u32,
    psk: &Seed,
    handshake_hash: &[u8],
    shared_secret: &[u8; 32],
) -> Result<(EpochSecret, EpochSecret)> {
    let mut salt = Vec::with_capacity(handshake_hash.len() + 4);
    salt.extend_from_slice(handshake_hash);
    salt.extend_from_slice(&epoch.to_be_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut okm = [0u8; 192];

    let mut info = Vec::with_capacity(EPOCH_DERIVE_LABEL.len() + psk.len());
    info.extend_from_slice(EPOCH_DERIVE_LABEL);
    info.extend_from_slice(psk);

    hk.expand(&info, &mut okm)
        .map_err(|_| anyhow!("failed to derive epoch material"))?;

    let initiator_tx = EpochSecret {
        data_key: okm[0..32].try_into().expect("slice len checked"),
        obfs_key: okm[32..64].try_into().expect("slice len checked"),
        mask_key: okm[64..96].try_into().expect("slice len checked"),
    };
    let responder_tx = EpochSecret {
        data_key: okm[96..128].try_into().expect("slice len checked"),
        obfs_key: okm[128..160].try_into().expect("slice len checked"),
        mask_key: okm[160..192].try_into().expect("slice len checked"),
    };

    Ok(match role {
        Role::Initiator => (initiator_tx, responder_tx),
        Role::Responder => (responder_tx, initiator_tx),
    })
}

pub fn derive_epoch_material_from_dh(
    role: Role,
    epoch: u32,
    psk: &Seed,
    handshake_hash: &[u8],
    private: &StaticSecret,
    peer_public: &[u8; 32],
) -> Result<(EpochSecret, EpochSecret)> {
    let peer = PublicKey::from(*peer_public);
    let shared = Zeroizing::new(private.diffie_hellman(&peer).to_bytes());
    derive_epoch_material(role, epoch, psk, handshake_hash, &shared)
}

pub fn encrypt_data(secret: &EpochSecret, packet_no: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&secret.data_key));
    let nonce_bytes = nonce_from_counter(packet_no);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &packet_no.to_be_bytes(),
            },
        )
        .map_err(|e| anyhow!("data encrypt failed: {e}"))
}

pub fn decrypt_data(secret: &EpochSecret, packet_no: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&secret.data_key));
    let nonce_bytes = nonce_from_counter(packet_no);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &packet_no.to_be_bytes(),
            },
        )
        .map_err(|e| anyhow!("data decrypt failed: {e}"))
}

pub fn seal_outer_envelope(
    obfs_key: &Seed,
    routing_tag: &RoutingTag,
    nonce: &[u8; OUTER_NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(obfs_key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: routing_tag,
            },
        )
        .map_err(|e| anyhow!("outer envelope encrypt failed: {e}"))
}

pub fn open_outer_envelope(
    obfs_key: &Seed,
    routing_tag: &RoutingTag,
    nonce: &[u8; OUTER_NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(obfs_key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: routing_tag,
            },
        )
        .map_err(|e| anyhow!("outer envelope decrypt failed: {e}"))
}

pub fn header_mask(
    mask_key: &Seed,
    routing_tag: &RoutingTag,
    nonce: &[u8; 24],
    len: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u32;
    while out.len() < len {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mask_key)
            .expect("mask key length is always valid");
        mac.update(HEADER_MASK_LABEL);
        mac.update(routing_tag);
        mac.update(nonce);
        mac.update(&counter.to_be_bytes());
        let block = mac.finalize().into_bytes();
        out.extend_from_slice(&block);
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

pub fn apply_header_mask(
    mask_key: &Seed,
    routing_tag: &RoutingTag,
    nonce: &[u8; 24],
    header: &[u8],
) -> Vec<u8> {
    let mask = header_mask(mask_key, routing_tag, nonce, header.len());
    header.iter().zip(mask).map(|(byte, m)| byte ^ m).collect()
}

pub fn control_encrypt(
    control: &StatelessTransportState,
    nonce: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut out = vec![0u8; plaintext.len() + 64];
    let written = control
        .write_message(nonce, plaintext, &mut out)
        .context("failed to write control-plane Noise message")?;
    out.truncate(written);
    Ok(out)
}

pub fn control_decrypt(
    control: &StatelessTransportState,
    nonce: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let mut out = vec![0u8; ciphertext.len() + 64];
    let read = control
        .read_message(nonce, ciphertext, &mut out)
        .context("failed to read control-plane Noise message")?;
    out.truncate(read);
    Ok(out)
}

fn nonce_from_counter(counter: u64) -> [u8; DATA_NONCE_LEN] {
    let mut nonce = [0u8; DATA_NONCE_LEN];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compat_identity_is_deterministic() {
        let seed = [0x11u8; 32];
        let a = derive_compat_identity(&seed, Role::Initiator).unwrap();
        let b = derive_compat_identity(&seed, Role::Initiator).unwrap();
        assert_eq!(a.private, b.private);
        assert_eq!(a.public, b.public);
    }

    #[test]
    fn test_data_cipher_roundtrip() {
        let secret = EpochSecret {
            data_key: [0x22; 32],
            obfs_key: [0x33; 32],
            mask_key: [0x44; 32],
        };
        let ct = encrypt_data(&secret, 17, b"hello world").unwrap();
        let pt = decrypt_data(&secret, 17, &ct).unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn test_outer_envelope_roundtrip() {
        let tag = [0xAA; 8];
        let nonce = [0xBB; 24];
        let key = [0xCC; 32];
        let payload = b"opaque envelope payload";

        let ct = seal_outer_envelope(&key, &tag, &nonce, payload).unwrap();
        let pt = open_outer_envelope(&key, &tag, &nonce, &ct).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn test_header_mask_is_reversible() {
        let tag = [0x10; 8];
        let nonce = [0x20; 24];
        let key = [0x30; 32];
        let header = b"header-bytes";
        let masked = apply_header_mask(&key, &tag, &nonce, header);
        let plain = apply_header_mask(&key, &tag, &nonce, &masked);
        assert_eq!(plain, header);
    }
}
