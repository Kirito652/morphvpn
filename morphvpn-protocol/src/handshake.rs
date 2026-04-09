use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use rand::rngs::OsRng;
use snow::{params::NoiseParams, Builder, HandshakeState, StatelessTransportState};
use x25519_dalek::{PublicKey, StaticSecret};

pub type Seed = [u8; 32];
pub const NOISE_PATTERN: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticIdentity {
    pub private: Seed,
    pub public: Seed,
}

#[derive(Debug)]
pub struct Established {
    pub control: StatelessTransportState,
    pub handshake_hash: Bytes,
    pub remote_static: Option<Seed>,
}

#[derive(Debug)]
pub struct InitiatorCreated {
    state: HandshakeState,
    expected_remote_static: Option<Seed>,
}

#[derive(Debug)]
pub struct WaitResp {
    state: HandshakeState,
    expected_remote_static: Option<Seed>,
}

#[derive(Debug)]
pub struct SendFinish {
    state: HandshakeState,
    expected_remote_static: Option<Seed>,
    remote_static: Option<Seed>,
}

#[derive(Debug)]
pub struct ResponderCreated {
    state: HandshakeState,
}

#[derive(Debug)]
pub struct SendResp {
    state: HandshakeState,
}

#[derive(Debug)]
pub struct WaitFinish {
    state: HandshakeState,
}

impl StaticIdentity {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            private: secret.to_bytes(),
            public: public.to_bytes(),
        }
    }
}

impl InitiatorCreated {
    pub fn new(identity: &StaticIdentity, psk: &Seed, expected_remote_static: Option<Seed>) -> Result<Self> {
        Ok(Self {
            state: build_initiator_state(identity, psk)?,
            expected_remote_static,
        })
    }

    pub fn send_init(mut self, payload: &[u8]) -> Result<(WaitResp, Bytes)> {
        let message = write_message(&mut self.state, payload)?;
        Ok((
            WaitResp {
                state: self.state,
                expected_remote_static: self.expected_remote_static,
            },
            message,
        ))
    }
}

impl WaitResp {
    pub fn read_resp(mut self, input: &[u8]) -> Result<SendFinish> {
        let _ = read_message(&mut self.state, input)?;
        let remote_static = copy_remote_static(&self.state)?;
        verify_expected_remote_static(self.expected_remote_static.as_ref(), remote_static.as_ref())?;

        Ok(SendFinish {
            state: self.state,
            expected_remote_static: self.expected_remote_static,
            remote_static,
        })
    }
}

impl SendFinish {
    pub fn send_finish(mut self, payload: &[u8]) -> Result<(Established, Bytes)> {
        let message = write_message(&mut self.state, payload)?;
        let established = finish_handshake(self.state, self.expected_remote_static.as_ref())?;
        Ok((established.with_remote_static(self.remote_static), message))
    }
}

impl ResponderCreated {
    pub fn new(identity: &StaticIdentity, psk: &Seed) -> Result<Self> {
        Ok(Self {
            state: build_responder_state(identity, psk)?,
        })
    }

    pub fn read_init(mut self, input: &[u8]) -> Result<SendResp> {
        let _ = read_message(&mut self.state, input)?;
        Ok(SendResp { state: self.state })
    }
}

impl SendResp {
    pub fn send_resp(mut self, payload: &[u8]) -> Result<(WaitFinish, Bytes)> {
        let message = write_message(&mut self.state, payload)?;
        Ok((WaitFinish { state: self.state }, message))
    }
}

impl WaitFinish {
    pub fn read_finish(mut self, input: &[u8]) -> Result<Established> {
        let _ = read_message(&mut self.state, input)?;
        finish_handshake(self.state, None)
    }
}

impl Established {
    fn with_remote_static(mut self, remote_static: Option<Seed>) -> Self {
        if self.remote_static.is_none() {
            self.remote_static = remote_static;
        }
        self
    }

    pub fn encrypt_control(&self, nonce: u64, plaintext: &[u8]) -> Result<Bytes> {
        let mut out = vec![0u8; plaintext.len() + 64];
        let written = self
            .control
            .write_message(nonce, plaintext, &mut out)
            .context("failed to write Noise control message")?;
        out.truncate(written);
        Ok(Bytes::from(out))
    }

    pub fn decrypt_control(&self, nonce: u64, ciphertext: &[u8]) -> Result<Bytes> {
        let mut out = vec![0u8; ciphertext.len() + 64];
        let read = self
            .control
            .read_message(nonce, ciphertext, &mut out)
            .context("failed to read Noise control message")?;
        out.truncate(read);
        Ok(Bytes::from(out))
    }
}

fn build_initiator_state(identity: &StaticIdentity, psk: &Seed) -> Result<HandshakeState> {
    let params: NoiseParams = NOISE_PATTERN.parse().context("invalid Noise params")?;
    Builder::new(params)
        .local_private_key(&identity.private)?
        .psk(3, psk)
        .context("failed to attach psk to initiator handshake")?
        .build_initiator()
        .context("failed to build initiator handshake")
}

fn build_responder_state(identity: &StaticIdentity, psk: &Seed) -> Result<HandshakeState> {
    let params: NoiseParams = NOISE_PATTERN.parse().context("invalid Noise params")?;
    Builder::new(params)
        .local_private_key(&identity.private)?
        .psk(3, psk)
        .context("failed to attach psk to responder handshake")?
        .build_responder()
        .context("failed to build responder handshake")
}

fn write_message(state: &mut HandshakeState, payload: &[u8]) -> Result<Bytes> {
    let mut out = vec![0u8; 1024];
    let written = state
        .write_message(payload, &mut out)
        .context("failed to write handshake message")?;
    out.truncate(written);
    Ok(Bytes::from(out))
}

fn read_message(state: &mut HandshakeState, input: &[u8]) -> Result<Bytes> {
    let mut out = vec![0u8; 1024];
    let read = state
        .read_message(input, &mut out)
        .context("failed to read handshake message")?;
    out.truncate(read);
    Ok(Bytes::from(out))
}

fn finish_handshake(state: HandshakeState, expected_remote_static: Option<&Seed>) -> Result<Established> {
    let remote_static = copy_remote_static(&state)?;
    verify_expected_remote_static(expected_remote_static, remote_static.as_ref())?;
    let handshake_hash = Bytes::copy_from_slice(state.get_handshake_hash());
    let control = state
        .into_stateless_transport_mode()
        .context("failed to enter stateless transport mode")?;

    Ok(Established {
        control,
        handshake_hash,
        remote_static,
    })
}

fn copy_remote_static(state: &HandshakeState) -> Result<Option<Seed>> {
    let Some(remote) = state.get_remote_static() else {
        return Ok(None);
    };
    if remote.len() != 32 {
        return Err(anyhow!("unexpected remote static length {}", remote.len()));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(remote);
    Ok(Some(key))
}

fn verify_expected_remote_static(expected: Option<&Seed>, actual: Option<&Seed>) -> Result<()> {
    if let Some(expected_key) = expected {
        let actual_key = actual.ok_or_else(|| anyhow!("remote static key missing"))?;
        if actual_key != expected_key {
            return Err(anyhow!("remote static key mismatch"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PSK: Seed = [0x42; 32];

    #[test]
    fn xxpsk3_typestate_handshake_roundtrip() {
        let client = StaticIdentity::generate();
        let server = StaticIdentity::generate();

        let initiator = InitiatorCreated::new(&client, &TEST_PSK, Some(server.public))
            .unwrap_or_else(|err| panic!("{err}"));
        let responder =
            ResponderCreated::new(&server, &TEST_PSK).unwrap_or_else(|err| panic!("{err}"));

        let (wait_resp, init) = initiator
            .send_init(b"init")
            .unwrap_or_else(|err| panic!("{err}"));
        let send_resp = responder
            .read_init(&init)
            .unwrap_or_else(|err| panic!("{err}"));
        let (wait_finish, resp) = send_resp
            .send_resp(b"resp")
            .unwrap_or_else(|err| panic!("{err}"));
        let send_finish = wait_resp
            .read_resp(&resp)
            .unwrap_or_else(|err| panic!("{err}"));
        let (established_client, finish) = send_finish
            .send_finish(b"finish")
            .unwrap_or_else(|err| panic!("{err}"));
        let established_server = wait_finish
            .read_finish(&finish)
            .unwrap_or_else(|err| panic!("{err}"));

        assert_eq!(established_client.remote_static, Some(server.public));
        assert_eq!(established_server.remote_static, Some(client.public));

        let ciphertext = established_client
            .encrypt_control(0, b"hello")
            .unwrap_or_else(|err| panic!("{err}"));
        let plaintext = established_server
            .decrypt_control(0, &ciphertext)
            .unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(plaintext, Bytes::from_static(b"hello"));
    }
}
