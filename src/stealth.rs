use crate::crypto::{
    apply_header_mask, generate_outer_nonce, open_outer_envelope, seal_outer_envelope, RoutingTag,
    OUTER_NONCE_LEN, ROUTING_TAG_LEN,
};
use anyhow::{anyhow, Result};
use rand::{rngs::OsRng, Rng};

const OUTER_TAG_LEN: usize = ROUTING_TAG_LEN + OUTER_NONCE_LEN;
const VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafficProfile {
    HttpsLike,
    VideoCallLike,
    GamingLike,
}

impl TrafficProfile {
    pub fn min_size(self) -> usize {
        match self {
            Self::HttpsLike => 640,
            Self::VideoCallLike => 280,
            Self::GamingLike => 96,
        }
    }

    pub fn max_size(self) -> usize {
        match self {
            Self::HttpsLike => 1452,
            Self::VideoCallLike => 1280,
            Self::GamingLike => 640,
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Control = 1,
    Data = 2,
}

impl FrameKind {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Control),
            2 => Some(Self::Data),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedHeader {
    pub epoch: u32,
    pub packet_no: u64,
    pub frame_kind: FrameKind,
    pub flags: u8,
    pub body_len: u16,
    pub probe_id: u16,
    pub probe_size: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedTransportPacket {
    pub routing_tag: RoutingTag,
    pub outer_nonce: [u8; OUTER_NONCE_LEN],
    pub header: ProtectedHeader,
    pub body: Vec<u8>,
    pub datagram_len: usize,
}

pub fn encode_handshake_datagram(routing_tag: RoutingTag, handshake_message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ROUTING_TAG_LEN + handshake_message.len());
    out.extend_from_slice(&routing_tag);
    out.extend_from_slice(handshake_message);
    out
}

pub fn decode_handshake_datagram(packet: &[u8]) -> Result<(RoutingTag, &[u8])> {
    if packet.len() <= ROUTING_TAG_LEN {
        return Err(anyhow!("handshake datagram too short"));
    }

    let mut tag = [0u8; ROUTING_TAG_LEN];
    tag.copy_from_slice(&packet[..ROUTING_TAG_LEN]);
    Ok((tag, &packet[ROUTING_TAG_LEN..]))
}

pub fn peek_routing_tag(packet: &[u8]) -> Result<RoutingTag> {
    if packet.len() < ROUTING_TAG_LEN {
        return Err(anyhow!("packet too short to contain routing tag"));
    }
    let mut tag = [0u8; ROUTING_TAG_LEN];
    tag.copy_from_slice(&packet[..ROUTING_TAG_LEN]);
    Ok(tag)
}

pub fn seal_transport_datagram(
    routing_tag: RoutingTag,
    obfs_key: &[u8; 32],
    mask_key: &[u8; 32],
    header: &ProtectedHeader,
    body: &[u8],
    profile: TrafficProfile,
    max_datagram: usize,
    exact_size: Option<usize>,
) -> Result<Vec<u8>> {
    let nonce = generate_outer_nonce();
    let header_plain = serialize_header(header);
    let masked_header = apply_header_mask(mask_key, &routing_tag, &nonce, &header_plain);

    let base_plain_len = 1 + masked_header.len() + body.len();
    let encrypted_floor = OUTER_TAG_LEN + base_plain_len + 16;
    let lower = encrypted_floor.max(profile.min_size());
    let upper = lower.max(profile.max_size().min(max_datagram));

    let target = if let Some(exact) = exact_size {
        exact.max(encrypted_floor).min(max_datagram)
    } else if lower >= upper {
        lower
    } else {
        OsRng.gen_range(lower..=upper)
    };

    let padding_len = target.saturating_sub(OUTER_TAG_LEN + base_plain_len + 16);
    let mut plaintext = Vec::with_capacity(base_plain_len + padding_len);
    plaintext.push(masked_header.len() as u8);
    plaintext.extend_from_slice(&masked_header);
    plaintext.extend_from_slice(body);
    plaintext.resize(base_plain_len + padding_len, 0);
    if padding_len > 0 {
        OsRng.fill(&mut plaintext[base_plain_len..]);
    }

    let sealed = seal_outer_envelope(obfs_key, &routing_tag, &nonce, &plaintext)?;
    let mut datagram = Vec::with_capacity(OUTER_TAG_LEN + sealed.len());
    datagram.extend_from_slice(&routing_tag);
    datagram.extend_from_slice(&nonce);
    datagram.extend_from_slice(&sealed);
    Ok(datagram)
}

pub fn open_transport_datagram(
    packet: &[u8],
    obfs_key: &[u8; 32],
    mask_key: &[u8; 32],
) -> Result<DecodedTransportPacket> {
    if packet.len() <= OUTER_TAG_LEN + 16 {
        return Err(anyhow!("transport datagram too short"));
    }

    let mut routing_tag = [0u8; ROUTING_TAG_LEN];
    routing_tag.copy_from_slice(&packet[..ROUTING_TAG_LEN]);

    let mut nonce = [0u8; OUTER_NONCE_LEN];
    nonce.copy_from_slice(&packet[ROUTING_TAG_LEN..OUTER_TAG_LEN]);

    let plaintext = open_outer_envelope(obfs_key, &routing_tag, &nonce, &packet[OUTER_TAG_LEN..])?;
    if plaintext.is_empty() {
        return Err(anyhow!("transport envelope plaintext is empty"));
    }

    let header_len = plaintext[0] as usize;
    if header_len == 0 {
        return Err(anyhow!("transport envelope header length is zero"));
    }
    if plaintext.len() < 1 + header_len {
        return Err(anyhow!("transport envelope truncated header"));
    }

    let header_masked = &plaintext[1..1 + header_len];
    let header_plain = apply_header_mask(mask_key, &routing_tag, &nonce, header_masked);
    let header = parse_header(&header_plain)?;

    let body_start = 1 + header_len;
    let body_end = body_start + header.body_len as usize;
    if plaintext.len() < body_end {
        return Err(anyhow!("transport envelope truncated body"));
    }

    Ok(DecodedTransportPacket {
        routing_tag,
        outer_nonce: nonce,
        header,
        body: plaintext[body_start..body_end].to_vec(),
        datagram_len: packet.len(),
    })
}

fn serialize_header(header: &ProtectedHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    out.push(VERSION);
    out.push(header.frame_kind as u8);
    out.push(header.flags);
    out.push(0);
    out.extend_from_slice(&header.epoch.to_be_bytes());
    out.extend_from_slice(&header.packet_no.to_be_bytes());
    out.extend_from_slice(&header.body_len.to_be_bytes());
    out.extend_from_slice(&header.probe_id.to_be_bytes());
    out.extend_from_slice(&header.probe_size.to_be_bytes());
    out
}

fn parse_header(raw: &[u8]) -> Result<ProtectedHeader> {
    if raw.len() < 22 {
        return Err(anyhow!("header too short: {}", raw.len()));
    }
    if raw[0] != VERSION {
        return Err(anyhow!("unsupported wire version {}", raw[0]));
    }

    let frame_kind =
        FrameKind::from_byte(raw[1]).ok_or_else(|| anyhow!("unknown frame kind {}", raw[1]))?;
    Ok(ProtectedHeader {
        epoch: u32::from_be_bytes(raw[4..8].try_into().expect("slice len checked")),
        packet_no: u64::from_be_bytes(raw[8..16].try_into().expect("slice len checked")),
        frame_kind,
        flags: raw[2],
        body_len: u16::from_be_bytes(raw[16..18].try_into().expect("slice len checked")),
        probe_id: u16::from_be_bytes(raw[18..20].try_into().expect("slice len checked")),
        probe_size: u16::from_be_bytes(raw[20..22].try_into().expect("slice len checked")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header(frame_kind: FrameKind) -> ProtectedHeader {
        ProtectedHeader {
            epoch: 7,
            packet_no: 99,
            frame_kind,
            flags: 0x5A,
            body_len: 12,
            probe_id: 44,
            probe_size: 1200,
        }
    }

    #[test]
    fn test_handshake_roundtrip() {
        let tag = [0xAA; 8];
        let packet = encode_handshake_datagram(tag, b"noise-hello");
        let (parsed_tag, body) = decode_handshake_datagram(&packet).unwrap();
        assert_eq!(parsed_tag, tag);
        assert_eq!(body, b"noise-hello");
    }

    #[test]
    fn test_transport_roundtrip() {
        let tag = [0x42; 8];
        let obfs = [0x10; 32];
        let mask = [0x20; 32];
        let header = sample_header(FrameKind::Data);
        let body = b"ciphertext123";
        let packet = seal_transport_datagram(
            tag,
            &obfs,
            &mask,
            &ProtectedHeader {
                body_len: body.len() as u16,
                ..header.clone()
            },
            body,
            TrafficProfile::GamingLike,
            1400,
            None,
        )
        .unwrap();
        let decoded = open_transport_datagram(&packet, &obfs, &mask).unwrap();
        assert_eq!(decoded.routing_tag, tag);
        assert_eq!(decoded.header.epoch, header.epoch);
        assert_eq!(decoded.header.packet_no, header.packet_no);
        assert_eq!(decoded.header.frame_kind, header.frame_kind);
        assert_eq!(decoded.body, body);
    }

    #[test]
    fn test_metadata_offsets_are_not_cleartext() {
        let tag = [0x90; 8];
        let obfs = [0x33; 32];
        let mask = [0x44; 32];
        let header = sample_header(FrameKind::Control);
        let packet = seal_transport_datagram(
            tag,
            &obfs,
            &mask,
            &ProtectedHeader {
                body_len: 4,
                ..header
            },
            b"test",
            TrafficProfile::HttpsLike,
            1452,
            Some(1024),
        )
        .unwrap();

        assert!(!packet.windows(8).any(|w| w == 99u64.to_be_bytes()));
        assert_eq!(packet.len(), 1024);
    }
}
