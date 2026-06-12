use crate::wire::{Mac, RoutingTag, MAC_LEN};
use anyhow::{anyhow, Result};
use blake2::digest::Mac as BlakeMac;
use blake2::Blake2sMac256;
use hmac::{Hmac, Mac as HmacMac};
use sha2::Sha256;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAC1_PERSONA: &[u8] = b"mvp1mac1";
const COOKIE_PERSONA: &[u8] = b"mvp1cook";

pub type Cookie = Mac;

#[derive(Clone, Debug)]
pub struct StatelessCookieGenerator {
    master_key: [u8; 32],
    rotation_period: Duration,
}

impl StatelessCookieGenerator {
    pub fn new(master_key: [u8; 32], rotation_period: Duration) -> Result<Self> {
        if rotation_period.is_zero() {
            return Err(anyhow!("rotation period must be non-zero"));
        }

        Ok(Self {
            master_key,
            rotation_period,
        })
    }

    pub fn compute_mac1(&self, responder_public_key: &[u8; 32], packet: &[u8]) -> Result<Mac> {
        compute_mac1(responder_public_key, packet)
    }

    pub fn verify_mac1(
        &self,
        responder_public_key: &[u8; 32],
        packet: &[u8],
        mac1: &Mac,
    ) -> Result<bool> {
        verify_mac1(responder_public_key, packet, mac1)
    }

    pub fn issue_cookie(
        &self,
        source: SocketAddr,
        routing_tag: &RoutingTag,
        now: SystemTime,
    ) -> Result<Cookie> {
        let bucket = current_bucket(now, self.rotation_period)?;
        derive_cookie(&self.master_key, bucket, source, routing_tag)
    }

    pub fn validate_cookie(
        &self,
        cookie: &Cookie,
        source: SocketAddr,
        routing_tag: &RoutingTag,
        now: SystemTime,
    ) -> Result<bool> {
        let bucket = current_bucket(now, self.rotation_period)?;
        let current = derive_cookie(&self.master_key, bucket, source, routing_tag)?;
        if current == *cookie {
            return Ok(true);
        }

        if bucket == 0 {
            return Ok(false);
        }

        let previous = derive_cookie(&self.master_key, bucket - 1, source, routing_tag)?;
        Ok(previous == *cookie)
    }

    pub fn compute_mac2(&self, cookie: &Cookie, packet: &[u8]) -> Result<Mac> {
        compute_mac2(cookie, packet)
    }

    pub fn verify_mac2(&self, cookie: &Cookie, packet: &[u8], mac2: &Mac) -> Result<bool> {
        verify_mac2(cookie, packet, mac2)
    }

    pub fn rotation_period(&self) -> Duration {
        self.rotation_period
    }
}

pub fn compute_mac1(responder_public_key: &[u8; 32], packet: &[u8]) -> Result<Mac> {
    let mut mac = Blake2sMac256::new_with_salt_and_personal(responder_public_key, &[], MAC1_PERSONA)
        .map_err(|_| anyhow!("failed to initialize MAC1 context"))?;
    mac.update(packet);
    let output = mac.finalize().into_bytes();
    Ok(truncate_mac(&output))
}

pub fn verify_mac1(
    responder_public_key: &[u8; 32],
    packet: &[u8],
    mac1: &Mac,
) -> Result<bool> {
    let computed = compute_mac1(responder_public_key, packet)?;
    Ok(computed == *mac1)
}

pub fn compute_mac2(cookie: &Cookie, packet: &[u8]) -> Result<Mac> {
    let mut mac = <Hmac<Sha256> as HmacMac>::new_from_slice(cookie)
        .map_err(|_| anyhow!("failed to initialize MAC2 context"))?;
    mac.update(packet);
    let output = mac.finalize().into_bytes();
    Ok(truncate_mac(&output))
}

pub fn verify_mac2(cookie: &Cookie, packet: &[u8], mac2: &Mac) -> Result<bool> {
    let computed = compute_mac2(cookie, packet)?;
    Ok(computed == *mac2)
}

fn derive_cookie(
    master_key: &[u8; 32],
    bucket: u64,
    source: SocketAddr,
    routing_tag: &RoutingTag,
) -> Result<Cookie> {
    let mut mac = <Hmac<Sha256> as HmacMac>::new_from_slice(master_key)
        .map_err(|_| anyhow!("failed to initialize cookie HMAC context"))?;
    mac.update(COOKIE_PERSONA);
    mac.update(&bucket.to_be_bytes());
    update_socket_addr(&mut mac, source);
    mac.update(routing_tag);
    let output = mac.finalize().into_bytes();
    Ok(truncate_mac(&output))
}

fn current_bucket(now: SystemTime, rotation_period: Duration) -> Result<u64> {
    let since_epoch = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("system clock is set before UNIX_EPOCH"))?;
    let period_nanos = rotation_period.as_nanos();
    if period_nanos == 0 {
        return Err(anyhow!("rotation period must resolve to at least one nanosecond"));
    }

    Ok((since_epoch.as_nanos() / period_nanos) as u64)
}

fn truncate_mac(bytes: &[u8]) -> Mac {
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&bytes[..MAC_LEN]);
    out
}

fn update_socket_addr<M: HmacMac>(mac: &mut M, source: SocketAddr) {
    match source.ip() {
        IpAddr::V4(v4) => {
            mac.update(&[4]);
            mac.update(&v4.octets());
        }
        IpAddr::V6(v6) => {
            mac.update(&[6]);
            mac.update(&v6.octets());
        }
    }
    mac.update(&source.port().to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generator() -> StatelessCookieGenerator {
        StatelessCookieGenerator::new([0x11; 32], Duration::from_secs(60))
            .unwrap_or_else(|err| panic!("{err}"))
    }

    #[test]
    fn mac1_roundtrip() {
        let responder_public = [0x22; 32];
        let packet = b"client-init-frame";
        let generator = generator();

        let mac1 = generator
            .compute_mac1(&responder_public, packet)
            .unwrap_or_else(|err| panic!("{err}"));
        assert!(
            generator
                .verify_mac1(&responder_public, packet, &mac1)
                .unwrap_or_else(|err| panic!("{err}"))
        );
        assert!(
            !generator
                .verify_mac1(&responder_public, b"wrong", &mac1)
                .unwrap_or_else(|err| panic!("{err}"))
        );
    }

    #[test]
    fn cookie_rejects_wrong_source() {
        let generator = generator();
        let tag = [0x33; 12];
        let issued_at = UNIX_EPOCH + Duration::from_secs(600);
        let cookie = generator
            .issue_cookie("127.0.0.1:5000".parse().unwrap_or_else(|err| panic!("{err}")), &tag, issued_at)
            .unwrap_or_else(|err| panic!("{err}"));

        assert!(
            !generator
                .validate_cookie(
                    &cookie,
                    "127.0.0.1:5001".parse().unwrap_or_else(|err| panic!("{err}")),
                    &tag,
                    issued_at
                )
                .unwrap_or_else(|err| panic!("{err}"))
        );
    }

    #[test]
    fn cookie_accepts_previous_bucket_only() {
        let generator = generator();
        let source = "127.0.0.1:5000"
            .parse()
            .unwrap_or_else(|err| panic!("{err}"));
        let tag = [0x44; 12];
        let issued_at = UNIX_EPOCH + Duration::from_secs(600);
        let cookie = generator
            .issue_cookie(source, &tag, issued_at)
            .unwrap_or_else(|err| panic!("{err}"));

        let next_bucket = issued_at + Duration::from_secs(60);
        let far_bucket = issued_at + Duration::from_secs(121);

        assert!(
            generator
                .validate_cookie(&cookie, source, &tag, next_bucket)
                .unwrap_or_else(|err| panic!("{err}"))
        );
        assert!(
            !generator
                .validate_cookie(&cookie, source, &tag, far_bucket)
                .unwrap_or_else(|err| panic!("{err}"))
        );
    }

    #[test]
    fn mac2_roundtrip() {
        let generator = generator();
        let packet = b"init-with-cookie";
        let cookie = [0x55; MAC_LEN];

        let mac2 = generator
            .compute_mac2(&cookie, packet)
            .unwrap_or_else(|err| panic!("{err}"));
        assert!(
            generator
                .verify_mac2(&cookie, packet, &mac2)
                .unwrap_or_else(|err| panic!("{err}"))
        );
        assert!(
            !generator
                .verify_mac2(&cookie, b"tampered", &mac2)
                .unwrap_or_else(|err| panic!("{err}"))
        );
    }
}
