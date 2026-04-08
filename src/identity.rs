use crate::crypto::{parse_hex_32, Seed, StaticIdentity};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn generate_x25519_identity() -> StaticIdentity {
    crate::crypto::generate_static_identity()
}

pub fn write_private_key_file(path: &Path, private_key: &Seed) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory '{}'", parent.display()))?;
        }
    }

    fs::write(path, format!("{}\n", hex::encode(private_key)))
        .with_context(|| format!("failed to write private key to '{}'", path.display()))
}

pub fn write_public_key_file(path: &Path, public_key: &Seed) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory '{}'", parent.display()))?;
        }
    }

    fs::write(path, format!("{}\n", hex::encode(public_key)))
        .with_context(|| format!("failed to write public key to '{}'", path.display()))
}

pub fn read_private_key_file(path: &Path) -> Result<StaticIdentity> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read private key '{}'", path.display()))?;
    let private = parse_hex_32(&raw, "private key")?;
    let secret = StaticSecret::from(private);
    let public = PublicKey::from(&secret).to_bytes();
    Ok(StaticIdentity { private, public })
}

pub fn read_public_key_file(path: &Path) -> Result<Seed> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read public key '{}'", path.display()))?;
    parse_hex_32(&raw, "public key")
}

pub fn read_public_key_arg(value: &str) -> Result<Seed> {
    if value.contains('\\')
        || value.contains('/')
        || value.ends_with(".key")
        || value.ends_with(".pub")
    {
        return read_public_key_file(Path::new(value));
    }
    parse_hex_32(value, "public key")
}
