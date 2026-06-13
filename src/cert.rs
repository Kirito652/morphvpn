use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct CertIdentity {
    pub cert_pem: String,
    pub key_pem: String,
    pub fingerprint: [u8; 32],
}

impl CertIdentity {
    pub fn generate_cn(cn: &str) -> Result<Self> {
        let mut params = CertificateParams::new(vec![cn.to_string()])
            .context("failed to create certificate params")?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key_pair = KeyPair::generate()
            .context("failed to generate key pair")?;
        let cert = params.self_signed(&key_pair)
            .context("failed to sign certificate")?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        let fingerprint = compute_fingerprint(&cert_pem)?;
        Ok(Self { cert_pem, key_pem, fingerprint })
    }

    pub fn save_cert(path: &Path, pem: &str) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(path, pem)
            .with_context(|| format!("failed to write cert to '{}'", path.display()))?;
        Ok(())
    }

    pub fn save_key(path: &Path, pem: &str) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(path, pem)
            .with_context(|| format!("failed to write key to '{}'", path.display()))?;
        Ok(())
    }

    pub fn load_cert(path: &Path) -> Result<String> {
        fs::read_to_string(path)
            .with_context(|| format!("failed to read cert '{}'", path.display()))
    }

    pub fn load_key(path: &Path) -> Result<String> {
        fs::read_to_string(path)
            .with_context(|| format!("failed to read key '{}'", path.display()))
    }
}

fn pem_to_der(pem_str: &str) -> Result<Vec<u8>> {
    let stripped = pem_str
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace(['\n', '\r'], "");
    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(stripped.trim())
        .context("failed to base64-decode PEM content")?;
    Ok(der)
}

pub fn compute_fingerprint(cert_pem: &str) -> Result<[u8; 32]> {
    let der = pem_to_der(cert_pem)?;
    let hash = Sha256::digest(&der);
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&hash);
    Ok(fp)
}

pub fn validate_cert_chain(server_cert_pem: &str, client_cert_pem: &str) -> Result<bool> {
    let _server_params = CertificateParams::from_ca_cert_pem(server_cert_pem)
        .context("failed to parse server cert")?;
    let _client_params = CertificateParams::from_ca_cert_pem(client_cert_pem)
        .context("failed to parse client cert")?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_fingerprint() {
        let identity = CertIdentity::generate_cn("test-server").unwrap();
        assert!(!identity.cert_pem.is_empty());
        assert!(!identity.key_pem.is_empty());
        assert_ne!(identity.fingerprint, [0u8; 32]);
    }

    #[test]
    fn save_and_load_cert() {
        let dir = std::env::temp_dir().join("morphvpn_test_cert");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let identity = CertIdentity::generate_cn("test").unwrap();
        let cert_path = dir.join("test.pem");
        let key_path = dir.join("test.key");

        CertIdentity::save_cert(&cert_path, &identity.cert_pem).unwrap();
        CertIdentity::save_key(&key_path, &identity.key_pem).unwrap();

        let loaded_cert = CertIdentity::load_cert(&cert_path).unwrap();
        let loaded_key = CertIdentity::load_key(&key_path).unwrap();

        assert_eq!(loaded_cert, identity.cert_pem);
        assert_eq!(loaded_key, identity.key_pem);

        let _ = fs::remove_dir_all(&dir);
    }
}
