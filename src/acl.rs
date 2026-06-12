use anyhow::{anyhow, Context, Result};
use morphvpn_protocol::handshake::Seed;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct AuthorizedClient {
    pub name: String,
    pub public_key: Seed,
    pub inner_ip: Ipv4Addr,
}

#[derive(Clone, Debug, Default)]
pub struct AccessControlList {
    clients: HashMap<Seed, AuthorizedClient>,
}

impl AccessControlList {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read ACL file '{}'", path.display()))?;
        let parsed: AclFile = toml::from_str(&raw)
            .with_context(|| format!("failed to parse ACL TOML '{}'", path.display()))?;

        let mut clients = HashMap::new();
        for entry in parsed.clients {
            let public_key = parse_hex_32(&entry.public_key, "ACL public key")
                .with_context(|| format!("invalid public key for ACL client '{}'", entry.name))?;
            let inner_ip: Ipv4Addr = entry
                .inner_ip
                .parse()
                .with_context(|| format!("invalid inner_ip for ACL client '{}'", entry.name))?;

            let client = AuthorizedClient {
                name: entry.name,
                public_key,
                inner_ip,
            };
            if clients.insert(public_key, client).is_some() {
                return Err(anyhow!("duplicate ACL public key entry"));
            }
        }

        Ok(Self { clients })
    }

    pub fn authorize(&self, public_key: &Seed) -> Option<&AuthorizedClient> {
        self.clients
            .get(public_key)
            .filter(|client| client.public_key == *public_key)
    }

}

#[derive(Debug, Deserialize)]
struct AclFile {
    #[serde(default)]
    clients: Vec<AclClientEntry>,
}

#[derive(Debug, Deserialize)]
struct AclClientEntry {
    name: String,
    public_key: String,
    inner_ip: String,
}

fn parse_hex_32(raw: &str, label: &str) -> Result<Seed> {
    let bytes = hex::decode(raw.trim())
        .with_context(|| format!("failed to decode {label} as hex"))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "{label} must be exactly 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acl_lookup() {
        let raw = r#"
            [[clients]]
            name = "alice"
            public_key = "1111111111111111111111111111111111111111111111111111111111111111"
            inner_ip = "10.8.0.5"
        "#;

        let parsed: AclFile = toml::from_str(raw).unwrap();
        let mut clients = HashMap::new();
        let key = parse_hex_32(&parsed.clients[0].public_key, "test").unwrap();
        clients.insert(
            key,
            AuthorizedClient {
                name: parsed.clients[0].name.clone(),
                public_key: key,
                inner_ip: parsed.clients[0].inner_ip.parse().unwrap(),
            },
        );

        let acl = AccessControlList { clients };
        assert_eq!(
            acl.authorize(&key).unwrap().inner_ip,
            "10.8.0.5".parse::<Ipv4Addr>().unwrap()
        );
    }
}
