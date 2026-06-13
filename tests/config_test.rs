use morphvpn::config::MorphConfig;

#[test]
fn parse_minimal_config() {
    let toml = r#"
[server]
bind = "0.0.0.0:51820"
private_key = "server.key"
acl = "acl.toml"
tun = "tun0"
tun_ip = "10.8.0.1"

[server.psk]
file = "server.psk"
"#;
    let config: MorphConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.server.as_ref().unwrap().bind, "0.0.0.0:51820");
    assert_eq!(config.server.as_ref().unwrap().tun, "tun0");
}

#[test]
fn parse_client_config() {
    let toml = r#"
[client]
server = "203.0.113.10:51820"
private_key = "client.key"
server_public_key = "server.pub"
tun = "tun1"
tun_ip = "10.8.0.2"
gateway = "10.8.0.1"

[client.psk]
file = "client.psk"
"#;
    let config: MorphConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.client.as_ref().unwrap().server, "203.0.113.10:51820");
}

#[test]
fn parse_config_with_cookie_key() {
    let toml = r#"
[server]
bind = "0.0.0.0:51820"
private_key = "server.key"
acl = "acl.toml"

[server.cookie]
master_key = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344"
"#;
    let config: MorphConfig = toml::from_str(toml).unwrap();
    let cookie = config.server.as_ref().unwrap().cookie.as_ref().unwrap();
    assert!(cookie.master_key.is_some());
}

#[test]
fn parse_config_with_dns() {
    let toml = r#"
[client]
server = "203.0.113.10:51820"
private_key = "client.key"
server_public_key = "server.pub"

[client.dns]
server = "8.8.8.8"
prevent_leak = true
"#;
    let config: MorphConfig = toml::from_str(toml).unwrap();
    let dns = config.client.as_ref().unwrap().dns.as_ref().unwrap();
    assert_eq!(dns.server, "8.8.8.8");
    assert!(dns.prevent_leak);
}

#[test]
fn parse_config_with_certs() {
    let toml = r#"
[server]
bind = "0.0.0.0:51820"
private_key = "server.key"
acl = "acl.toml"

[server.cert]
cert = "server.pem"
key = "server-key.pem"
verify_peer = true
"#;
    let config: MorphConfig = toml::from_str(toml).unwrap();
    let cert = config.server.as_ref().unwrap().cert.as_ref().unwrap();
    assert!(cert.verify_peer);
    assert_eq!(cert.cert.to_str().unwrap(), "server.pem");
}

#[test]
fn parse_config_with_keepalive() {
    let toml = r#"
[client]
server = "203.0.113.10:51820"
private_key = "client.key"
server_public_key = "server.pub"

[client.keepalive]
interval_secs = 10
timeout_secs = 30
"#;
    let config: MorphConfig = toml::from_str(toml).unwrap();
    let ka = config.client.as_ref().unwrap().keepalive.as_ref().unwrap();
    assert_eq!(ka.interval_secs, 10);
    assert_eq!(ka.timeout_secs, 30);
}

#[test]
fn parse_config_with_log() {
    let toml = r#"
[log]
format = "json"
level = "debug"
"#;
    let config: MorphConfig = toml::from_str(toml).unwrap();
    let log = config.log.as_ref().unwrap();
    assert_eq!(log.format, "json");
    assert_eq!(log.level, "debug");
}

#[test]
fn parse_config_with_tcp() {
    let toml = r#"
[server]
bind = "0.0.0.0:51820"
private_key = "server.key"
acl = "acl.toml"

[server.tcp]
enabled = true
port = 51821
timeout_secs = 30
"#;
    let config: MorphConfig = toml::from_str(toml).unwrap();
    let tcp = config.server.as_ref().unwrap().tcp.as_ref().unwrap();
    assert!(tcp.enabled);
    assert_eq!(tcp.port, 51821);
    assert_eq!(tcp.timeout_secs, 30);
}

#[test]
fn validate_rejects_empty_config() {
    let config = MorphConfig::default();
    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_both_server_and_client() {
    let toml = r#"
[server]
bind = "0.0.0.0:51820"
private_key = "server.key"
acl = "acl.toml"

[client]
server = "127.0.0.1:51820"
private_key = "client.key"
server_public_key = "aa"
"#;
    let config: MorphConfig = toml::from_str(toml).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_invalid_address() {
    let toml = r#"
[server]
bind = "not-a-valid-address"
private_key = "server.key"
acl = "acl.toml"
"#;
    let config: MorphConfig = toml::from_str(toml).unwrap();
    assert!(config.validate().is_err());
}