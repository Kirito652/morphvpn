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