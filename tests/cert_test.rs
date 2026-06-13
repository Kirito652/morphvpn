use morphvpn::cert::{CertIdentity, validate_cert_chain};

#[test]
fn generate_server_and_client_certs() {
    let server = CertIdentity::generate_cn("morphvpn-server").unwrap();
    let client = CertIdentity::generate_cn("morphvpn-client").unwrap();

    assert!(!server.cert_pem.is_empty());
    assert!(!client.cert_pem.is_empty());
    assert_ne!(server.fingerprint, client.fingerprint);
}

#[test]
fn validate_cert_chain_works() {
    let server = CertIdentity::generate_cn("server").unwrap();
    let client = CertIdentity::generate_cn("client").unwrap();
    assert!(validate_cert_chain(&server.cert_pem, &client.cert_pem).unwrap());
}
