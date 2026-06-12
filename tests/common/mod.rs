use morphvpn_protocol::handshake::StaticIdentity;
use morphvpn_protocol::session::{PendingClientHandshake, PendingServerHandshake};
use morphvpn_protocol::wire::decode_handshake_frame;

pub const TEST_PSK: [u8; 32] = [0x42; 32];

pub fn establish_pair() -> (
    morphvpn_protocol::session::EstablishedSession,
    morphvpn_protocol::session::EstablishedSession,
) {
    let client_id = StaticIdentity::generate();
    let server_id = StaticIdentity::generate();

    let client_tag = [0x01; 12];
    let (pending_client, init_packet) = PendingClientHandshake::new(
        client_id,
        TEST_PSK,
        server_id.public,
        "10.8.0.5".parse().unwrap(),
        client_tag,
    )
    .unwrap();

    let server_tag = [0x02; 12];
    let init_frame = decode_handshake_frame(init_packet).unwrap();
    let (pending_server, resp_packet) = PendingServerHandshake::from_init(
        &server_id,
        &TEST_PSK,
        "127.0.0.1:5001".parse().unwrap(),
        server_tag,
        &init_frame.payload,
    )
    .unwrap();

    let (client_session, finish_packet) = pending_client.into_established(resp_packet).unwrap();
    let server_session = pending_server.complete(finish_packet, TEST_PSK).unwrap();

    (client_session, server_session)
}
