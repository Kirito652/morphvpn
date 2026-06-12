mod common;

use common::TEST_PSK;
use morphvpn_protocol::handshake::StaticIdentity;
use morphvpn_protocol::session::{PendingClientHandshake, PendingServerHandshake};
use morphvpn_protocol::wire::{decode_handshake_frame, ControlFrame};

#[test]
fn full_handshake_and_data_transfer() {
    let client_id = StaticIdentity::generate();
    let server_id = StaticIdentity::generate();

    let client_tag = [0xAA; 12];
    let (pending_client, init_packet) = PendingClientHandshake::new(
        client_id.clone(),
        TEST_PSK,
        server_id.public,
        "10.8.0.5".parse().unwrap(),
        client_tag,
    )
    .unwrap();

    let server_tag = [0xBB; 12];
    let init_frame = decode_handshake_frame(init_packet).unwrap();
    let (pending_server, resp_packet) = PendingServerHandshake::from_init(
        &server_id,
        &TEST_PSK,
        "127.0.0.1:5001".parse().unwrap(),
        server_tag,
        &init_frame.payload,
    )
    .unwrap();

    let (mut client_session, finish_packet) = pending_client.into_established(resp_packet).unwrap();
    let mut server_session = pending_server.complete(finish_packet, TEST_PSK).unwrap();

    client_session.assign_ip("10.8.0.5".parse().unwrap());
    server_session.assign_ip("10.8.0.1".parse().unwrap());

    let test_payload = b"Hello from MorphVPN client!";
    let encrypted = client_session
        .send_data(bytes::Bytes::from_static(test_payload), 8)
        .unwrap();
    assert!(encrypted.len() > test_payload.len());

    let event = server_session.open_inbound(encrypted).unwrap();
    match event {
        morphvpn_protocol::session::SessionEvent::Data(payload) => {
            assert_eq!(payload.as_ref(), test_payload);
        }
        other => panic!("expected Data event, got {:?}", other),
    }

    let reply_payload = b"Hello from MorphVPN server!";
    let encrypted_reply = server_session
        .send_data(bytes::Bytes::from_static(reply_payload), 8)
        .unwrap();

    let event = client_session.open_inbound(encrypted_reply).unwrap();
    match event {
        morphvpn_protocol::session::SessionEvent::Data(payload) => {
            assert_eq!(payload.as_ref(), reply_payload);
        }
        other => panic!("expected Data event, got {:?}", other),
    }
}

#[test]
fn control_frame_keepalive_roundtrip() {
    let (mut client, mut server) = common::establish_pair();

    let keepalive = client.send_keepalive().unwrap();
    let event = server.open_inbound(keepalive).unwrap();
    match event {
        morphvpn_protocol::session::SessionEvent::Control(frame) => {
            assert_eq!(frame, ControlFrame::Keepalive);
        }
        other => panic!("expected Control event, got {:?}", other),
    }

    let ack = server.send_keepalive_ack().unwrap();
    let event = client.open_inbound(ack).unwrap();
    match event {
        morphvpn_protocol::session::SessionEvent::Control(frame) => {
            assert_eq!(frame, ControlFrame::KeepaliveAck);
        }
        other => panic!("expected Control event, got {:?}", other),
    }
}

#[test]
fn bootstrap_init_resp_roundtrip() {
    let (mut client, mut server) = common::establish_pair();

    let bootstrap = client
        .send_bootstrap_init("10.8.0.5".parse().unwrap())
        .unwrap();
    let event = server.open_inbound(bootstrap).unwrap();
    match event {
        morphvpn_protocol::session::SessionEvent::Control(frame) => match frame {
            ControlFrame::BootstrapInit { requested_ip } => {
                assert_eq!(
                    requested_ip,
                    "10.8.0.5".parse::<std::net::Ipv4Addr>().unwrap()
                );
            }
            other => panic!("expected BootstrapInit, got {:?}", other),
        },
        other => panic!("expected Control event, got {:?}", other),
    }

    let resp = server
        .send_bootstrap_resp("10.8.0.5".parse().unwrap())
        .unwrap();
    let event = client.open_inbound(resp).unwrap();
    match event {
        morphvpn_protocol::session::SessionEvent::Control(frame) => match frame {
            ControlFrame::BootstrapResp { assigned_ip } => {
                assert_eq!(
                    assigned_ip,
                    "10.8.0.5".parse::<std::net::Ipv4Addr>().unwrap()
                );
            }
            other => panic!("expected BootstrapResp, got {:?}", other),
        },
        other => panic!("expected Control event, got {:?}", other),
    }
}
