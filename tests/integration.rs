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

#[test]
fn rekey_rotates_keys_and_continues_communication() {
    let (mut client, mut server) = common::establish_pair();

    // Send some data before rekey
    let payload1 = b"before rekey";
    let encrypted1 = client
        .send_data(bytes::Bytes::from_static(payload1), 8)
        .unwrap();
    let event = server.open_inbound(encrypted1).unwrap();
    match event {
        morphvpn_protocol::session::SessionEvent::Data(data) => {
            assert_eq!(data.as_ref(), payload1);
        }
        other => panic!("expected Data, got {:?}", other),
    }

    // Force rekey by exhausting nonce
    client.data_tx_nonce = u64::MAX - 100;
    let rekey_init = client.advance_rekey().unwrap().unwrap();

    // Server processes rekey init
    let event = server.open_inbound(rekey_init).unwrap();
    match event {
        morphvpn_protocol::session::SessionEvent::Control(frame) => {
            match frame {
                morphvpn_protocol::wire::ControlFrame::RekeyInit { epoch, .. } => {
                    let resp = server.handle_rekey_init(epoch, [0; 32]).unwrap().unwrap();
                    // Client processes rekey response
                    let event2 = client.open_inbound(resp).unwrap();
                    match event2 {
                        morphvpn_protocol::session::SessionEvent::Control(
                            morphvpn_protocol::wire::ControlFrame::RekeyResp { epoch, .. },
                        ) => {
                            client.handle_rekey_resp(epoch, [0; 32]).unwrap();
                        }
                        other => panic!("expected RekeyResp, got {:?}", other),
                    }
                }
                other => panic!("expected RekeyInit, got {:?}", other),
            }
        }
        other => panic!("expected Control, got {:?}", other),
    }

    // Verify nonce counters reset
    assert_eq!(client.data_tx_nonce, 0);
    assert_eq!(server.data_tx_nonce, 0);

    // Send data after rekey
    let payload2 = b"after rekey";
    let encrypted2 = client
        .send_data(bytes::Bytes::from_static(payload2), 8)
        .unwrap();
    let event = server.open_inbound(encrypted2).unwrap();
    match event {
        morphvpn_protocol::session::SessionEvent::Data(data) => {
            assert_eq!(data.as_ref(), payload2);
        }
        other => panic!("expected Data after rekey, got {:?}", other),
    }
}
