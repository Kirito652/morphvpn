use morphvpn::transport::{TcpServer, TcpTransport};

#[tokio::test]
async fn tcp_tunnel_frame_roundtrip() {
    let server = TcpServer::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = server.local_addr().unwrap();

    let mut client = TcpTransport::connect(addr).await.unwrap();
    let (server_stream, _) = server.accept().await.unwrap();
    let mut server_conn = TcpTransport::from_stream(server_stream).unwrap();

    let mut packet = vec![0u8; 12 + 32];
    packet[..12].copy_from_slice(&[0xAA; 12]);
    packet[12..].copy_from_slice(&[0xBB; 32]);

    client.send(&packet).await.unwrap();
    let mut buf = [0u8; 65535];
    let len = server_conn.recv(&mut buf).await.unwrap();
    assert_eq!(len, 44);
    assert_eq!(&buf[..12], &[0xAA; 12]);
    assert_eq!(&buf[12..44], &[0xBB; 32]);
}

#[tokio::test]
async fn tcp_tunnel_multiple_packets() {
    let server = TcpServer::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = server.local_addr().unwrap();

    let mut client = TcpTransport::connect(addr).await.unwrap();
    let (server_stream, _) = server.accept().await.unwrap();
    let mut server_conn = TcpTransport::from_stream(server_stream).unwrap();

    for i in 0..5u8 {
        let mut packet = vec![0u8; 12 + 16];
        packet[..12].copy_from_slice(&[i; 12]);
        packet[12..].copy_from_slice(&[i + 100; 16]);
        client.send(&packet).await.unwrap();
    }

    let mut buf = [0u8; 65535];
    for i in 0..5u8 {
        let len = server_conn.recv(&mut buf).await.unwrap();
        assert_eq!(len, 28);
        assert_eq!(buf[0], i);
        assert_eq!(buf[12], i + 100);
    }
}

#[tokio::test]
async fn tcp_tunnel_large_packet() {
    let server = TcpServer::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = server.local_addr().unwrap();

    let mut client = TcpTransport::connect(addr).await.unwrap();
    let (server_stream, _) = server.accept().await.unwrap();
    let mut server_conn = TcpTransport::from_stream(server_stream).unwrap();

    let mut packet = vec![0u8; 1400];
    packet[..12].copy_from_slice(&[0xCC; 12]);
    for i in 12..1400 {
        packet[i] = (i % 256) as u8;
    }

    client.send(&packet).await.unwrap();
    let mut buf = [0u8; 8192];
    let len = server_conn.recv(&mut buf).await.unwrap();
    assert_eq!(len, 1400);
    assert_eq!(&buf[..12], &[0xCC; 12]);
}

#[tokio::test]
async fn tcp_bidirectional_tunnel() {
    let server = TcpServer::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = server.local_addr().unwrap();

    let mut client = TcpTransport::connect(addr).await.unwrap();
    let (server_stream, _) = server.accept().await.unwrap();
    let mut server_conn = TcpTransport::from_stream(server_stream).unwrap();

    let mut pkt1 = vec![0u8; 12 + 8];
    pkt1[..12].copy_from_slice(&[0x01; 12]);
    pkt1[12..].copy_from_slice(b"ping!!!!");
    client.send(&pkt1).await.unwrap();

    let mut buf = [0u8; 65535];
    let len = server_conn.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[12..20], b"ping!!!!");

    let mut pkt2 = vec![0u8; 12 + 8];
    pkt2[..12].copy_from_slice(&[0x02; 12]);
    pkt2[12..].copy_from_slice(b"pong!!!!");
    server_conn.send(&pkt2).await.unwrap();

    let len = client.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[12..20], b"pong!!!!");
}
