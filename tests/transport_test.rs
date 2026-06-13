use morphvpn::transport::{TcpTransport, TcpServer, UdpTransport};

#[tokio::test]
async fn udp_bind_and_local_addr() {
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = transport.local_addr().unwrap();
    assert!(addr.port() > 0);
}

#[tokio::test]
async fn tcp_server_bind_and_connect() {
    let server = TcpServer::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = server.local_addr().unwrap();

    let mut client = TcpTransport::connect(addr).await.unwrap();
    let (server_stream, _) = server.accept().await.unwrap();
    let mut server_conn = TcpTransport::from_stream(server_stream).unwrap();

    client.send(b"hello").await.unwrap();
    let mut buf = [0u8; 1024];
    let len = server_conn.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..len], b"hello");

    server_conn.send(b"world").await.unwrap();
    let len = client.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..len], b"world");
}

#[tokio::test]
async fn tcp_large_message() {
    let server = TcpServer::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = server.local_addr().unwrap();

    let mut client = TcpTransport::connect(addr).await.unwrap();
    let (server_stream, _) = server.accept().await.unwrap();
    let mut server_conn = TcpTransport::from_stream(server_stream).unwrap();

    let msg = vec![0xABu8; 4096];
    client.send(&msg).await.unwrap();
    let mut buf = [0u8; 8192];
    let len = server_conn.recv(&mut buf).await.unwrap();
    assert_eq!(len, 4096);
    assert_eq!(&buf[..len], msg.as_slice());
}