use morphvpn::health::HealthServer;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn health_endpoint_returns_json() {
    let server = HealthServer::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = server.local_addr().unwrap();

    let metrics = morphvpn::metrics::MetricsHandle::new();
    let peer_manager = Arc::new(tokio::sync::RwLock::new(morphvpn::peer::PeerManager::new()));

    tokio::spawn(async move {
        server.run(metrics, peer_manager).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();

    let mut response = vec![0u8; 4096];
    let n = stream.read(&mut response).await.unwrap();
    let body = String::from_utf8_lossy(&response[..n]);

    assert!(body.contains("200 OK"));
    assert!(body.contains("\"status\":\"ok\""));
    assert!(body.contains("\"version\""));
    assert!(body.contains("\"total_peers\""));
}

#[tokio::test]
async fn health_endpoint_shows_uptime() {
    let server = HealthServer::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = server.local_addr().unwrap();

    let metrics = morphvpn::metrics::MetricsHandle::new();
    let peer_manager = Arc::new(tokio::sync::RwLock::new(morphvpn::peer::PeerManager::new()));

    tokio::spawn(async move {
        server.run(metrics, peer_manager).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();

    let mut response = vec![0u8; 4096];
    let n = stream.read(&mut response).await.unwrap();
    let body = String::from_utf8_lossy(&response[..n]);

    assert!(body.contains("\"uptime_secs\""));
}
