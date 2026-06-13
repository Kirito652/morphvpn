use morphvpn::health::HealthServer;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn health_endpoint_returns_json() {
    let server = HealthServer::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = server.local_addr().unwrap();

    let rx = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let tx = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let rx2 = rx.clone();
    let tx2 = tx.clone();

    tokio::spawn(async move {
        server.run(rx2, tx2).await.unwrap();
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
}

#[tokio::test]
async fn health_endpoint_shows_uptime() {
    let server = HealthServer::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = server.local_addr().unwrap();

    let rx = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let tx = Arc::new(std::sync::atomic::AtomicU64::new(0));

    tokio::spawn(async move {
        server.run(rx, tx).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();

    let mut response = vec![0u8; 4096];
    let n = stream.read(&mut response).await.unwrap();
    let body = String::from_utf8_lossy(&response[..n]);

    assert!(body.contains("\"uptime_secs\""));
}
