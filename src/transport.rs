use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::{TcpListener as TokioTcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportType {
    Udp,
    Tcp,
}

pub struct UdpTransport {
    socket: Arc<UdpSocket>,
}

impl UdpTransport {
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self { socket: Arc::new(socket) })
    }

    pub async fn send_to(&self, data: &[u8], target: SocketAddr) -> Result<usize> {
        let len = self.socket.send_to(data, target).await?;
        Ok(len)
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (len, addr) = self.socket.recv_from(buf).await?;
        Ok((len, addr))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
}

pub struct TcpTransport {
    stream: TcpStream,
    peer: SocketAddr,
}

impl TcpTransport {
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let peer = stream.peer_addr()?;
        Ok(Self { stream, peer })
    }

    pub fn from_stream(stream: TcpStream) -> Result<Self> {
        let peer = stream.peer_addr()?;
        Ok(Self { stream, peer })
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        let len = data.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > buf.len() {
            anyhow::bail!("TCP frame too large: {} bytes", len);
        }
        self.stream.read_exact(&mut buf[..len]).await?;
        Ok(len)
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
}

pub struct TcpServer {
    listener: TokioTcpListener,
}

impl TcpServer {
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let listener = TokioTcpListener::bind(addr).await?;
        Ok(Self { listener })
    }

    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        Ok((stream, addr))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
}