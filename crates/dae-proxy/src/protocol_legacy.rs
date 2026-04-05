//! Proxy protocol implementations

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub enum ProxyProtocol {
    Http,
    Socks5,
    Shadowsocks,
    VLess,
    Trojan,
}

impl ProxyProtocol {
    pub fn name(&self) -> &'static str {
        match self {
            ProxyProtocol::Http => "HTTP",
            ProxyProtocol::Socks5 => "SOCKS5",
            ProxyProtocol::Shadowsocks => "Shadowsocks",
            ProxyProtocol::VLess => "VLESS",
            ProxyProtocol::Trojan => "Trojan",
        }
    }
}

/// A proxy connection handler
pub struct ProxyHandler {
    protocol: ProxyProtocol,
}

impl ProxyHandler {
    pub fn new(protocol: ProxyProtocol) -> Self {
        Self { protocol }
    }

    pub fn protocol_name(&self) -> &'static str {
        self.protocol.name()
    }

    /// Forward traffic between client and remote
    pub async fn forward(&self, mut client: TcpStream, remote_addr: &str) -> std::io::Result<()> {
        let mut remote = TcpStream::connect(remote_addr).await?;

        // Simple byte forwarding (placeholder for actual protocol implementation)
        let mut buf = vec![0u8; 8192];
        loop {
            let n = client.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            remote.write_all(&buf[..n]).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_names() {
        assert_eq!(ProxyProtocol::Http.name(), "HTTP");
        assert_eq!(ProxyProtocol::Socks5.name(), "SOCKS5");
        assert_eq!(ProxyProtocol::Shadowsocks.name(), "Shadowsocks");
    }
}
