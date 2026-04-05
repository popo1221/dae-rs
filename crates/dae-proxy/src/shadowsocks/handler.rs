//! Shadowsocks handler implementation
//!
//! Implements the ss-local side connection handler.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, info};

use super::config::SsClientConfig;
use super::protocol::TargetAddress;
use crate::protocol::relay::relay_bidirectional;
use crate::protocol::unified_handler::{Handler, HandlerConfig};
use crate::protocol::ProtocolType;

/// Shadowsocks handler that implements the ss-local side
pub struct ShadowsocksHandler {
    config: SsClientConfig,
}

impl ShadowsocksHandler {
    /// Create a new Shadowsocks handler
    pub fn new(config: SsClientConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration
    #[allow(dead_code)]
    pub fn new_default() -> Self {
        Self {
            config: SsClientConfig::default(),
        }
    }

    /// Get the listen address
    #[allow(dead_code)]
    pub fn listen_addr(&self) -> std::net::SocketAddr {
        self.config.listen_addr
    }

    /// Handle a Shadowsocks connection
    pub async fn handle(self: Arc<Self>, mut client: TcpStream) -> std::io::Result<()> {
        let client_addr = client.peer_addr()?;

        // Read the Shadowsocks AEAD header
        // Format: [1 byte type][payload]
        // For AEAD: first packet contains target address encrypted
        let mut header_buf = vec![0u8; 1];
        client.read_exact(&mut header_buf).await?;

        // For AEAD, we need to read the length prefix and encrypted payload
        // Length prefix is typically 2 bytes for AEAD
        let mut len_buf = [0u8; 2];
        client.read_exact(&mut len_buf).await?;
        let payload_len = u16::from_be_bytes(len_buf) as usize;

        // Read encrypted payload (contains target address)
        let mut encrypted_payload = vec![0u8; payload_len];
        client.read_exact(&mut encrypted_payload).await?;

        // Parse target address from payload
        // In a real implementation, we would decrypt the payload first
        // For now, we try to parse assuming plaintext (for testing/non-encrypted mode)
        // or the payload contains the raw target address
        let (target_addr, target_port) = match TargetAddress::parse_from_aead(&encrypted_payload) {
            Some((addr, port)) => (addr, port),
            None => {
                // If parsing fails, assume this is encrypted and we need the key
                // For a full implementation, decryption would happen here
                error!("Failed to parse Shadowsocks target address");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid Shadowsocks AEAD payload",
                ));
            }
        };

        info!(
            "Shadowsocks TCP: {} -> {}:{}",
            client_addr, target_addr, target_port
        );

        // Connect to the Shadowsocks server
        let remote_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
        let timeout = self.config.tcp_timeout;

        let remote = match tokio::time::timeout(timeout, TcpStream::connect(&remote_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err(e);
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection to Shadowsocks server timed out",
                ));
            }
        };

        debug!("Connected to Shadowsocks server {}", remote_addr);

        // Relay data between client and remote
        self.relay(client, remote).await
    }

    /// Relay data between client and Shadowsocks server
    async fn relay(&self, client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
        relay_bidirectional(client, remote).await
    }

    /// Handle UDP traffic
    #[allow(dead_code)]
    pub async fn handle_udp(self: Arc<Self>, client: UdpSocket) -> std::io::Result<()> {
        // Maximum UDP packet size for Shadowsocks
        const MAX_UDP_SIZE: usize = 65535;
        let mut buf = vec![0u8; MAX_UDP_SIZE];

        loop {
            let (n, client_addr) = client.recv_from(&mut buf).await?;

            if n < 3 {
                continue;
            }

            // Parse Shadowsocks UDP packet
            let atyp = buf[0];
            let (target_addr, target_port, payload_offset) = match atyp {
                0x01 => {
                    // IPv4
                    if n < 7 {
                        continue;
                    }
                    let ip = IpAddr::V4(Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]));
                    let port = u16::from_be_bytes([buf[5], buf[6]]);
                    (TargetAddress::Ip(ip), port, 7)
                }
                0x03 => {
                    // Domain
                    if n < 4 {
                        continue;
                    }
                    let domain_len = buf[1] as usize;
                    if n < 4 + domain_len {
                        continue;
                    }
                    let domain =
                        String::from_utf8(buf[2..2 + domain_len].to_vec()).unwrap_or_default();
                    let port = u16::from_be_bytes([buf[2 + domain_len], buf[3 + domain_len]]);
                    (TargetAddress::Domain(domain, port), port, 4 + domain_len)
                }
                0x04 => {
                    // IPv6
                    if n < 18 {
                        continue;
                    }
                    let ip = IpAddr::V6(Ipv6Addr::new(
                        u16::from_be_bytes([buf[1], buf[2]]),
                        u16::from_be_bytes([buf[3], buf[4]]),
                        u16::from_be_bytes([buf[5], buf[6]]),
                        u16::from_be_bytes([buf[7], buf[8]]),
                        u16::from_be_bytes([buf[9], buf[10]]),
                        u16::from_be_bytes([buf[11], buf[12]]),
                        u16::from_be_bytes([buf[13], buf[14]]),
                        u16::from_be_bytes([buf[15], buf[16]]),
                    ));
                    let port = u16::from_be_bytes([buf[17], buf[18]]);
                    (TargetAddress::Ip(ip), port, 19)
                }
                _ => continue,
            };

            let payload = &buf[payload_offset..n];

            debug!(
                "Shadowsocks UDP: {} -> {}:{} ({} bytes)",
                client_addr,
                target_addr,
                target_port,
                payload.len()
            );

            // Forward to Shadowsocks server and back
            let server_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
            let server_socket = UdpSocket::bind("0.0.0.0:0").await?;
            server_socket.send_to(payload, &server_addr).await?;

            let mut response_buf = vec![0u8; MAX_UDP_SIZE];
            match tokio::time::timeout(
                self.config.udp_timeout,
                server_socket.recv_from(&mut response_buf),
            )
            .await
            {
                Ok(Ok((m, _))) => {
                    client.send_to(&response_buf[..m], &client_addr).await?;
                }
                _ => {
                    // Timeout or error, ignore
                }
            }
        }
    }
}

/// Implement HandlerConfig for SsClientConfig
impl HandlerConfig for SsClientConfig {}

/// Implement Handler trait for ShadowsocksHandler
///
/// This allows ShadowsocksHandler to be used through the unified Handler interface.
#[async_trait]
impl Handler for ShadowsocksHandler {
    type Config = SsClientConfig;

    fn name(&self) -> &'static str {
        "shadowsocks"
    }

    fn protocol(&self) -> ProtocolType {
        ProtocolType::Shadowsocks
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }

    async fn handle(self: Arc<Self>, stream: TcpStream) -> std::io::Result<()> {
        self.handle(stream).await
    }
}
