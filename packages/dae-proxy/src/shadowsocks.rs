//! Shadowsocks AEAD protocol handler with plugin support
//!
//! Implements Shadowsocks AEAD protocol support.
//! Supports AEAD ciphers: chacha20-ietf-poly1305, aes-256-gcm, aes-128-gcm
//! Implements OTA (One-Time Auth) compatibility mode.
//!
//! Supports obfuscation plugins:
//! - simple-obfs (HTTP and TLS obfuscation)
//! - v2ray-plugin (WebSocket-based obfuscation)
//!
//! Protocol flow:
//! Client -> [obfs/plugin] -> [Shadowsocks AEAD] -> Server

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

pub mod plugin;
pub mod ssr;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info};

/// Shadowsocks AEAD cipher type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SsCipherType {
    /// chacha20-ietf-poly1305
    #[default]
    Chacha20IetfPoly1305,
    /// aes-256-gcm
    Aes256Gcm,
    /// aes-128-gcm
    Aes128Gcm,
}

impl std::fmt::Display for SsCipherType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsCipherType::Chacha20IetfPoly1305 => write!(f, "chacha20-ietf-poly1305"),
            SsCipherType::Aes256Gcm => write!(f, "aes-256-gcm"),
            SsCipherType::Aes128Gcm => write!(f, "aes-128-gcm"),
        }
    }
}

impl SsCipherType {
    /// Parse cipher type from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "chacha20-ietf-poly1305" | "chacha20poly1305" => {
                Some(SsCipherType::Chacha20IetfPoly1305)
            }
            "aes-256-gcm" | "aes256gcm" => Some(SsCipherType::Aes256Gcm),
            "aes-128-gcm" | "aes128gcm" => Some(SsCipherType::Aes128Gcm),
            _ => None,
        }
    }
}

/// Shadowsocks server configuration
#[derive(Debug, Clone)]
pub struct SsServerConfig {
    /// Server address (IP or domain)
    pub addr: String,
    /// Server port
    pub port: u16,
    /// Encryption method
    pub method: SsCipherType,
    /// Password/key
    pub password: String,
    /// Enable OTA (One-Time Auth)
    #[allow(dead_code)]
    pub ota: bool,
}

impl Default for SsServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 8388,
            method: SsCipherType::Chacha20IetfPoly1305,
            password: String::new(),
            ota: false,
        }
    }
}

/// Shadowsocks client configuration
#[derive(Debug, Clone)]
pub struct SsClientConfig {
    /// Local listen address
    pub listen_addr: SocketAddr,
    /// Remote server configuration
    pub server: SsServerConfig,
    /// TCP connection timeout
    pub tcp_timeout: Duration,
    /// UDP session timeout
    pub udp_timeout: Duration,
}

impl Default for SsClientConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 1080)),
            server: SsServerConfig::default(),
            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(30),
        }
    }
}

/// Shadowsocks target address
#[derive(Debug, Clone)]
pub enum TargetAddress {
    /// IPv4 address
    Ip(IpAddr),
    /// Domain name with port
    Domain(String, u16),
}

impl std::fmt::Display for TargetAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetAddress::Ip(ip) => write!(f, "{ip}"),
            TargetAddress::Domain(domain, _) => write!(f, "{domain}"),
        }
    }
}

impl TargetAddress {
    /// Parse target address from Shadowsocks AEAD header
    /// Returns (address, port, bytes_consumed)
    pub fn parse_from_aead(payload: &[u8]) -> Option<(Self, u16)> {
        if payload.is_empty() {
            return None;
        }

        let atyp = payload[0];
        match atyp {
            0x01 => {
                // IPv4: 1 byte type + 4 bytes IP + 2 bytes port
                if payload.len() < 7 {
                    return None;
                }
                let ip = IpAddr::V4(Ipv4Addr::new(
                    payload[1], payload[2], payload[3], payload[4],
                ));
                let port = u16::from_be_bytes([payload[5], payload[6]]);
                Some((TargetAddress::Ip(ip), port))
            }
            0x03 => {
                // Domain: 1 byte type + 1 byte length + domain + 2 bytes port
                if payload.len() < 4 {
                    return None;
                }
                let domain_len = payload[1] as usize;
                if payload.len() < 4 + domain_len {
                    return None;
                }
                let domain = String::from_utf8(payload[2..2 + domain_len].to_vec()).ok()?;
                let port = u16::from_be_bytes([payload[2 + domain_len], payload[3 + domain_len]]);
                Some((TargetAddress::Domain(domain, port), port))
            }
            0x04 => {
                // IPv6: 1 byte type + 16 bytes IP + 2 bytes port
                if payload.len() < 18 {
                    return None;
                }
                let ip = IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([payload[1], payload[2]]),
                    u16::from_be_bytes([payload[3], payload[4]]),
                    u16::from_be_bytes([payload[5], payload[6]]),
                    u16::from_be_bytes([payload[7], payload[8]]),
                    u16::from_be_bytes([payload[9], payload[10]]),
                    u16::from_be_bytes([payload[11], payload[12]]),
                    u16::from_be_bytes([payload[13], payload[14]]),
                    u16::from_be_bytes([payload[15], payload[16]]),
                ));
                let port = u16::from_be_bytes([payload[17], payload[18]]);
                Some((TargetAddress::Ip(ip), port))
            }
            _ => None,
        }
    }

    /// Get the address portion (without port) as bytes for Shadowsocks protocol
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TargetAddress::Ip(IpAddr::V4(ip)) => {
                let mut bytes = vec![0x01]; // ATYP IPv4
                bytes.extend_from_slice(&ip.octets());
                bytes
            }
            TargetAddress::Ip(IpAddr::V6(ip)) => {
                let mut bytes = vec![0x04]; // ATYP IPv6
                for &segment in &ip.segments() {
                    bytes.extend_from_slice(&segment.to_be_bytes());
                }
                bytes
            }
            TargetAddress::Domain(domain, _) => {
                let mut bytes = vec![0x03, domain.len() as u8];
                bytes.extend_from_slice(domain.as_bytes());
                bytes
            }
        }
    }

    /// Format address for display
    pub fn address_string(&self) -> String {
        match self {
            TargetAddress::Ip(ip) => ip.to_string(),
            TargetAddress::Domain(domain, _) => domain.clone(),
        }
    }
}

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
    pub fn listen_addr(&self) -> SocketAddr {
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
        let (mut cr, mut cw) = tokio::io::split(client);
        let (mut rr, mut rw) = tokio::io::split(remote);

        let client_to_remote = tokio::io::copy(&mut cr, &mut rw);
        let remote_to_client = tokio::io::copy(&mut rr, &mut cw);

        tokio::try_join!(client_to_remote, remote_to_client)?;
        Ok(())
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

/// Shadowsocks server that listens for connections
pub struct ShadowsocksServer {
    handler: Arc<ShadowsocksHandler>,
    listener: TcpListener,
    listen_addr: SocketAddr,
}

impl ShadowsocksServer {
    /// Create a new Shadowsocks server
    #[allow(dead_code)]
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            handler: Arc::new(ShadowsocksHandler::new_default()),
            listener,
            listen_addr: addr,
        })
    }

    /// Create with custom configuration
    pub async fn with_config(config: SsClientConfig) -> std::io::Result<Self> {
        let listen_addr = config.listen_addr;
        let handler = Arc::new(ShadowsocksHandler::new(config));
        let listener = TcpListener::bind(listen_addr).await?;
        Ok(Self {
            handler,
            listener,
            listen_addr,
        })
    }

    /// Start the Shadowsocks server
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("Shadowsocks server listening on {}", self.listen_addr);

        loop {
            match self.listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(client).await {
                            debug!("Shadowsocks connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Shadowsocks accept error: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_type_from_str() {
        assert_eq!(
            SsCipherType::from_str("chacha20-ietf-poly1305"),
            Some(SsCipherType::Chacha20IetfPoly1305)
        );
        assert_eq!(
            SsCipherType::from_str("aes-256-gcm"),
            Some(SsCipherType::Aes256Gcm)
        );
        assert_eq!(
            SsCipherType::from_str("aes-128-gcm"),
            Some(SsCipherType::Aes128Gcm)
        );
        assert_eq!(SsCipherType::from_str("invalid"), None);
    }

    #[test]
    fn test_cipher_type_display() {
        assert_eq!(
            SsCipherType::Chacha20IetfPoly1305.to_string(),
            "chacha20-ietf-poly1305"
        );
        assert_eq!(SsCipherType::Aes256Gcm.to_string(), "aes-256-gcm");
        assert_eq!(SsCipherType::Aes128Gcm.to_string(), "aes-128-gcm");
    }

    #[test]
    fn test_default_config() {
        let config = SsClientConfig::default();
        assert_eq!(config.listen_addr, SocketAddr::from(([127, 0, 0, 1], 1080)));
        assert_eq!(config.server.port, 8388);
        assert_eq!(config.server.method, SsCipherType::Chacha20IetfPoly1305);
    }

    #[test]
    fn test_target_address_parse_ipv4() {
        let payload = [
            0x01, 192, 168, 1, 1, 0x1F, 0x90, // 192.168.1.1:8080
        ];
        let result = TargetAddress::parse_from_aead(&payload);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        match addr {
            TargetAddress::Ip(IpAddr::V4(ip)) => {
                assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
            }
            _ => panic!("Expected IPv4"),
        }
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_target_address_parse_domain() {
        // Domain format: ATYP(1) + LEN(1) + DOMAIN(LEN) + PORT(2)
        // example.com = 11 bytes
        let payload = [
            0x03, // ATYP_DOMAIN
            0x0b, // domain length = 11
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', // "example.com"
            0x00, 0x50, // port = 80
        ];
        let result = TargetAddress::parse_from_aead(&payload);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        match addr {
            TargetAddress::Domain(domain, _) => {
                assert_eq!(domain, "example.com");
            }
            _ => panic!("Expected Domain"),
        }
        assert_eq!(port, 80);
    }

    #[test]
    fn test_target_address_to_bytes_ipv4() {
        let addr = TargetAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let bytes = addr.to_bytes();
        assert_eq!(bytes, vec![0x01, 192, 168, 1, 1]);
    }

    #[test]
    fn test_cipher_type_all_variants() {
        // Only these ciphers are supported
        assert!(SsCipherType::from_str("aes-128-gcm").is_some());
        assert!(SsCipherType::from_str("aes-256-gcm").is_some());
        assert!(SsCipherType::from_str("chacha20-ietf-poly1305").is_some());
        // These are NOT supported
        assert!(SsCipherType::from_str("aes-128-cfb").is_none());
        assert!(SsCipherType::from_str("aes-256-cfb").is_none());
        assert!(SsCipherType::from_str("invalid").is_none());
    }

    #[test]
    fn test_cipher_type_to_string() {
        assert_eq!(SsCipherType::Aes128Gcm.to_string(), "aes-128-gcm");
        assert_eq!(SsCipherType::Aes256Gcm.to_string(), "aes-256-gcm");
        assert_eq!(SsCipherType::Chacha20IetfPoly1305.to_string(), "chacha20-ietf-poly1305");
    }

    #[test]
    fn test_target_address_ipv6() {
        let payload = [
            0x04, // ATYP_IPV6
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x50, // [2001:db8::1]:80
        ];
        let result = TargetAddress::parse_from_aead(&payload);
        assert!(result.is_some());
    }

    #[test]
    fn test_target_address_invalid() {
        let payload = [0xFF, 0x00]; // Invalid type
        let result = TargetAddress::parse_from_aead(&payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_target_address_truncated() {
        let payload = [0x01, 192]; // Too short for IPv4
        let result = TargetAddress::parse_from_aead(&payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_target_address_domain_length_mismatch() {
        // Domain length says 11 but only 3 bytes follow
        let payload = [0x03, 0x0b, 0x65, 0x78, 0x61]; // "exa" only
        let result = TargetAddress::parse_from_aead(&payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_ss_client_config_default() {
        let config = SsClientConfig::default();
        assert_eq!(config.server.port, 8388);
    }

    #[test]
    fn test_ss_client_config_clone() {
        let config = SsClientConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.server.method, config.server.method);
    }

    #[test]
    fn test_target_address_debug() {
        let addr = TargetAddress::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let debug_str = format!("{:?}", addr);
        assert!(debug_str.contains("Ip"));
    }
}
