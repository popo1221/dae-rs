//! Trojan protocol handler
//!
//! Implements Trojan protocol support for dae-rs.
//! Trojan is a VPN protocol that mimics HTTPS traffic.
//!
//! Protocol reference: https://trojan-gfw.github.io/
//!
//! Protocol flow:
//! Client -> dae-rs (Trojan client) -> remote Trojan server -> target

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info};

/// Trojan protocol command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanCommand {
    /// TCP connection
    Proxy = 0x01,
    /// UDP (Trojan-Go style)
    UdpAssociate = 0x02,
}

/// Trojan address type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanAddressType {
    /// IPv4
    Ipv4 = 0x01,
    /// Domain
    Domain = 0x02,
    /// IPv6
    Ipv6 = 0x03,
}

/// Trojan server configuration
#[derive(Debug, Clone)]
pub struct TrojanServerConfig {
    /// Server address (IP or domain)
    pub addr: String,
    /// Server port
    pub port: u16,
    /// Password for authentication
    pub password: String,
    /// TLS settings
    pub tls: TrojanTlsConfig,
}

impl Default for TrojanServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 443,
            password: String::new(),
            tls: TrojanTlsConfig::default(),
        }
    }
}

/// Trojan TLS configuration
#[derive(Debug, Clone)]
pub struct TrojanTlsConfig {
    /// Enable TLS (default: true)
    pub enabled: bool,
    /// TLS version (tls1.2, tls1.3)
    pub version: String,
    /// ALPN protocols
    pub alpn: Vec<String>,
    /// Server name for SNI
    pub server_name: Option<String>,
    /// Certificate path (for incoming TLS)
    pub cert_file: Option<String>,
    /// Private key path (for incoming TLS)
    pub key_file: Option<String>,
    /// Insecure skip verify (for outgoing TLS)
    pub insecure: bool,
}

impl Default for TrojanTlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            version: "1.3".to_string(),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            server_name: None,
            cert_file: None,
            key_file: None,
            insecure: false,
        }
    }
}

/// Trojan client configuration
#[derive(Debug, Clone)]
pub struct TrojanClientConfig {
    /// Local listen address
    pub listen_addr: SocketAddr,
    /// Remote server configuration
    pub server: TrojanServerConfig,
    /// TCP connection timeout
    pub tcp_timeout: Duration,
    /// UDP session timeout
    pub udp_timeout: Duration,
}

impl Default for TrojanClientConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 1080)),
            server: TrojanServerConfig::default(),
            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(30),
        }
    }
}

/// Trojan target address
#[derive(Debug, Clone)]
pub enum TrojanTargetAddress {
    /// IPv4 address
    Ipv4(IpAddr),
    /// Domain name with port
    Domain(String, u16),
    /// IPv6 address
    Ipv6(IpAddr),
}

impl std::fmt::Display for TrojanTargetAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrojanTargetAddress::Ipv4(ip) => write!(f, "{}", ip),
            TrojanTargetAddress::Domain(domain, _) => write!(f, "{}", domain),
            TrojanTargetAddress::Ipv6(ip) => write!(f, "{}", ip),
        }
    }
}

impl TrojanTargetAddress {
    /// Parse target address from Trojan header bytes
    pub fn parse_from_bytes(payload: &[u8]) -> Option<(Self, u16)> {
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
                let ip = IpAddr::V4(Ipv4Addr::new(payload[1], payload[2], payload[3], payload[4]));
                let port = u16::from_be_bytes([payload[5], payload[6]]);
                Some((TrojanTargetAddress::Ipv4(ip), port))
            }
            0x02 => {
                // Domain: 1 byte type + 1 byte length + domain + 2 bytes port
                if payload.len() < 4 {
                    return None;
                }
                let domain_len = payload[1] as usize;
                if payload.len() < 4 + domain_len {
                    return None;
                }
                let domain = String::from_utf8(payload[2..2+domain_len].to_vec()).ok()?;
                let port = u16::from_be_bytes([payload[2+domain_len], payload[3+domain_len]]);
                Some((TrojanTargetAddress::Domain(domain, port), port))
            }
            0x03 => {
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
                Some((TrojanTargetAddress::Ipv6(ip), port))
            }
            _ => None,
        }
    }

    /// Convert address to bytes for Trojan protocol
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TrojanTargetAddress::Ipv4(ip) => {
                let mut bytes = vec![0x01]; // ATYP IPv4
                if let IpAddr::V4(ipv4) = ip {
                    bytes.extend_from_slice(&ipv4.octets());
                }
                bytes
            }
            TrojanTargetAddress::Ipv6(ip) => {
                let mut bytes = vec![0x03]; // ATYP IPv6
                if let IpAddr::V6(ipv6) = ip {
                    for &segment in &ipv6.segments() {
                        bytes.extend_from_slice(&segment.to_be_bytes());
                    }
                }
                bytes
            }
            TrojanTargetAddress::Domain(domain, _) => {
                let mut bytes = vec![0x02, domain.len() as u8];
                bytes.extend_from_slice(domain.as_bytes());
                bytes
            }
        }
    }
}

/// Trojan handler that implements the client-side protocol
pub struct TrojanHandler {
    config: TrojanClientConfig,
    /// Multiple backends for failover
    backends: Vec<TrojanServerConfig>,
    /// Current backend index for round-robin
    current_index: std::sync::atomic::AtomicUsize,
}

impl TrojanHandler {
    /// Create a new Trojan handler with single backend
    pub fn new(config: TrojanClientConfig) -> Self {
        Self {
            backends: vec![config.server.clone()],
            current_index: std::sync::atomic::AtomicUsize::new(0),
            config,
        }
    }

    /// Create a new Trojan handler with multiple backends
    pub fn with_backends(config: TrojanClientConfig, backends: Vec<TrojanServerConfig>) -> Self {
        Self {
            backends: if backends.is_empty() {
                vec![config.server.clone()]
            } else {
                backends
            },
            current_index: std::sync::atomic::AtomicUsize::new(0),
            config,
        }
    }

    /// Create with default configuration
    #[allow(dead_code)]
    pub fn new_default() -> Self {
        Self {
            config: TrojanClientConfig::default(),
            backends: vec![TrojanServerConfig::default()],
            current_index: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Get the next backend using round-robin
    fn next_backend(&self) -> &TrojanServerConfig {
        let idx = self.current_index.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.backends.len();
        &self.backends[idx]
    }

    /// Get all backends
    #[allow(dead_code)]
    pub fn get_backends(&self) -> &[TrojanServerConfig] {
        &self.backends
    }

    /// Get the number of configured backends
    #[allow(dead_code)]
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    /// Get the listen address
    #[allow(dead_code)]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    /// Validate password
    pub fn validate_password(&self, password: &str) -> bool {
        // Simple constant-time comparison would be better in production
        self.config.server.password == password
    }

    /// Generate CRLF for Trojan protocol
    const CRLF: &'static [u8] = b"\r\n";

    /// Handle a Trojan TCP connection
    pub async fn handle(self: Arc<Self>, mut client: TcpStream) -> std::io::Result<()> {
        let client_addr = client.peer_addr()?;

        // Trojan protocol:
        // After TLS handshake, client sends:
        // [password (56 bytes)][0x0D, 0x0A]  <- CRLF
        // [command (1 byte)][address type (1 byte)][address][port (2 bytes)][0x0D, 0x0A]

        // Read password (56 bytes)
        let mut password_buf = vec![0u8; 56];
        client.read_exact(&mut password_buf).await?;

        // Read CRLF (2 bytes)
        let mut crlf_buf = [0u8; 2];
        client.read_exact(&mut crlf_buf).await?;
        if &crlf_buf != Self::CRLF {
            error!("Invalid Trojan header: missing CRLF after password");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Trojan header"
            ));
        }

        // Read command and address
        let mut cmd_buf = [0u8; 1];
        client.read_exact(&mut cmd_buf).await?;
        let command = cmd_buf[0];

        let cmd = match command {
            0x01 => TrojanCommand::Proxy,
            0x02 => TrojanCommand::UdpAssociate,
            _ => {
                error!("Unknown Trojan command: {}", command);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unknown Trojan command"
                ));
            }
        };

        debug!("Trojan TCP: {} command={:?}", client_addr, cmd);

        match cmd {
            TrojanCommand::Proxy => {
                // Read address type
                let mut atyp_buf = [0u8; 1];
                client.read_exact(&mut atyp_buf).await?;
                let atyp = atyp_buf[0];

                // Read address based on type
                let address = match atyp {
                    0x01 => {
                        // IPv4 (4 bytes)
                        let mut ip_buf = [0u8; 4];
                        client.read_exact(&mut ip_buf).await?;
                        TrojanTargetAddress::Ipv4(IpAddr::V4(Ipv4Addr::new(
                            ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3]
                        )))
                    }
                    0x02 => {
                        // Domain (1 byte length + domain)
                        let mut len_buf = [0u8; 1];
                        client.read_exact(&mut len_buf).await?;
                        let domain_len = len_buf[0] as usize;
                        let mut domain_buf = vec![0u8; domain_len];
                        client.read_exact(&mut domain_buf).await?;
                        let domain = String::from_utf8(domain_buf)
                            .map_err(|_| std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid domain in Trojan header"
                            ))?;
                        TrojanTargetAddress::Domain(domain, 0) // Port will be read next
                    }
                    0x03 => {
                        // IPv6 (16 bytes)
                        let mut ip_buf = [0u8; 16];
                        client.read_exact(&mut ip_buf).await?;
                        TrojanTargetAddress::Ipv6(IpAddr::V6(Ipv6Addr::new(
                            u16::from_be_bytes([ip_buf[0], ip_buf[1]]),
                            u16::from_be_bytes([ip_buf[2], ip_buf[3]]),
                            u16::from_be_bytes([ip_buf[4], ip_buf[5]]),
                            u16::from_be_bytes([ip_buf[6], ip_buf[7]]),
                            u16::from_be_bytes([ip_buf[8], ip_buf[9]]),
                            u16::from_be_bytes([ip_buf[10], ip_buf[11]]),
                            u16::from_be_bytes([ip_buf[12], ip_buf[13]]),
                            u16::from_be_bytes([ip_buf[14], ip_buf[15]]),
                        )))
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid address type in Trojan header"
                        ));
                    }
                };

                // Read port (2 bytes)
                let mut port_buf = [0u8; 2];
                client.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);

                // Read final CRLF (2 bytes)
                let mut crlf_buf = [0u8; 2];
                client.read_exact(&mut crlf_buf).await?;
                if &crlf_buf != Self::CRLF {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid Trojan header: missing CRLF after address"
                    ));
                }

                let address_str = match &address {
                    TrojanTargetAddress::Domain(d, _) => format!("{}:{}", d, port),
                    _ => format!("{}:{}", address, port),
                };

                // Select backend using round-robin
                let backend = self.next_backend();
                let remote_addr = format!("{}:{}", backend.addr, backend.port);
                let timeout = self.config.tcp_timeout;

                info!("Trojan TCP: {} -> {} (via {}:{}, {} backends available)",
                    client_addr, address_str, backend.addr, backend.port, self.backend_count());

                // Connect to the selected backend
                let remote = match tokio::time::timeout(timeout, TcpStream::connect(&remote_addr)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        error!("Failed to connect to Trojan backend {}:{}: {}", backend.addr, backend.port, e);
                        return Err(e);
                    }
                    Err(_) => {
                        error!("Timeout connecting to Trojan backend {}:{}", backend.addr, backend.port);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "connection to Trojan server timed out"
                        ));
                    }
                };

                debug!("Connected to Trojan server {}", remote_addr);

                // Relay data between client and remote
                self.relay(client, remote).await
            }
            TrojanCommand::UdpAssociate => {
                // UDP associate handling
                error!("Trojan UDP Associate not fully implemented");
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Trojan UDP Associate not implemented"
                ))
            }
        }
    }

    /// Relay data between client and remote
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
        const MAX_UDP_SIZE: usize = 65535;
        let mut buf = vec![0u8; MAX_UDP_SIZE];

        loop {
            let (n, client_addr) = client.recv_from(&mut buf).await?;

            if n < 5 {
                continue;
            }

            // Parse Trojan UDP header
            let (target_addr, target_port, payload_offset) =
                match TrojanTargetAddress::parse_from_bytes(&buf) {
                    Some((addr, port)) => (addr, port, 0),
                    None => continue,
                };

            let payload = &buf[payload_offset..n];

            debug!("Trojan UDP: {} -> {}:{} ({} bytes)",
                client_addr, target_addr, target_port, payload.len());

            // Forward to Trojan server and back
            let server_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
            let server_socket = UdpSocket::bind("0.0.0.0:0").await?;
            server_socket.send_to(payload, &server_addr).await?;

            let mut response_buf = vec![0u8; MAX_UDP_SIZE];
            match tokio::time::timeout(self.config.udp_timeout, server_socket.recv_from(&mut response_buf)).await {
                Ok(Ok((m, _))) => {
                    client.send_to(&response_buf[..m], &client_addr).await?;
                }
                _ => {}
            }
        }
    }
}

/// Trojan server that listens for connections
pub struct TrojanServer {
    handler: Arc<TrojanHandler>,
    listener: TcpListener,
    listen_addr: SocketAddr,
}

impl TrojanServer {
    /// Create a new Trojan server
    #[allow(dead_code)]
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            handler: Arc::new(TrojanHandler::new_default()),
            listener,
            listen_addr: addr,
        })
    }

    /// Create with custom configuration
    pub async fn with_config(config: TrojanClientConfig) -> std::io::Result<Self> {
        let listen_addr = config.listen_addr;
        let handler = Arc::new(TrojanHandler::new(config));
        let listener = TcpListener::bind(listen_addr).await?;
        Ok(Self {
            handler,
            listener,
            listen_addr,
        })
    }

    /// Create with multiple backends for failover
    #[allow(dead_code)]
    pub async fn with_backends(config: TrojanClientConfig, backends: Vec<TrojanServerConfig>) -> std::io::Result<Self> {
        let listen_addr = config.listen_addr;
        let handler = Arc::new(TrojanHandler::with_backends(config, backends));
        let listener = TcpListener::bind(listen_addr).await?;
        info!("Trojan server created with {} backends", handler.backend_count());
        Ok(Self {
            handler,
            listener,
            listen_addr,
        })
    }

    /// Start the Trojan server
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("Trojan server listening on {}", self.listen_addr);

        loop {
            match self.listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(client).await {
                            debug!("Trojan connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Trojan accept error: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TrojanClientConfig::default();
        assert_eq!(config.listen_addr, SocketAddr::from(([127, 0, 0, 1], 1080)));
        assert_eq!(config.server.port, 443);
    }

    #[test]
    fn test_target_address_parse_ipv4() {
        let payload = [
            0x01, 192, 168, 1, 1, 0x1F, 0x90  // 192.168.1.1:8080
        ];
        let result = TrojanTargetAddress::parse_from_bytes(&payload);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        match addr {
            TrojanTargetAddress::Ipv4(ip) => {
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            }
            _ => panic!("Expected IPv4"),
        }
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_target_address_parse_domain() {
        // Domain format: ATYP(1) + LEN(1) + DOMAIN(LEN) + PORT(2)
        let payload = [
            0x02,       // ATYP_DOMAIN
            0x0b,       // domain length = 11
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',  // "example.com"
            0x00, 0x50  // port = 80
        ];
        let result = TrojanTargetAddress::parse_from_bytes(&payload);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        match addr {
            TrojanTargetAddress::Domain(domain, _) => {
                assert_eq!(domain, "example.com");
            }
            _ => panic!("Expected Domain"),
        }
        assert_eq!(port, 80);
    }

    #[test]
    fn test_target_address_to_bytes_ipv4() {
        let addr = TrojanTargetAddress::Ipv4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let bytes = addr.to_bytes();
        assert_eq!(bytes, vec![0x01, 192, 168, 1, 1]);
    }

    #[test]
    fn test_command_is_proxy() {
        assert_eq!(TrojanCommand::Proxy as u8, 0x01);
        assert_eq!(TrojanCommand::UdpAssociate as u8, 0x02);
    }
}
