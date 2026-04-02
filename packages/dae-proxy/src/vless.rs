//! VLESS protocol handler (Xtls)
//!
//! Implements VLESS protocol support for dae-rs.
//! VLESS is a stateless VPN protocol that uses TLS/XTLS transport.
//!
//! Protocol spec: https://xtls.github.io/
//!
//! Protocol flow:
//! Client -> dae-rs (VLESS client) -> remote VLESS server -> target

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info};

/// VLESS protocol version
const VLESS_VERSION: u8 = 0x01;

/// VLESS command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    /// TCP connection
    Tcp = 0x01,
    /// UDP (mux)
    Udp = 0x02,
    /// XTLS Vision
    XtlsVision = 0x03,
}

/// VLESS address type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessAddressType {
    /// IPv4
    Ipv4 = 0x01,
    /// Domain
    Domain = 0x02,
    /// IPv6
    Ipv6 = 0x03,
}

/// VLESS server configuration
#[derive(Debug, Clone)]
pub struct VlessServerConfig {
    /// Server address (IP or domain)
    pub addr: String,
    /// Server port
    pub port: u16,
    /// UUID for authentication
    pub uuid: String,
    /// TLS settings
    pub tls: VlessTlsConfig,
}

impl Default for VlessServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 443,
            uuid: String::new(),
            tls: VlessTlsConfig::default(),
        }
    }
}

/// VLESS TLS configuration
#[derive(Debug, Clone)]
pub struct VlessTlsConfig {
    /// Enable TLS
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

impl Default for VlessTlsConfig {
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

/// VLESS client configuration
#[derive(Debug, Clone)]
pub struct VlessClientConfig {
    /// Local listen address
    pub listen_addr: SocketAddr,
    /// Remote server configuration
    pub server: VlessServerConfig,
    /// TCP connection timeout
    pub tcp_timeout: Duration,
    /// UDP session timeout
    pub udp_timeout: Duration,
}

impl Default for VlessClientConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 1080)),
            server: VlessServerConfig::default(),
            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(30),
        }
    }
}

/// VLESS target address
#[derive(Debug, Clone)]
pub enum VlessTargetAddress {
    /// IPv4 address
    Ipv4(IpAddr),
    /// Domain name with port
    Domain(String, u16),
    /// IPv6 address
    Ipv6(IpAddr),
}

impl std::fmt::Display for VlessTargetAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VlessTargetAddress::Ipv4(ip) => write!(f, "{ip}"),
            VlessTargetAddress::Domain(domain, _) => write!(f, "{domain}"),
            VlessTargetAddress::Ipv6(ip) => write!(f, "{ip}"),
        }
    }
}

impl VlessTargetAddress {
    /// Parse target address from VLESS header bytes
    /// Returns (address, port, bytes_consumed)
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
                let ip = IpAddr::V4(Ipv4Addr::new(
                    payload[1], payload[2], payload[3], payload[4],
                ));
                let port = u16::from_be_bytes([payload[5], payload[6]]);
                Some((VlessTargetAddress::Ipv4(ip), port))
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
                let domain = String::from_utf8(payload[2..2 + domain_len].to_vec()).ok()?;
                let port = u16::from_be_bytes([payload[2 + domain_len], payload[3 + domain_len]]);
                Some((VlessTargetAddress::Domain(domain, port), port))
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
                Some((VlessTargetAddress::Ipv6(ip), port))
            }
            _ => None,
        }
    }

    /// Convert address to bytes for VLESS protocol
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            VlessTargetAddress::Ipv4(ip) => {
                let mut bytes = vec![0x01]; // ATYP IPv4
                if let IpAddr::V4(ipv4) = ip {
                    bytes.extend_from_slice(&ipv4.octets());
                }
                bytes
            }
            VlessTargetAddress::Ipv6(ip) => {
                let mut bytes = vec![0x03]; // ATYP IPv6
                if let IpAddr::V6(ipv6) = ip {
                    for &segment in &ipv6.segments() {
                        bytes.extend_from_slice(&segment.to_be_bytes());
                    }
                }
                bytes
            }
            VlessTargetAddress::Domain(domain, _) => {
                let mut bytes = vec![0x02, domain.len() as u8];
                bytes.extend_from_slice(domain.as_bytes());
                bytes
            }
        }
    }
}

/// VLESS handler that implements the client-side protocol
pub struct VlessHandler {
    config: VlessClientConfig,
}

impl VlessHandler {
    /// Create a new VLESS handler
    pub fn new(config: VlessClientConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration
    #[allow(dead_code)]
    pub fn new_default() -> Self {
        Self {
            config: VlessClientConfig::default(),
        }
    }

    /// Get the listen address
    #[allow(dead_code)]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    /// Validate UUID
    pub fn validate_uuid(uuid: &[u8]) -> bool {
        // UUID must be 16 bytes (128 bits)
        uuid.len() == 16
    }

    /// Handle a VLESS TCP connection
    pub async fn handle(self: Arc<Self>, mut client: TcpStream) -> std::io::Result<()> {
        let client_addr = client.peer_addr()?;

        // Read VLESS header
        // VLESS TCP request format:
        // [1 byte version][16 bytes UUID][1 byte version padding][1 byte command]
        // [4 bytes port][1 byte address type][address][16 bytes auth]
        let mut header_buf = vec![0u8; 38]; // Minimum header size
        client.read_exact(&mut header_buf).await?;

        // Validate version
        if header_buf[0] != VLESS_VERSION {
            error!("Invalid VLESS version: {}", header_buf[0]);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid VLESS version",
            ));
        }

        // Extract UUID (bytes 1-16)
        let uuid = &header_buf[1..17];
        if !Self::validate_uuid(uuid) {
            error!("Invalid UUID length");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid UUID",
            ));
        }

        // Extract command (byte 18)
        let command = header_buf[18];
        let cmd = match command {
            0x01 => VlessCommand::Tcp,
            0x02 => VlessCommand::Udp,
            0x03 => VlessCommand::XtlsVision,
            _ => {
                error!("Unknown VLESS command: {}", command);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unknown VLESS command",
                ));
            }
        };

        debug!("VLESS TCP: {} command={:?}", client_addr, cmd);

        // For now, handle TCP command
        match cmd {
            VlessCommand::Tcp => {
                // Read additional header: port(4) + atyp(1) + addr + auth(16)
                let mut addl_buf = vec![0u8; 64];
                client.read_exact(&mut addl_buf).await?;

                // Parse address
                let atyp = addl_buf[4];
                let address = match atyp {
                    0x01 => {
                        // IPv4
                        if addl_buf.len() < 10 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "buffer too small",
                            ));
                        }
                        let ip = IpAddr::V4(Ipv4Addr::new(
                            addl_buf[5],
                            addl_buf[6],
                            addl_buf[7],
                            addl_buf[8],
                        ));
                        let _port = u16::from_be_bytes([addl_buf[9], addl_buf[10]]);
                        VlessTargetAddress::Ipv4(ip)
                    }
                    0x02 => {
                        // Domain
                        if addl_buf.len() < 6 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "buffer too small",
                            ));
                        }
                        let domain_len = addl_buf[5] as usize;
                        if addl_buf.len() < 6 + domain_len + 2 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "buffer too small",
                            ));
                        }
                        let domain = String::from_utf8(addl_buf[6..6 + domain_len].to_vec())
                            .map_err(|_| {
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "invalid domain",
                                )
                            })?;
                        let port = u16::from_be_bytes([
                            addl_buf[6 + domain_len],
                            addl_buf[6 + domain_len + 1],
                        ]);
                        VlessTargetAddress::Domain(domain, port)
                    }
                    0x03 => {
                        // IPv6
                        if addl_buf.len() < 22 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "buffer too small",
                            ));
                        }
                        let ip = IpAddr::V6(Ipv6Addr::new(
                            u16::from_be_bytes([addl_buf[5], addl_buf[6]]),
                            u16::from_be_bytes([addl_buf[7], addl_buf[8]]),
                            u16::from_be_bytes([addl_buf[9], addl_buf[10]]),
                            u16::from_be_bytes([addl_buf[11], addl_buf[12]]),
                            u16::from_be_bytes([addl_buf[13], addl_buf[14]]),
                            u16::from_be_bytes([addl_buf[15], addl_buf[16]]),
                            u16::from_be_bytes([addl_buf[17], addl_buf[18]]),
                            u16::from_be_bytes([addl_buf[19], addl_buf[20]]),
                        ));
                        let _port = u16::from_be_bytes([addl_buf[21], addl_buf[22]]);
                        VlessTargetAddress::Ipv6(ip)
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid address type",
                        ));
                    }
                };

                info!(
                    "VLESS TCP: {} -> {} (via {}:{})",
                    client_addr, address, self.config.server.addr, self.config.server.port
                );

                // Connect to VLESS server
                let remote_addr =
                    format!("{}:{}", self.config.server.addr, self.config.server.port);
                let timeout = self.config.tcp_timeout;

                let remote =
                    match tokio::time::timeout(timeout, TcpStream::connect(&remote_addr)).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => return Err(e),
                        Err(_) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "connection to VLESS server timed out",
                            ));
                        }
                    };

                debug!("Connected to VLESS server {}", remote_addr);

                // Relay data between client and remote
                self.relay(client, remote).await
            }
            VlessCommand::Udp => {
                // UDP handling would go here
                error!("VLESS UDP not fully implemented");
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "VLESS UDP not implemented",
                ))
            }
            VlessCommand::XtlsVision => {
                // XTLS Vision handling would go here
                error!("VLESS XTLS Vision not fully implemented");
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "VLESS XTLS Vision not implemented",
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

            // Parse VLESS UDP header
            let (target_addr, target_port, payload_offset) =
                match VlessTargetAddress::parse_from_bytes(&buf) {
                    Some((addr, port)) => (addr, port, 0), // Placeholder for actual offset
                    None => continue,
                };

            let payload = &buf[payload_offset..n];

            debug!(
                "VLESS UDP: {} -> {}:{} ({} bytes)",
                client_addr,
                target_addr,
                target_port,
                payload.len()
            );

            // Forward to VLESS server and back
            let server_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
            let server_socket = UdpSocket::bind("0.0.0.0:0").await?;
            server_socket.send_to(payload, &server_addr).await?;

            let mut response_buf = vec![0u8; MAX_UDP_SIZE];
            if let Ok(Ok((m, _))) = tokio::time::timeout(
                self.config.udp_timeout,
                server_socket.recv_from(&mut response_buf),
            )
            .await
            {
                client.send_to(&response_buf[..m], &client_addr).await?;
            }
        }
    }
}

/// VLESS server that listens for connections
pub struct VlessServer {
    handler: Arc<VlessHandler>,
    listener: TcpListener,
    listen_addr: SocketAddr,
}

impl VlessServer {
    /// Create a new VLESS server
    #[allow(dead_code)]
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            handler: Arc::new(VlessHandler::new_default()),
            listener,
            listen_addr: addr,
        })
    }

    /// Create with custom configuration
    pub async fn with_config(config: VlessClientConfig) -> std::io::Result<Self> {
        let listen_addr = config.listen_addr;
        let handler = Arc::new(VlessHandler::new(config));
        let listener = TcpListener::bind(listen_addr).await?;
        Ok(Self {
            handler,
            listener,
            listen_addr,
        })
    }

    /// Start the VLESS server
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("VLESS server listening on {}", self.listen_addr);

        loop {
            match self.listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(client).await {
                            debug!("VLESS connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("VLESS accept error: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_uuid() {
        // Valid 16-byte UUID
        let valid_uuid = [0u8; 16];
        assert!(VlessHandler::validate_uuid(&valid_uuid));

        // Invalid lengths
        assert!(!VlessHandler::validate_uuid(&[]));
        assert!(!VlessHandler::validate_uuid(&[0u8; 15]));
        assert!(!VlessHandler::validate_uuid(&[0u8; 17]));
    }

    #[test]
    fn test_default_config() {
        let config = VlessClientConfig::default();
        assert_eq!(config.listen_addr, SocketAddr::from(([127, 0, 0, 1], 1080)));
        assert_eq!(config.server.port, 443);
    }

    #[test]
    fn test_target_address_parse_ipv4() {
        let payload = [
            0x01, 192, 168, 1, 1, 0x1F, 0x90, // 192.168.1.1:8080
        ];
        let result = VlessTargetAddress::parse_from_bytes(&payload);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        match addr {
            VlessTargetAddress::Ipv4(ip) => {
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
            0x02, // ATYP_DOMAIN
            0x0b, // domain length = 11
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', // "example.com"
            0x00, 0x50, // port = 80
        ];
        let result = VlessTargetAddress::parse_from_bytes(&payload);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        match addr {
            VlessTargetAddress::Domain(domain, _) => {
                assert_eq!(domain, "example.com");
            }
            _ => panic!("Expected Domain"),
        }
        assert_eq!(port, 80);
    }

    #[test]
    fn test_target_address_to_bytes_ipv4() {
        let addr = VlessTargetAddress::Ipv4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let bytes = addr.to_bytes();
        assert_eq!(bytes, vec![0x01, 192, 168, 1, 1]);
    }
}
