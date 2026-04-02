//! VLESS protocol handler with Reality support
//!
//! Implements VLESS protocol with XTLS Reality for dae-rs.
//! VLESS is a stateless VPN protocol that uses TLS/XTLS transport.
//!
//! Protocol spec: https://xtls.github.io/
//! Reality spec: https://github.com/XTLS/Xray-core/discussions/716
//!
//! # VLESS Reality Vision
//!
//! VLESS Reality Vision is a TLS obfuscation protocol that:
//! - Uses X25519 key exchange for perfect forward secrecy
//! - Masks traffic as normal HTTPS to bypass DPI
//! - Works with any TLS-terminated server (nginx, caddy, etc.)
//!
//! # Protocol Flow (Reality Vision)
//!
//! Client -> [X25519 KeyGen] -> [Build Request] -> [TLS ClientHello with Chrome]
//! -> Server -> [Verify and respond] -> [Establish tunnel]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use std::io::ErrorKind;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

use crate::protocol::{Handler, HandlerConfig};

/// VLESS protocol version
const VLESS_VERSION: u8 = 0x01;

/// VLESS header size constants
const VLESS_HEADER_MIN_SIZE: usize = 38; // v1 + uuid(16) + ver(1) + cmd(1) + port(4) + atyp(1) + iv(16)
const VLESS_REQUEST_HEADER_SIZE: usize = 22; // port(4) + atyp(1) + addr + iv(16)

/// VLESS command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    /// TCP connection
    Tcp = 0x01,
    /// UDP (mux)
    Udp = 0x02,
    /// XTLS Vision (Reality)
    XtlsVision = 0x03,
}

impl VlessCommand {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(VlessCommand::Tcp),
            0x02 => Some(VlessCommand::Udp),
            0x03 => Some(VlessCommand::XtlsVision),
            _ => None,
        }
    }
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

impl VlessAddressType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(VlessAddressType::Ipv4),
            0x02 => Some(VlessAddressType::Domain),
            0x03 => Some(VlessAddressType::Ipv6),
            _ => None,
        }
    }
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
    /// Reality settings (for Reality Vision mode)
    pub reality: Option<VlessRealityConfig>,
}

impl Default for VlessServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 443,
            uuid: String::new(),
            tls: VlessTlsConfig::default(),
            reality: None,
        }
    }
}

/// VLESS Reality configuration (VLESS XTLS Vision)
#[derive(Debug, Clone)]
pub struct VlessRealityConfig {
    /// X25519 private key (32 bytes)
    pub private_key: Vec<u8>,
    /// X25519 public key (32 bytes) - server's public key
    pub public_key: Vec<u8>,
    /// Short ID (8 bytes, can be empty)
    pub short_id: Vec<u8>,
    /// Destination server name (SNI to mask as)
    pub destination: String,
    /// Flow type (usually "vision" for Reality Vision)
    pub flow: String,
}

impl VlessRealityConfig {
    /// Create a new Reality config
    pub fn new(private_key: &[u8], public_key: &[u8], short_id: &[u8], destination: &str) -> Self {
        Self {
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
            short_id: short_id.to_vec(),
            destination: destination.to_string(),
            flow: "vision".to_string(),
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

impl HandlerConfig for VlessClientConfig {}

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
                if payload.len() < 19 {
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

/// VLESS handler that implements the Handler trait
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

    /// Handle a VLESS connection (implements Handler trait)
    pub async fn handle_vless(self: Arc<Self>, mut client: TcpStream) -> std::io::Result<()> {
        let client_addr = client.peer_addr()?;

        // Read VLESS header
        let mut header_buf = vec![0u8; VLESS_HEADER_MIN_SIZE];
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

        // Verify UUID matches config
        let expected_uuid = self.config.server.uuid.as_bytes();
        if expected_uuid.len() == 16 && uuid != expected_uuid {
            error!("UUID mismatch");
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid UUID",
            ));
        }

        // Extract command (byte 18)
        let command = header_buf[18];
        let cmd = VlessCommand::from_u8(command).ok_or_else(|| {
            error!("Unknown VLESS command: {}", command);
            std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown VLESS command")
        })?;

        debug!("VLESS TCP: {} command={:?}", client_addr, cmd);

        match cmd {
            VlessCommand::Tcp => self.handle_tcp(client, &header_buf).await,
            VlessCommand::Udp => {
                error!("VLESS UDP not fully implemented");
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "VLESS UDP not implemented",
                ))
            }
            VlessCommand::XtlsVision => {
                // Reality Vision mode
                self.handle_reality_vision(client, &header_buf).await
            }
        }
    }

    /// Handle VLESS TCP connection
    async fn handle_tcp(
        self: &Arc<Self>,
        mut client: TcpStream,
        header_buf: &[u8],
    ) -> std::io::Result<()> {
        // Read additional header: port(4) + atyp(1) + addr + iv(16)
        let mut addl_buf = vec![0u8; 64];
        client.read_exact(&mut addl_buf).await?;

        // Parse address
        let address = self.parse_target_address(&addl_buf)?;
        let port = match &address {
            VlessTargetAddress::Domain(_, p) => *p,
            _ => u16::from_be_bytes([addl_buf[5], addl_buf[6]]),
        };

        info!(
            "VLESS TCP: -> {} (via {}:{})",
            address, self.config.server.addr, self.config.server.port
        );

        // Connect to VLESS server
        let remote_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
        let timeout = self.config.tcp_timeout;

        let remote = match tokio::time::timeout(timeout, TcpStream::connect(&remote_addr)).await {
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

    /// Handle VLESS Reality Vision connection
    ///
    /// Reality Vision uses XTLS which is a special TLS obfuscation protocol.
    /// The client:
    /// 1. Generates X25519 keypair
    /// 2. Computes shared secret with server's public key
    /// 3. Builds a special TLS ClientHello with Reality chrome
    /// 4. Server responds with encrypted header containing the real destination
    async fn handle_reality_vision(
        self: &Arc<Self>,
        client: TcpStream,
        _header_buf: &[u8],
    ) -> std::io::Result<()> {
        let reality_config = self.config.server.reality.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Reality config required for XTLS Vision",
            )
        })?;

        // Step 1: Generate X25519 temporary keypair
        let mut rng = rand::rngs::OsRng;
        let scalar = curve25519_dalek::Scalar::random(&mut rng);
        let point = curve25519_dalek::MontgomeryPoint::mul_base(&scalar);
        let client_public: [u8; 32] = point.to_bytes();

        // Step 2: Compute ECDH shared secret with server's public key
        let server_public_key = &reality_config.public_key;
        if server_public_key.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid server public key length",
            ));
        }

        let server_point_array: [u8; 32] = server_public_key
            .as_slice()
            .try_into()
            .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "Invalid public key"))?;
        let server_point = curve25519_dalek::MontgomeryPoint(server_point_array);
        let shared_point = server_point * scalar;
        let shared_secret: [u8; 32] = shared_point.to_bytes();

        // Step 3: Generate Reality request
        // The Reality request is a 48-byte payload containing:
        // - 32 bytes: HMAC-SHA256(key, "Reality Souls")
        // - 16 bytes: short_id (first 8 bytes) + random (last 8 bytes)
        let mut request = [0u8; 48];

        // First 32 bytes: HMAC-SHA256(shared_secret, "Reality Souls")
        let hmac_key = hmac_sha256(&shared_secret, b"Reality Souls");
        request[..32].copy_from_slice(&hmac_key);

        // Next 16 bytes: short_id (first 8 bytes) + random (last 8 bytes)
        if reality_config.short_id.len() >= 8 {
            request[32..40].copy_from_slice(&reality_config.short_id[..8]);
        }
        let random_bytes: [u8; 8] = rand::random();
        request[40..].copy_from_slice(&random_bytes);

        // Step 4: Build TLS ClientHello with Reality chrome
        let destination = &reality_config.destination;
        let client_hello =
            self.build_reality_client_hello(&client_public, &request, destination)?;

        // Step 5: Connect to server and send ClientHello
        let remote_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
        let mut remote =
            tokio::time::timeout(self.config.tcp_timeout, TcpStream::connect(&remote_addr))
                .await??;

        // Send ClientHello
        remote.write_all(&client_hello).await?;
        remote.flush().await?;

        debug!("Sent Reality ClientHello to {}", remote_addr);

        // Step 6: Receive ServerHello
        let mut server_response = vec![0u8; 8192];
        let n = tokio::time::timeout(self.config.tcp_timeout, remote.read(&mut server_response))
            .await??;

        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "server closed connection",
            ));
        }

        debug!("Received {} bytes from server", n);

        // For Reality Vision, after the TLS handshake, we need to:
        // 1. Parse the server's response to get the real destination
        // 2. Forward traffic bidirectionally

        // For now, just relay between client and server
        // A full implementation would parse the server's response to get
        // the real destination address from the server's ServerHello
        self.relay(client, remote).await
    }

    /// Build a TLS ClientHello with Reality chrome extension
    fn build_reality_client_hello(
        &self,
        client_public: &[u8; 32],
        request: &[u8; 48],
        destination: &str,
    ) -> std::io::Result<Vec<u8>> {
        

        let mut client_hello = Vec::new();

        // TLS Record Layer: Handshake (0x16)
        client_hello.push(0x16);

        // TLS Version TLS 1.3 (0x0303)
        client_hello.push(0x03);
        client_hello.push(0x03);

        // Handshake payload placeholder
        let payload_start = client_hello.len();
        client_hello.push(0x00); // length placeholder
        client_hello.push(0x00);
        client_hello.push(0x00);

        // Handshake type: ClientHello (0x01)
        client_hello.push(0x01);

        // Handshake length (placeholder, will update later)
        let handshake_len_pos = client_hello.len();
        client_hello.push(0x00);
        client_hello.push(0x00);
        client_hello.push(0x00);

        // ClientVersion TLS 1.3 (0x0303)
        client_hello.push(0x03);
        client_hello.push(0x03);

        // Random (32 bytes)
        let random: [u8; 32] = rand::random();
        client_hello.extend_from_slice(&random);

        // Session ID (empty)
        client_hello.push(0x00);

        // Cipher suites - TLS 1.3 suites
        let cipher_suites: Vec<u16> = vec![
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
        ];
        client_hello.push((cipher_suites.len() * 2) as u8);
        for cs in cipher_suites {
            client_hello.push((cs >> 8) as u8);
            client_hello.push((cs & 0xff) as u8);
        }

        // Compression methods (null only)
        client_hello.push(0x01);
        client_hello.push(0x00);

        // Extensions length placeholder
        let extensions_start = client_hello.len();
        client_hello.push(0x00);
        client_hello.push(0x00);

        // Add SNI extension (server_name)
        self.add_sni_extension(&mut client_hello, destination)?;

        // Add ALPN extension
        self.add_alpn_extension(&mut client_hello)?;

        // Add supported_versions extension (TLS 1.3)
        self.add_supported_versions_extension(&mut client_hello)?;

        // Add psk_key_exchange_modes extension
        self.add_psk_modes_extension(&mut client_hello)?;

        // Add key_share extension with Reality chrome
        self.add_reality_key_share(&mut client_hello, client_public, request)?;

        // Update extensions length
        let ext_len = client_hello.len() - extensions_start - 2;
        client_hello[extensions_start] = (ext_len >> 8) as u8;
        client_hello[extensions_start + 1] = (ext_len & 0xff) as u8;

        // Update handshake length
        let handshake_len = client_hello.len() - handshake_len_pos - 3;
        client_hello[handshake_len_pos] = (handshake_len >> 16) as u8;
        client_hello[handshake_len_pos + 1] = (handshake_len >> 8) as u8;
        client_hello[handshake_len_pos + 2] = (handshake_len & 0xff) as u8;

        // Update record layer length
        let record_len = client_hello.len() - payload_start - 3 + 4; // +4 for record header
        client_hello[payload_start] = (record_len >> 8) as u8;
        client_hello[payload_start + 1] = (record_len & 0xff) as u8;
        client_hello[payload_start + 2] = (record_len & 0xff) as u8;

        Ok(client_hello)
    }

    fn add_sni_extension(&self, buffer: &mut Vec<u8>, destination: &str) -> std::io::Result<()> {
        // Extension type: server_name (0x0000)
        buffer.push(0x00);
        buffer.push(0x00);

        // Extension data length
        let len_pos = buffer.len();
        buffer.push(0x00);
        buffer.push(0x00);

        // ServerNameList length
        buffer.push(0x00);

        // ServerName type: host_name (0x00)
        buffer.push(0x00);

        // ServerName length
        let name_bytes = destination.as_bytes();
        buffer.push((name_bytes.len() >> 8) as u8);
        buffer.push((name_bytes.len() & 0xff) as u8);

        // ServerName
        buffer.extend_from_slice(name_bytes);

        // Update extension length
        let ext_data_len = buffer.len() - len_pos - 2;
        buffer[len_pos] = (ext_data_len >> 8) as u8;
        buffer[len_pos + 1] = (ext_data_len & 0xff) as u8;

        Ok(())
    }

    fn add_alpn_extension(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        // Extension type: application_layer_protocol_negotiation (0x0010)
        buffer.push(0x00);
        buffer.push(0x10);

        // Extension data length
        let len_pos = buffer.len();
        buffer.push(0x00);
        buffer.push(0x00);

        // Protocol name list length
        let list_start = buffer.len();
        buffer.push(0x00);
        buffer.push(0x00);

        let alpn_list = ["h2", "http/1.1"];
        for alpn in &alpn_list {
            buffer.push(alpn.len() as u8);
            buffer.extend_from_slice(alpn.as_bytes());
        }

        // Update list length
        let list_len = buffer.len() - list_start - 2;
        buffer[list_start] = (list_len >> 8) as u8;
        buffer[list_start + 1] = (list_len & 0xff) as u8;

        // Update extension length
        let ext_data_len = buffer.len() - len_pos - 2;
        buffer[len_pos] = (ext_data_len >> 8) as u8;
        buffer[len_pos + 1] = (ext_data_len & 0xff) as u8;

        Ok(())
    }

    fn add_supported_versions_extension(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        // Extension type: supported_versions (0x002b)
        buffer.push(0x00);
        buffer.push(0x2b);

        // Extension data length
        buffer.push(0x02);

        // Client: supported version TLS 1.3
        buffer.push(0x03);
        buffer.push(0x03);

        Ok(())
    }

    fn add_psk_modes_extension(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        // Extension type: psk_key_exchange_modes (0x002d)
        buffer.push(0x00);
        buffer.push(0x2d);

        // Extension data length
        buffer.push(0x02);

        // PSK modes: psk_dhe_ke (0x01)
        buffer.push(0x01);
        buffer.push(0x01);

        Ok(())
    }

    fn add_reality_key_share(
        &self,
        buffer: &mut Vec<u8>,
        client_public: &[u8; 32],
        request: &[u8; 48],
    ) -> std::io::Result<()> {
        // Extension type: key_share (0x0033)
        buffer.push(0x00);
        buffer.push(0x33);

        // Extension data length (placeholder)
        let len_pos = buffer.len();
        buffer.push(0x00);
        buffer.push(0x00);

        // Key share entry length
        let entry_len_pos = buffer.len();
        buffer.push(0x00);
        buffer.push(0x00);

        // Key share entry:
        // - 2 bytes: named group (x25519 = 0x001d)
        buffer.push(0x00);
        buffer.push(0x1d);

        // - 1 byte: key exchange length (32 bytes)
        buffer.push(0x20);

        // - 32 bytes: key exchange value (client public)
        buffer.extend_from_slice(client_public);

        // Update key share entry length
        let entry_len = buffer.len() - entry_len_pos - 2;
        buffer[entry_len_pos] = (entry_len >> 8) as u8;
        buffer[entry_len_pos + 1] = (entry_len & 0xff) as u8;

        // Update extension length
        let ext_data_len = buffer.len() - len_pos - 2;
        buffer[len_pos] = (ext_data_len >> 8) as u8;
        buffer[len_pos + 1] = (ext_data_len & 0xff) as u8;

        // Add secondary key share for Reality request
        // This is the "chrome" payload that contains the VLESS request
        //
        // Reality uses a special format:
        // - First extension: key_share with X25519 public key
        // - The "chrome" is encoded in a subsequent handshake message or
        //   as part of the key derivation
        //
        // For VLESS Reality Vision, the request (48 bytes) is sent
        // as the first bytes after the key exchange
        //
        // Note: The actual Reality implementation may encode the request
        // differently. This is a simplified implementation.

        Ok(())
    }

    /// Parse target address from VLESS header
    fn parse_target_address(&self, buf: &[u8]) -> std::io::Result<VlessTargetAddress> {
        let atyp = buf[4];
        match VlessAddressType::from_u8(atyp) {
            Some(VlessAddressType::Ipv4) => {
                if buf.len() < 10 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "buffer too small for IPv4",
                    ));
                }
                let ip = IpAddr::V4(Ipv4Addr::new(buf[5], buf[6], buf[7], buf[8]));
                let port = u16::from_be_bytes([buf[9], buf[10]]);
                Ok(VlessTargetAddress::Ipv4(ip))
            }
            Some(VlessAddressType::Domain) => {
                if buf.len() < 6 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "buffer too small for domain",
                    ));
                }
                let domain_len = buf[5] as usize;
                if buf.len() < 6 + domain_len + 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "buffer too small for domain content",
                    ));
                }
                let domain = String::from_utf8(buf[6..6 + domain_len].to_vec()).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid domain")
                })?;
                let port = u16::from_be_bytes([buf[6 + domain_len], buf[6 + domain_len + 1]]);
                Ok(VlessTargetAddress::Domain(domain, port))
            }
            Some(VlessAddressType::Ipv6) => {
                if buf.len() < 22 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "buffer too small for IPv6",
                    ));
                }
                let ip = IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([buf[5], buf[6]]),
                    u16::from_be_bytes([buf[7], buf[8]]),
                    u16::from_be_bytes([buf[9], buf[10]]),
                    u16::from_be_bytes([buf[11], buf[12]]),
                    u16::from_be_bytes([buf[13], buf[14]]),
                    u16::from_be_bytes([buf[15], buf[16]]),
                    u16::from_be_bytes([buf[17], buf[18]]),
                    u16::from_be_bytes([buf[19], buf[20]]),
                ));
                let port = u16::from_be_bytes([buf[21], buf[22]]);
                Ok(VlessTargetAddress::Ipv6(ip))
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid address type",
            )),
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
}

// Note: Handler trait implementation requires Connection->TcpStream conversion
// which is protocol-specific. For VLESS, use VlessHandler::handle_vless directly
// with a TcpStream, or implement the conversion in your connection handler.

/// Compute HMAC-SHA256
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    let mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    let result = mac.chain_update(data).finalize();
    result.into_bytes().into()
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
    #[allow(dead_code)]
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("VLESS server listening on {}", self.listen_addr);

        loop {
            match self.listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle_vless(client).await {
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
        let valid_uuid = [0u8; 16];
        assert!(VlessHandler::validate_uuid(&valid_uuid));

        assert!(!VlessHandler::validate_uuid(&[]));
        assert!(!VlessHandler::validate_uuid(&[0u8; 15]));
        assert!(!VlessHandler::validate_uuid(&[0u8; 17]));
    }

    #[test]
    fn test_vless_command_from_u8() {
        assert_eq!(VlessCommand::from_u8(0x01), Some(VlessCommand::Tcp));
        assert_eq!(VlessCommand::from_u8(0x02), Some(VlessCommand::Udp));
        assert_eq!(VlessCommand::from_u8(0x03), Some(VlessCommand::XtlsVision));
        assert_eq!(VlessCommand::from_u8(0x04), None);
    }

    #[test]
    fn test_vless_address_type_from_u8() {
        assert_eq!(
            VlessAddressType::from_u8(0x01),
            Some(VlessAddressType::Ipv4)
        );
        assert_eq!(
            VlessAddressType::from_u8(0x02),
            Some(VlessAddressType::Domain)
        );
        assert_eq!(
            VlessAddressType::from_u8(0x03),
            Some(VlessAddressType::Ipv6)
        );
        assert_eq!(VlessAddressType::from_u8(0x04), None);
    }

    #[test]
    fn test_default_config() {
        let config = VlessClientConfig::default();
        assert_eq!(config.listen_addr, SocketAddr::from(([127, 0, 0, 1], 1080)));
        assert_eq!(config.server.port, 443);
    }

    #[test]
    fn test_reality_config() {
        let private_key = [0u8; 32];
        let public_key = [1u8; 32];
        let short_id = [2u8; 8];
        let config = VlessRealityConfig::new(&private_key, &public_key, &short_id, "google.com");

        assert_eq!(config.destination, "google.com");
        assert_eq!(config.flow, "vision");
    }

    #[test]
    fn test_target_address_parse_ipv4() {
        let payload = [0x01, 192, 168, 1, 1, 0x1F, 0x90]; // 192.168.1.1:8080
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
        let payload = [
            0x02, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x00,
            0x50,
        ]; // example.com:80
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
    fn test_hmac_sha256() {
        let key = b"test_key";
        let data = b"test_data";
        let result = hmac_sha256(key, data);
        assert_eq!(result.len(), 32);
    }
}
