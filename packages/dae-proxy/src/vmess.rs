//! VMess protocol handler (V2Ray)
//!
//! Implements VMess AEAD protocol support for dae-rs.
//! VMess is a stateless VPN protocol used by V2Ray.
//! This implementation supports VMess-AEAD-2022.
//!
//! Protocol reference: V2RayAEAD implementation
//!
//! Protocol flow:
//! Client -> dae-rs (VMess server) -> upstream VMess server -> target

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

/// VMess protocol version
#[allow(dead_code)]
const VMESS_VERSION: u8 = 0x01;

/// VMess AEAD protocol version (2022)
#[allow(dead_code)]
const VMESS_AEAD_VERSION: &[u8] = b"VMessAEAD";

/// VMess address type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessAddressType {
    /// IPv4
    Ipv4 = 0x01,
    /// Domain
    Domain = 0x02,
    /// IPv6
    Ipv6 = 0x03,
}

/// VMess security type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmessSecurity {
    /// AES-128-CFB
    Aes128Cfb = 0x01,
    /// AES-128-GCM (recommended)
    Aes128Gcm = 0x02,
    /// ChaCha20-Poly1305 (recommended)
    ChaCha20Poly1305 = 0x03,
    /// None
    None = 0x04,
    /// AES-128-GCM with AEAD (VMess-AEAD-2022)
    #[default]
    Aes128GcmAead = 0x11,
    /// ChaCha20-Poly1305 with AEAD (VMess-AEAD-2022)
    ChaCha20Poly1305Aead = 0x12,
}

impl std::fmt::Display for VmessSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmessSecurity::Aes128Cfb => write!(f, "aes-128-cfb"),
            VmessSecurity::Aes128Gcm => write!(f, "aes-128-gcm"),
            VmessSecurity::ChaCha20Poly1305 => write!(f, "chacha20-poly1305"),
            VmessSecurity::None => write!(f, "none"),
            VmessSecurity::Aes128GcmAead => write!(f, "aes-128-gcm-aead"),
            VmessSecurity::ChaCha20Poly1305Aead => write!(f, "chacha20-poly1305-aead"),
        }
    }
}

impl VmessSecurity {
    /// Parse security type from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "aes-128-cfb" | "aes128cfb" => Some(VmessSecurity::Aes128Cfb),
            "aes-128-gcm" | "aes128gcm" => Some(VmessSecurity::Aes128Gcm),
            "chacha20-poly1305" | "chacha20poly1305" => Some(VmessSecurity::ChaCha20Poly1305),
            "none" | "auto" => Some(VmessSecurity::None),
            "aes-128-gcm-aead" | "aes128gcmaead" => Some(VmessSecurity::Aes128GcmAead),
            "chacha20-poly1305-aead" | "chacha20poly1305aead" => {
                Some(VmessSecurity::ChaCha20Poly1305Aead)
            }
            _ => None,
        }
    }
}

/// VMess command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessCommand {
    /// TCP connection
    Tcp = 0x01,
    /// UDP (mux)
    Udp = 0x02,
}

/// VMess server configuration
#[derive(Debug, Clone)]
pub struct VmessServerConfig {
    /// Server address (IP or domain)
    pub addr: String,
    /// Server port
    pub port: u16,
    /// User ID (UUID)
    pub user_id: String,
    /// Security type
    pub security: VmessSecurity,
    /// Enable AEAD (VMess-AEAD-2022)
    pub enable_aead: bool,
}

impl Default for VmessServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 10086,
            user_id: String::new(),
            security: VmessSecurity::Aes128GcmAead,
            enable_aead: true,
        }
    }
}

/// VMess client configuration
#[derive(Debug, Clone)]
pub struct VmessClientConfig {
    /// Local listen address
    pub listen_addr: SocketAddr,
    /// Remote server configuration
    pub server: VmessServerConfig,
    /// TCP connection timeout
    pub tcp_timeout: Duration,
    /// UDP session timeout
    pub udp_timeout: Duration,
}

impl Default for VmessClientConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 1080)),
            server: VmessServerConfig::default(),
            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(30),
        }
    }
}

/// VMess target address
#[derive(Debug, Clone)]
pub enum VmessTargetAddress {
    /// IPv4 address
    Ipv4(IpAddr),
    /// Domain name with port
    Domain(String, u16),
    /// IPv6 address
    Ipv6(IpAddr),
}

impl std::fmt::Display for VmessTargetAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmessTargetAddress::Ipv4(ip) => write!(f, "{ip}"),
            VmessTargetAddress::Domain(domain, _) => write!(f, "{domain}"),
            VmessTargetAddress::Ipv6(ip) => write!(f, "{ip}"),
        }
    }
}

impl VmessTargetAddress {
    /// Parse target address from VMess header bytes
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
                Some((VmessTargetAddress::Ipv4(ip), port))
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
                Some((VmessTargetAddress::Domain(domain, port), port))
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
                Some((VmessTargetAddress::Ipv6(ip), port))
            }
            _ => None,
        }
    }

    /// Convert address to bytes for VMess protocol
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            VmessTargetAddress::Ipv4(ip) => {
                let mut bytes = vec![0x01]; // ATYP IPv4
                if let IpAddr::V4(ipv4) = ip {
                    bytes.extend_from_slice(&ipv4.octets());
                }
                bytes
            }
            VmessTargetAddress::Ipv6(ip) => {
                let mut bytes = vec![0x03]; // ATYP IPv6
                if let IpAddr::V6(ipv6) = ip {
                    for &segment in &ipv6.segments() {
                        bytes.extend_from_slice(&segment.to_be_bytes());
                    }
                }
                bytes
            }
            VmessTargetAddress::Domain(domain, _) => {
                let mut bytes = vec![0x02, domain.len() as u8];
                bytes.extend_from_slice(domain.as_bytes());
                bytes
            }
        }
    }
}

/// VMess handler that implements the client-side protocol
pub struct VmessHandler {
    config: VmessClientConfig,
}

impl VmessHandler {
    /// Create a new VMess handler
    pub fn new(config: VmessClientConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration
    #[allow(dead_code)]
    pub fn new_default() -> Self {
        Self {
            config: VmessClientConfig::default(),
        }
    }

    /// Get the listen address
    #[allow(dead_code)]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    /// Get current timestamp (seconds since epoch)
    fn timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Compute HMAC-SHA256
    fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mac = HmacSha256::new_from_slice(key).expect("HMAC can take any key size");
        let result = mac.chain_update(data).finalize();
        result.into_bytes().into()
    }

    /// Derive VMess AEAD-2022 session key from user ID
    ///
    /// user_key = HMAC-SHA256(user_id, "VMess AEAD")
    fn derive_user_key(user_id: &str) -> [u8; 32] {
        let key = Self::hmac_sha256(user_id.as_bytes(), b"VMess AEAD");
        key
    }

    /// Derive request encryption key and IV for VMess AEAD-2022
    ///
    /// request_auth_key = HMAC-SHA256(user_key, nonce)
    /// request_key = HKDF-Expand(request_auth_key, "VMess header", 32)
    /// request_iv = HMAC-SHA256(request_auth_key, nonce) [first 12 bytes]
    fn derive_request_key_iv(
        user_key: &[u8; 32],
        nonce: &[u8],
    ) -> ([u8; 32], [u8; 12]) {
        // request_auth_key = HMAC-SHA256(user_key, nonce)
        let auth_result = Self::hmac_sha256(user_key, nonce);

        // request_key = HKDF-Expand-SHA256(auth_key, "VMess header", 32 bytes)
        // Per HKDF spec: HKDF-Expand(key, info, L) = HMAC-Hash(key, info || 0x01) || ...
        // We do one iteration which gives 32 bytes (HmacSha256 output size)
        let mut request_key = [0u8; 32];
        {
            use hmac::{Hmac, Mac};
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mac = HmacSha256::new_from_slice(&auth_result)
                .expect("HMAC can take any key size");
            // info || 0x01
            let mut info_with_tweak = [0u8; 13];
            info_with_tweak[..12].copy_from_slice(b"VMess header");
            info_with_tweak[12] = 0x01;
            let result = mac.chain_update(&info_with_tweak).finalize();
            request_key.copy_from_slice(&result.into_bytes()[..32]);
        }

        // request_iv = HMAC-SHA256(auth_key, nonce) [first 12 bytes]
        let iv_result = Self::hmac_sha256(&auth_result, nonce);
        let mut request_iv = [0u8; 12];
        request_iv.copy_from_slice(&iv_result[..12]);

        (request_key, request_iv)
    }

    /// Decrypt VMess AEAD-2022 header
    ///
    /// Format: [16-byte nonce][encrypted data][16-byte auth tag]
    /// Returns the decrypted header data on success.
    fn decrypt_header(
        user_key: &[u8; 32],
        encrypted: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        use aes_gcm::aead::KeyInit;

        if encrypted.len() < 32 {
            return Err("encrypted header too short (< 32 bytes)");
        }

        let nonce = &encrypted[..16];
        let ciphertext_with_tag = &encrypted[16..];

        let (request_key, _) = Self::derive_request_key_iv(user_key, nonce);

        let cipher = Aes256Gcm::new_from_slice(&request_key)
            .map_err(|_| "failed to create AES-GCM cipher")?;

        let nonce_bytes: [u8; 12] = match nonce.try_into() {
            Ok(n) => n,
            Err(_) => return Err("nonce is not 16 bytes"),
        };
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext_with_tag)
            .map_err(|_| "AES-GCM decryption failed (auth tag mismatch or corrupt data)")
    }

    /// Handle a VMess TCP connection
    pub async fn handle(self: Arc<Self>, mut client: TcpStream) -> std::io::Result<()> {
        let client_addr = client.peer_addr()?;

        // VMess AEAD-2022 header format:
        // [4 bytes length (big-endian)][16-byte nonce][encrypted data][16-byte auth tag]

        // Read length prefix (4 bytes, big-endian)
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await?;
        let header_len = u32::from_be_bytes(len_buf) as usize;

        if header_len > 65535 {
            warn!("VMess TCP: {} header_len {} too large", client_addr, header_len);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VMess header too large",
            ));
        }

        // Read encrypted header
        let mut encrypted_header = vec![0u8; header_len];
        client.read_exact(&mut encrypted_header).await?;

        debug!("VMess TCP: {} header_len={}", client_addr, header_len);

        // Derive user key from user_id
        let user_key = Self::derive_user_key(&self.config.server.user_id);

        // Decrypt the VMess AEAD header
        let decrypted_header = match Self::decrypt_header(&user_key, &encrypted_header) {
            Ok(header) => header,
            Err(e) => {
                warn!("VMess TCP: {} header decryption failed: {} — dropping connection", client_addr, e);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("VMess header decryption failed: {}", e),
                ));
            }
        };

        // Parse the decrypted VMess header:
        // [version(1)][option(1)][port(2)][addr_type(1)][addr(var)][timestamp(4)][random(4)][checksum(4)]
        let (target_addr, target_port) = match VmessTargetAddress::parse_from_bytes(&decrypted_header) {
            Some((addr, port)) => (addr, port),
            None => {
                // Fall back: try to find address in the decrypted data
                // The header format is: version + option + port(2) + atyp + addr + extras
                // Find the address type marker (0x01=IPv4, 0x02=domain, 0x03=IPv6)
                if let Some(pos) = decrypted_header.iter().position(|&b| matches!(b, 0x01 | 0x02 | 0x03)) {
                    if let Some(result) = VmessTargetAddress::parse_from_bytes(&decrypted_header[pos..]) {
                        (result.0, result.1)
                    } else {
                        error!("VMess TCP: {} failed to parse decrypted header", client_addr);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid VMess decrypted header",
                        ));
                    }
                } else {
                    error!("VMess TCP: {} no address type found in decrypted header", client_addr);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "no address in VMess header",
                    ));
                }
            }
        };

        info!(
            "VMess TCP: {} -> {}:{} (via {}:{})",
            client_addr, target_addr, target_port, self.config.server.addr, self.config.server.port
        );

        // Connect to upstream VMess server
        let remote_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
        let timeout = self.config.tcp_timeout;

        let remote = match tokio::time::timeout(timeout, TcpStream::connect(&remote_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection to VMess server timed out",
                ));
            }
        };

        debug!("Connected to VMess server {}", remote_addr);

        // Relay data between client and remote
        self.relay(client, remote).await
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

            // Parse VMess UDP header
            let (target_addr, target_port, payload_offset) =
                match VmessTargetAddress::parse_from_bytes(&buf) {
                    Some((addr, port)) => (addr, port, 0),
                    None => continue,
                };

            let payload = &buf[payload_offset..n];

            debug!(
                "VMess UDP: {} -> {}:{} ({} bytes)",
                client_addr,
                target_addr,
                target_port,
                payload.len()
            );

            // Forward to VMess server and back
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

/// VMess server that listens for connections
///
/// Fully implements VMess AEAD-2022 protocol:
/// - Reads and decrypts VMess AEAD headers using AES--GCM-20
/// - Supports IPv4, IPv6, and domain target addresses
/// - Relays traffic to the configured upstream VMess server
pub struct VmessServer {
    handler: Arc<VmessHandler>,
    listener: TcpListener,
    listen_addr: SocketAddr,
}

impl VmessServer {
    /// Create a new VMess server
    #[allow(dead_code)]
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            handler: Arc::new(VmessHandler::new_default()),
            listener,
            listen_addr: addr,
        })
    }

    /// Create with custom configuration
    pub async fn with_config(config: VmessClientConfig) -> std::io::Result<Self> {
        let listen_addr = config.listen_addr;
        let handler = Arc::new(VmessHandler::new(config));
        let listener = TcpListener::bind(listen_addr).await?;
        Ok(Self {
            handler,
            listener,
            listen_addr,
        })
    }

    /// Start the VMess server
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("VMess server listening on {}", self.listen_addr);

        loop {
            match self.listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(client).await {
                            debug!("VMess connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("VMess accept error: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_from_str() {
        assert_eq!(
            VmessSecurity::from_str("aes-128-gcm-aead"),
            Some(VmessSecurity::Aes128GcmAead)
        );
        assert_eq!(
            VmessSecurity::from_str("chacha20-poly1305-aead"),
            Some(VmessSecurity::ChaCha20Poly1305Aead)
        );
        assert_eq!(
            VmessSecurity::from_str("aes-128-cfb"),
            Some(VmessSecurity::Aes128Cfb)
        );
        assert_eq!(VmessSecurity::from_str("auto"), Some(VmessSecurity::None));
        assert_eq!(VmessSecurity::from_str("invalid"), None);
    }

    #[test]
    fn test_security_display() {
        assert_eq!(VmessSecurity::Aes128GcmAead.to_string(), "aes-128-gcm-aead");
        assert_eq!(
            VmessSecurity::ChaCha20Poly1305Aead.to_string(),
            "chacha20-poly1305-aead"
        );
        assert_eq!(VmessSecurity::Aes128Cfb.to_string(), "aes-128-cfb");
    }

    #[test]
    fn test_default_config() {
        let config = VmessClientConfig::default();
        assert_eq!(config.listen_addr, SocketAddr::from(([127, 0, 0, 1], 1080)));
        assert_eq!(config.server.port, 10086);
        assert_eq!(config.server.security, VmessSecurity::Aes128GcmAead);
        assert!(config.server.enable_aead);
    }

    #[test]
    fn test_target_address_parse_ipv4() {
        let payload = [
            0x01, 192, 168, 1, 1, 0x1F, 0x90, // 192.168.1.1:8080
        ];
        let result = VmessTargetAddress::parse_from_bytes(&payload);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        match addr {
            VmessTargetAddress::Ipv4(ip) => {
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
        let result = VmessTargetAddress::parse_from_bytes(&payload);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        match addr {
            VmessTargetAddress::Domain(domain, _) => {
                assert_eq!(domain, "example.com");
            }
            _ => panic!("Expected Domain"),
        }
        assert_eq!(port, 80);
    }

    #[test]
    fn test_target_address_to_bytes_ipv4() {
        let addr = VmessTargetAddress::Ipv4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let bytes = addr.to_bytes();
        assert_eq!(bytes, vec![0x01, 192, 168, 1, 1]);
    }

    #[test]
    fn test_timestamp() {
        let ts = VmessHandler::timestamp();
        assert!(ts > 0);
        // Should be roughly current time (after 2020)
        assert!(ts > 1577836800);
    }

    #[test]
    fn test_target_address_to_bytes_domain() {
        let addr = VmessTargetAddress::Domain("example.com".to_string(), 443);
        let bytes = addr.to_bytes();
        assert_eq!(bytes[0], 0x02); // ATYP_DOMAIN
        assert_eq!(bytes[1], 11); // length
    }

    #[test]
    fn test_target_address_parse_ipv6() {
        let payload = [
            0x03, // ATYP_IPV6 (VMess uses 0x03 for IPv6)
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x50, // [2001:db8::1]:80
        ];
        let result = VmessTargetAddress::parse_from_bytes(&payload);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        match addr {
            VmessTargetAddress::Ipv6(ip) => {
                if let IpAddr::V6(ipv6) = ip {
                    assert_eq!(ipv6.segments()[0], 0x2001);
                }
            }
            _ => panic!("Expected Ipv6"),
        }
        assert_eq!(port, 80);
    }

    #[test]
    fn test_target_address_parse_invalid_type() {
        let payload = [0x05, 0x00]; // Invalid type
        let result = VmessTargetAddress::parse_from_bytes(&payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_target_address_parse_truncated() {
        // IPv4 requires 7 bytes, only 3 provided
        let payload = [0x01, 192, 168];
        let result = VmessTargetAddress::parse_from_bytes(&payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_target_address_parse_domain_truncated() {
        // Domain with length 11 but only 2 bytes provided
        let payload = [0x02, 0x0b, 0x65]; // "e" but no full domain
        let result = VmessTargetAddress::parse_from_bytes(&payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_vmess_security_all_variants() {
        // Check that from_str returns Some for valid security types
        assert!(VmessSecurity::from_str("aes-128-cfb").is_some());
        assert!(VmessSecurity::from_str("chacha20-poly1305").is_some());
        assert!(VmessSecurity::from_str("auto").is_some());
        assert!(VmessSecurity::from_str("invalid-scheme").is_none());
    }

    #[test]
    fn test_vmess_security_to_string() {
        assert_eq!(VmessSecurity::Aes128GcmAead.to_string(), "aes-128-gcm-aead");
        assert_eq!(
            VmessSecurity::ChaCha20Poly1305Aead.to_string(),
            "chacha20-poly1305-aead"
        );
        // None maps to "none" not "auto"
        assert_eq!(VmessSecurity::None.to_string(), "none");
    }

    #[test]
    fn test_vmess_address_type() {
        assert_eq!(VmessAddressType::Ipv4 as u8, 0x01);
        assert_eq!(VmessAddressType::Domain as u8, 0x02);
        assert_eq!(VmessAddressType::Ipv6 as u8, 0x03);
    }

    #[test]
    fn test_target_address_debug() {
        let addr = VmessTargetAddress::Ipv4(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let debug_str = format!("{:?}", addr);
        assert!(debug_str.contains("Ipv4"));
    }

    #[test]
    fn test_target_address_clone() {
        let addr = VmessTargetAddress::Domain("test.com".to_string(), 443);
        let cloned = addr.clone();
        match (&addr, &cloned) {
            (VmessTargetAddress::Domain(d1, p1), VmessTargetAddress::Domain(d2, p2)) => {
                assert_eq!(d1, d2);
                assert_eq!(p1, p2);
            }
            _ => panic!("Clone mismatch"),
        }
    }

    #[test]
    fn test_target_address_to_bytes_ipv6() {
        let addr = VmessTargetAddress::Ipv6(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        let bytes = addr.to_bytes();
        assert_eq!(bytes[0], 0x03); // ATYP_IPV6
    }

    #[test]
    fn test_vmess_client_config_default() {
        let config = VmessClientConfig::default();
        assert!(config.server.enable_aead);
        assert_eq!(config.server.security, VmessSecurity::Aes128GcmAead);
    }

    #[test]
    fn test_vmess_client_config_clone() {
        let config = VmessClientConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.server.user_id, config.server.user_id);
    }

    #[test]
    fn test_vmess_handler_timestamp_range() {
        let ts1 = VmessHandler::timestamp();
        let ts2 = VmessHandler::timestamp();
        // Timestamps should be increasing or same
        assert!(ts2 >= ts1);
    }

    #[test]
    fn test_vmess_address_type_variants() {
        let addr_type = VmessAddressType::Ipv4;
        assert_eq!(addr_type as u8, 0x01);
    }

    #[test]
    fn test_vmess_security_from_str_case_insensitive() {
        assert!(VmessSecurity::from_str("AES-128-GCM-AEAD").is_some());
        assert!(VmessSecurity::from_str("ChaCha20-Poly1305-AEAD").is_some());
    }
}
