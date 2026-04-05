//! VLESS configuration types
//!
//! Configuration structures for VLESS client and server.

use std::net::SocketAddr;
use std::time::Duration;

use crate::protocol::HandlerConfig;

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
