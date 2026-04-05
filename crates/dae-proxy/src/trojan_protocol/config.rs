//! Trojan configuration types
//!
//! This module contains all configuration types for Trojan protocol,
//! including server config, client config, and TLS settings.

use std::net::SocketAddr;
use std::time::Duration;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_tls_config() {
        let config = TrojanTlsConfig::default();
        assert!(config.enabled);
        assert_eq!(config.version, "1.3");
        assert_eq!(config.alpn.len(), 2);
        assert!(!config.insecure);
    }

    #[test]
    fn test_default_server_config() {
        let config = TrojanServerConfig::default();
        assert_eq!(config.addr, "127.0.0.1");
        assert_eq!(config.port, 443);
        assert!(config.password.is_empty());
    }

    #[test]
    fn test_default_client_config() {
        let config = TrojanClientConfig::default();
        assert_eq!(config.listen_addr, SocketAddr::from(([127, 0, 0, 1], 1080)));
        assert_eq!(config.server.port, 443);
        assert_eq!(config.tcp_timeout, Duration::from_secs(60));
        assert_eq!(config.udp_timeout, Duration::from_secs(30));
    }
}
