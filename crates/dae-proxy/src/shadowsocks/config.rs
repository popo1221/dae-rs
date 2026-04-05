//! Shadowsocks configuration types
//!
//! Contains server and client configuration structures.

use std::net::SocketAddr;
use std::time::Duration;

use super::protocol::SsCipherType;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SsClientConfig::default();
        assert_eq!(config.listen_addr, SocketAddr::from(([127, 0, 0, 1], 1080)));
        assert_eq!(config.server.port, 8388);
        assert_eq!(config.server.method, SsCipherType::Chacha20IetfPoly1305);
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
}
