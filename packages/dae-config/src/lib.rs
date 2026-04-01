//! dae-config library

use serde::Deserialize;

pub mod rules;
pub use rules::{RuleConfig, RuleGroupConfig, RuleConfigItem};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub global: GlobalConfig,
    pub proxy: Vec<ProxyConfig>,
    #[serde(default)]
    pub shadowsocks: Vec<ShadowsocksServerConfig>,
    #[serde(default)]
    pub vless: Vec<VlessServerConfig>,
    #[serde(default)]
    pub vmess: Vec<VmessServerConfig>,
    #[serde(default)]
    pub trojan: Vec<TrojanServerConfig>,
}

#[derive(Debug, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Deserialize)]
pub struct ProxyConfig {
    pub name: String,
    pub proto: String,
    pub addr: String,
}

/// Shadowsocks server/node configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ShadowsocksServerConfig {
    /// Server name/identifier
    pub name: String,
    /// Server address (IP or domain)
    pub addr: String,
    /// Server port
    pub port: u16,
    /// Encryption method (chacha20-ietf-poly1305, aes-256-gcm, aes-128-gcm)
    pub method: String,
    /// Password/key
    pub password: String,
    /// Enable OTA (One-Time Auth) - default false
    #[serde(default)]
    pub ota: bool,
}

/// Shadowsocks client configuration
#[derive(Debug, Clone)]
pub struct ShadowsocksClientConfig {
    /// Local listen address
    pub listen_addr: String,
    /// Server address
    pub server_addr: String,
    /// Server port
    pub server_port: u16,
    /// Encryption method
    pub method: String,
    /// Password
    pub password: String,
    /// Enable OTA
    pub ota: bool,
}

impl ShadowsocksClientConfig {
    /// Create from ShadowsocksServerConfig with local listen address
    pub fn from_server_config(listen_addr: &str, server: &ShadowsocksServerConfig) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            server_addr: server.addr.clone(),
            server_port: server.port,
            method: server.method.clone(),
            password: server.password.clone(),
            ota: server.ota,
        }
    }
}

/// VLESS server/node configuration
#[derive(Debug, Clone, Deserialize)]
pub struct VlessServerConfig {
    /// Server name/identifier
    pub name: String,
    /// Server address (IP or domain)
    pub addr: String,
    /// Server port
    pub port: u16,
    /// UUID for authentication
    pub uuid: String,
    /// TLS settings (optional)
    #[serde(default)]
    pub tls: Option<VlessTlsConfig>,
}

impl VlessServerConfig {
    /// Create a VlessServerConfig with minimal settings
    pub fn new(name: &str, addr: &str, port: u16, uuid: &str) -> Self {
        Self {
            name: name.to_string(),
            addr: addr.to_string(),
            port,
            uuid: uuid.to_string(),
            tls: None,
        }
    }
}

/// VLESS TLS configuration
#[derive(Debug, Clone, Deserialize)]
pub struct VlessTlsConfig {
    /// Enable TLS (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// TLS version
    #[serde(default = "default_tls_version")]
    pub version: String,
    /// Server name for SNI
    #[serde(default)]
    pub server_name: Option<String>,
    /// ALPN protocols
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
}

/// VLESS client configuration
#[derive(Debug, Clone)]
pub struct VlessClientConfig {
    /// Local listen address
    pub listen_addr: String,
    /// Server address
    pub server_addr: String,
    /// Server port
    pub server_port: u16,
    /// UUID
    pub uuid: String,
    /// TLS enabled
    pub tls_enabled: bool,
}

impl VlessClientConfig {
    /// Create from VlessServerConfig with local listen address
    pub fn from_server_config(listen_addr: &str, server: &VlessServerConfig) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            server_addr: server.addr.clone(),
            server_port: server.port,
            uuid: server.uuid.clone(),
            tls_enabled: server.tls.as_ref().map(|t| t.enabled).unwrap_or(true),
        }
    }
}

/// VMess server/node configuration
#[derive(Debug, Clone, Deserialize)]
pub struct VmessServerConfig {
    /// Server name/identifier
    pub name: String,
    /// Server address (IP or domain)
    pub addr: String,
    /// Server port
    pub port: u16,
    /// User ID (UUID)
    pub user_id: String,
    /// Security type (aes-128-gcm-aead, chacha20-poly1305-aead, etc.)
    #[serde(default = "default_vmess_security")]
    pub security: String,
    /// Enable AEAD (VMess-AEAD-2022)
    #[serde(default = "default_true")]
    pub enable_aead: bool,
}

impl VmessServerConfig {
    /// Create a VmessServerConfig with minimal settings
    pub fn new(name: &str, addr: &str, port: u16, user_id: &str) -> Self {
        Self {
            name: name.to_string(),
            addr: addr.to_string(),
            port,
            user_id: user_id.to_string(),
            security: "aes-128-gcm-aead".to_string(),
            enable_aead: true,
        }
    }
}

/// VMess client configuration
#[derive(Debug, Clone)]
pub struct VmessClientConfig {
    /// Local listen address
    pub listen_addr: String,
    /// Server address
    pub server_addr: String,
    /// Server port
    pub server_port: u16,
    /// User ID
    pub user_id: String,
    /// Security type
    pub security: String,
    /// Enable AEAD
    pub enable_aead: bool,
}

impl VmessClientConfig {
    /// Create from VmessServerConfig with local listen address
    pub fn from_server_config(listen_addr: &str, server: &VmessServerConfig) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            server_addr: server.addr.clone(),
            server_port: server.port,
            user_id: server.user_id.clone(),
            security: server.security.clone(),
            enable_aead: server.enable_aead,
        }
    }
}

/// Trojan server/node configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TrojanServerConfig {
    /// Server name/identifier
    pub name: String,
    /// Server address (IP or domain)
    pub addr: String,
    /// Server port
    pub port: u16,
    /// Password for authentication
    pub password: String,
    /// TLS settings (optional)
    #[serde(default)]
    pub tls: Option<TrojanTlsConfig>,
}

impl TrojanServerConfig {
    /// Create a TrojanServerConfig with minimal settings
    pub fn new(name: &str, addr: &str, port: u16, password: &str) -> Self {
        Self {
            name: name.to_string(),
            addr: addr.to_string(),
            port,
            password: password.to_string(),
            tls: None,
        }
    }
}

/// Trojan TLS configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TrojanTlsConfig {
    /// Enable TLS (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// TLS version
    #[serde(default = "default_tls_version")]
    pub version: String,
    /// Server name for SNI
    #[serde(default)]
    pub server_name: Option<String>,
    /// ALPN protocols
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
}

/// Trojan client configuration
#[derive(Debug, Clone)]
pub struct TrojanClientConfig {
    /// Local listen address
    pub listen_addr: String,
    /// Server address
    pub server_addr: String,
    /// Server port
    pub server_port: u16,
    /// Password
    pub password: String,
    /// TLS enabled
    pub tls_enabled: bool,
}

impl TrojanClientConfig {
    /// Create from TrojanServerConfig with local listen address
    pub fn from_server_config(listen_addr: &str, server: &TrojanServerConfig) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            server_addr: server.addr.clone(),
            server_port: server.port,
            password: server.password.clone(),
            tls_enabled: server.tls.as_ref().map(|t| t.enabled).unwrap_or(true),
        }
    }
}

// Helper functions for default values
fn default_port() -> u16 {
    8080
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_true() -> bool {
    true
}

fn default_tls_version() -> String {
    "1.3".to_string()
}

fn default_vmess_security() -> String {
    "aes-128-gcm-aead".to_string()
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config {
            global: GlobalConfig {
                port: 8080,
                log_level: "info".to_string(),
            },
            proxy: vec![],
            shadowsocks: vec![],
            vless: vec![],
            vmess: vec![],
            trojan: vec![],
        };
        assert_eq!(config.global.port, 8080);
    }

    #[test]
    fn test_vless_server_config() {
        let vless = VlessServerConfig::new("test", "example.com", 443, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(vless.name, "test");
        assert_eq!(vless.addr, "example.com");
        assert_eq!(vless.port, 443);
        assert_eq!(vless.uuid, "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_vmess_server_config() {
        let vmess = VmessServerConfig::new("test", "example.com", 10086, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(vmess.name, "test");
        assert_eq!(vmess.addr, "example.com");
        assert_eq!(vmess.port, 10086);
        assert_eq!(vmess.user_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(vmess.security, "aes-128-gcm-aead");
        assert!(vmess.enable_aead);
    }

    #[test]
    fn test_trojan_server_config() {
        let trojan = TrojanServerConfig::new("test", "example.com", 443, "password123");
        assert_eq!(trojan.name, "test");
        assert_eq!(trojan.addr, "example.com");
        assert_eq!(trojan.port, 443);
        assert_eq!(trojan.password, "password123");
    }
}
