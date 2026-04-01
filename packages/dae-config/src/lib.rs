//! dae-config library

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub global: GlobalConfig,
    pub proxy: Vec<ProxyConfig>,
    #[serde(default)]
    pub shadowsocks: Vec<ShadowsocksServerConfig>,
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

fn default_port() -> u16 {
    8080
}

fn default_log_level() -> String {
    "info".to_string()
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
        };
        assert_eq!(config.global.port, 8080);
    }
}
