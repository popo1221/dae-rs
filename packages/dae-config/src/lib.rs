//! dae-config library

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub global: GlobalConfig,
    pub proxy: Vec<ProxyConfig>,
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
        };
        assert_eq!(config.global.port, 8080);
    }
}
