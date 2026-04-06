//! dae-config base types
//!
//! Core configuration types for dae-rs.

use serde::Deserialize;
use thiserror::Error;

/// Configuration validation errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid port number: {0} (must be 1-65535)")]
    InvalidPort(u16),
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("Invalid node configuration: {0}")]
    InvalidNode(String),
    #[error("Rule file not found: {0}")]
    RuleFileNotFound(String),
    #[error("Rule file parse error: {0}")]
    RuleFileParseError(String),
    #[error("Invalid subscription: {0}")]
    InvalidSubscription(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
}

/// Node type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeType {
    Shadowsocks,
    Vless,
    Vmess,
    Trojan,
}

impl NodeType {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeType::Shadowsocks => "shadowsocks",
            NodeType::Vless => "vless",
            NodeType::Vmess => "vmess",
            NodeType::Trojan => "trojan",
        }
    }
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeType::Shadowsocks => write!(f, "shadowsocks"),
            NodeType::Vless => write!(f, "vless"),
            NodeType::Vmess => write!(f, "vmess"),
            NodeType::Trojan => write!(f, "trojan"),
        }
    }
}

impl std::str::FromStr for NodeType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "shadowsocks" | "ss" => Ok(NodeType::Shadowsocks),
            "vless" => Ok(NodeType::Vless),
            "vmess" => Ok(NodeType::Vmess),
            "trojan" => Ok(NodeType::Trojan),
            _ => Err(format!("Unknown node type: {s}")),
        }
    }
}

/// Log level enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
