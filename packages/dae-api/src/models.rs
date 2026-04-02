//! Request/Response models for REST API
//!
//! These types are used for API serialization/deserialization

use serde::{Deserialize, Serialize};

/// Node information response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeResponse {
    /// Unique node identifier
    pub id: String,
    /// Human-readable node name
    pub name: String,
    /// Protocol type (shadowsocks, vless, vmess, trojan, etc.)
    pub protocol: String,
    /// Latency in milliseconds (None if not measured)
    pub latency_ms: Option<u32>,
    /// Node connection status
    pub status: NodeStatus,
}

/// Node connection status
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum NodeStatus {
    Online,
    Offline,
    Unknown,
}

impl std::fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeStatus::Online => write!(f, "Online"),
            NodeStatus::Offline => write!(f, "Offline"),
            NodeStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Rule information response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuleResponse {
    /// Unique rule identifier
    pub id: String,
    /// Human-readable rule name
    pub name: String,
    /// Rule action (accept, reject, proxy)
    pub action: String,
    /// Rule priority (lower = higher priority)
    pub priority: u32,
}

/// Statistics response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StatsResponse {
    /// Total connections since start
    pub total_connections: u64,
    /// Currently active connections
    pub active_connections: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Uptime in seconds
    pub uptime_secs: u64,
}

/// Configuration response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigResponse {
    /// SOCKS5 listen address
    pub socks5_listen: Option<String>,
    /// HTTP proxy listen address
    pub http_listen: Option<String>,
    /// eBPF interface name
    pub ebpf_interface: String,
    /// eBPF enabled flag
    pub ebpf_enabled: bool,
    /// Number of configured nodes
    pub node_count: usize,
    /// Rules config file path
    pub rules_config: Option<String>,
}

/// Health check response
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HealthResponse {
    /// Service status
    pub status: String,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Version string
    pub version: String,
}

/// Error response
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

impl ErrorResponse {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
        }
    }
}
