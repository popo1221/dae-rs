//! Control interface types
//!
//! Shared types for the Unix Domain Socket control interface.

use serde::{Deserialize, Serialize};

/// Control command types
#[derive(Debug, Clone)]
pub enum ControlCommand {
    /// Get proxy status
    Status,
    /// Reload configuration (hot reload)
    Reload,
    /// Get statistics
    Stats,
    /// Shutdown the proxy gracefully
    Shutdown,
    /// Test connectivity to a specific node
    TestNode(String),
    /// Get version information
    Version,
    /// Get help
    Help,
}

/// Control response types
#[derive(Debug, Clone)]
pub enum ControlResponse {
    /// Success response with data
    Ok(String),
    /// Error response
    Error(String),
    /// Statistics response
    Stats(ProxyStats),
    /// Status response
    Status(ProxyStatus),
    /// Test result response
    TestResult(NodeTestResult),
    /// Version response
    Version(String),
}

/// Proxy running status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub uptime_secs: u64,
    pub tcp_connections: usize,
    pub udp_sessions: usize,
    pub rules_loaded: bool,
    pub rule_count: usize,
    pub nodes_configured: usize,
    // Extended stats
    pub total_connections: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
}

/// Proxy statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStats {
    pub total_connections: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub active_tcp_connections: usize,
    pub active_udp_sessions: usize,
    pub rules_hit: u64,
    pub nodes_tested: usize,
    pub rule_count: usize,
    pub node_count: usize,
}

/// Node test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeTestResult {
    pub node_name: String,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Configuration state tracked by control interface
#[derive(Debug, Clone)]
pub struct ConfigState {
    pub rules_loaded: bool,
    pub rule_count: usize,
    pub node_count: usize,
}

impl Default for ConfigState {
    fn default() -> Self {
        Self {
            rules_loaded: false,
            rule_count: 0,
            node_count: 0,
        }
    }
}

/// Legacy overall stats structure for metrics-based fallback
#[derive(Debug, Clone)]
pub struct LegacyOverallStats {
    pub connections_total: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub rules_hit: u64,
    pub nodes_tested: usize,
}
