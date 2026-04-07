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
#[derive(Debug, Clone, Default)]
pub struct ConfigState {
    pub rules_loaded: bool,
    pub rule_count: usize,
    pub node_count: usize,
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

// =============================================================================
// HTTP API Response Types for Tracking
// =============================================================================

/// Connection info for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConnectionInfo {
    pub key: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: String,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub state: String,
    pub node_id: u32,
    pub rule_id: u32,
    pub start_time: u64,
    pub last_time: u64,
    pub age_ms: u64,
    pub idle_ms: u64,
}

/// Connections list response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConnectionsResponse {
    pub total: usize,
    pub active: usize,
    pub connections: Vec<ApiConnectionInfo>,
}

/// Protocol stats for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiProtocolStats {
    pub protocol: String,
    pub packets: u64,
    pub bytes: u64,
    pub connections: u64,
    pub active_connections: u32,
}

/// Transport protocol breakdown response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiTransportProtocolsResponse {
    pub tcp: ApiProtocolStats,
    pub udp: ApiProtocolStats,
    pub icmp: ApiProtocolStats,
}

/// Proxy protocol tracking info for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiProxyProtocolInfo {
    pub protocol: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub total_bytes: u64,
    pub metadata: std::collections::HashMap<String, String>,
}

/// Proxy protocols breakdown response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiProxyProtocolsResponse {
    pub protocols: Vec<ApiProxyProtocolInfo>,
}

/// Rule stats for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRuleStats {
    pub rule_id: u32,
    pub rule_type: String,
    pub match_count: u64,
    pub pass_count: u64,
    pub proxy_count: u64,
    pub drop_count: u64,
    pub bytes_matched: u64,
}

/// Rules statistics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRulesResponse {
    pub total_rules: usize,
    pub rules: Vec<ApiRuleStats>,
}

/// Node stats for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiNodeStats {
    pub node_id: u32,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub latency_avg_ms: f64,
    pub latency_p50_ms: u32,
    pub latency_p90_ms: u32,
    pub latency_p99_ms: u32,
    pub success_rate: f64,
    pub status: String,
}

/// Nodes statistics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiNodesResponse {
    pub total_nodes: usize,
    pub nodes: Vec<ApiNodeStats>,
}

/// Overall statistics for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiOverviewStats {
    pub uptime_secs: u64,
    pub packets_total: u64,
    pub bytes_total: u64,
    pub connections_total: u64,
    pub connections_active: u32,
    pub dropped_total: u64,
    pub routed_total: u64,
    pub unmatched_total: u64,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
}

/// Overview statistics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiOverviewResponse {
    pub overall: ApiOverviewStats,
    pub transport_protocols: ApiTransportProtocolsResponse,
}
