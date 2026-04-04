//! Tracking configuration module

use serde::Deserialize;

/// Tracking/monitoring configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TrackingConfig {
    /// Enable tracking
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Export interval in seconds
    #[serde(default = "default_tracking_export_interval")]
    pub export_interval: u64,
    /// Maximum connection entries to track
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Maximum rule entries to track
    #[serde(default = "default_max_rules")]
    pub max_rules: usize,
    /// Connection tracking TTL in seconds
    #[serde(default = "default_connection_ttl")]
    pub connection_ttl: u64,
    /// Export configuration
    #[serde(default)]
    pub export: TrackingExportConfig,
    /// Sampling configuration
    #[serde(default)]
    pub sampling: TrackingSamplingConfig,
    /// Protocol tracking configuration
    #[serde(default)]
    pub protocols: TrackingProtocolsConfig,
    /// Rule tracking configuration
    #[serde(default)]
    pub rules: TrackingRulesConfig,
    /// Node tracking configuration
    #[serde(default)]
    pub nodes: TrackingNodesConfig,
}

impl Default for TrackingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            export_interval: default_tracking_export_interval(),
            max_connections: default_max_connections(),
            max_rules: default_max_rules(),
            connection_ttl: default_connection_ttl(),
            export: TrackingExportConfig::default(),
            sampling: TrackingSamplingConfig::default(),
            protocols: TrackingProtocolsConfig::default(),
            rules: TrackingRulesConfig::default(),
            nodes: TrackingNodesConfig::default(),
        }
    }
}

/// Tracking export configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TrackingExportConfig {
    /// Enable Prometheus export
    #[serde(default)]
    pub prometheus: bool,
    /// Prometheus listen port
    #[serde(default = "default_prometheus_port")]
    pub prometheus_port: u16,
    /// Prometheus metrics path
    #[serde(default = "default_prometheus_path")]
    pub prometheus_path: String,
    /// Enable JSON API
    #[serde(default)]
    pub json_api: bool,
    /// JSON API listen port
    #[serde(default = "default_json_api_port")]
    pub json_api_port: u16,
    /// JSON API path
    #[serde(default = "default_json_api_path")]
    pub json_api_path: String,
    /// Enable WebSocket for real-time updates
    #[serde(default)]
    pub websocket: bool,
}

impl Default for TrackingExportConfig {
    fn default() -> Self {
        Self {
            prometheus: false,
            prometheus_port: default_prometheus_port(),
            prometheus_path: default_prometheus_path(),
            json_api: false,
            json_api_port: default_json_api_port(),
            json_api_path: default_json_api_path(),
            websocket: false,
        }
    }
}

/// Tracking sampling configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TrackingSamplingConfig {
    /// Sample 1 in N packets for detailed tracking
    #[serde(default = "default_packet_sample_rate")]
    pub packet_sample_rate: u32,
    /// Sample 1 in N connections for latency tracking
    #[serde(default = "default_latency_sample_rate")]
    pub latency_sample_rate: u32,
}

impl Default for TrackingSamplingConfig {
    fn default() -> Self {
        Self {
            packet_sample_rate: default_packet_sample_rate(),
            latency_sample_rate: default_latency_sample_rate(),
        }
    }
}

/// Tracking protocols configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TrackingProtocolsConfig {
    /// TCP tracking settings
    #[serde(default)]
    pub tcp: TrackingProtocolSettings,
    /// UDP tracking settings
    #[serde(default)]
    pub udp: TrackingProtocolSettings,
    /// DNS tracking settings
    #[serde(default)]
    pub dns: TrackingProtocolSettings,
}

impl Default for TrackingProtocolsConfig {
    fn default() -> Self {
        Self {
            tcp: TrackingProtocolSettings::default(),
            udp: TrackingProtocolSettings::default(),
            dns: TrackingProtocolSettings::default(),
        }
    }
}

/// Individual protocol tracking settings
#[derive(Debug, Clone, Deserialize)]
pub struct TrackingProtocolSettings {
    /// Enable tracking for this protocol
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Track RTT/latency
    #[serde(default)]
    pub track_rtt: bool,
}

impl Default for TrackingProtocolSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            track_rtt: false,
        }
    }
}

/// Tracking rules configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TrackingRulesConfig {
    /// Enable per-rule statistics
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Track bytes per rule
    #[serde(default = "default_true")]
    pub track_bytes: bool,
}

impl Default for TrackingRulesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            track_bytes: true,
        }
    }
}

/// Tracking nodes configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TrackingNodesConfig {
    /// Enable per-node statistics
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Track latency percentiles
    #[serde(default = "default_true")]
    pub track_percentiles: bool,
    /// Latency histogram buckets (ms)
    #[serde(default = "default_latency_buckets")]
    pub latency_buckets: Vec<u32>,
}

impl Default for TrackingNodesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            track_percentiles: true,
            latency_buckets: default_latency_buckets(),
        }
    }
}

// Tracking default helper functions
fn default_tracking_export_interval() -> u64 {
    10
}
fn default_max_connections() -> usize {
    65536
}
fn default_max_rules() -> usize {
    1024
}
fn default_connection_ttl() -> u64 {
    3600
}
fn default_prometheus_port() -> u16 {
    9090
}
fn default_prometheus_path() -> String {
    "/metrics".to_string()
}
fn default_json_api_port() -> u16 {
    8080
}
fn default_json_api_path() -> String {
    "/api/stats".to_string()
}
fn default_packet_sample_rate() -> u32 {
    100
}
fn default_latency_sample_rate() -> u32 {
    10
}
fn default_latency_buckets() -> Vec<u32> {
    vec![10, 25, 50, 100, 200, 500, 1000]
}
fn default_true() -> bool {
    true
}
