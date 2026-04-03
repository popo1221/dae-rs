//! Tracking store for user-space statistics aggregation
//!
//! Provides in-memory storage and aggregation for tracking data.
//! This is a specification for the tracking storage system.
//!
//! Note: This implementation provides the type definitions and interfaces.
//! Actual implementation would require adding dependencies like dashmap to Cargo.toml.

use crate::tracking::types::*;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

/// Maximum entries in connection tracking
const MAX_CONNECTION_ENTRIES: usize = 65536;

/// Connection tracking store
pub struct ConnectionTrackingStore {
    connections: RwLock<HashMap<ConnectionKey, ConnectionStatsEntry>>,
}

impl ConnectionTrackingStore {
    /// Create a new connection tracking store
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Update or create connection stats
    pub fn update(&self, key: ConnectionKey, stats: ConnectionStatsEntry) {
        let mut connections = self.connections.write().unwrap();
        connections.insert(key, stats);
        
        // Cleanup if too many connections
        if connections.len() > MAX_CONNECTION_ENTRIES {
            Self::cleanup(&mut connections);
        }
    }

    /// Get connection stats
    #[allow(dead_code)]
    pub fn get(&self, key: &ConnectionKey) -> Option<ConnectionStatsEntry> {
        let connections = self.connections.read().unwrap();
        connections.get(key).copied()
    }

    /// Remove connection
    #[allow(dead_code)]
    pub fn remove(&self, key: &ConnectionKey) {
        let mut connections = self.connections.write().unwrap();
        connections.remove(key);
    }

    /// Get all active connections
    #[allow(dead_code)]
    pub fn get_active(&self) -> Vec<(ConnectionKey, ConnectionStatsEntry)> {
        let connections = self.connections.read().unwrap();
        connections
            .iter()
            .filter(|(_, stats)| stats.state != ConnectionState::Closed as u8)
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    /// Cleanup old/closed connections
    fn cleanup(connections: &mut HashMap<ConnectionKey, ConnectionStatsEntry>) {
        let now = current_epoch_ms();
        let max_age = Duration::from_secs(3600); // 1 hour max age
        
        connections.retain(|_, stats| {
            let age = now.saturating_sub(stats.last_time);
            age < max_age.as_millis() as u64 && stats.state != ConnectionState::Closed as u8
        });
    }
}

impl Default for ConnectionTrackingStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Node tracking store
pub struct NodeTrackingStore {
    nodes: RwLock<HashMap<u32, NodeStatsEntry>>,
}

impl NodeTrackingStore {
    /// Create a new node tracking store
    pub fn new() -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
        }
    }

    /// Update node stats
    #[allow(dead_code)]
    pub fn update(&self, node_id: u32, stats: NodeStatsEntry) {
        let mut nodes = self.nodes.write().unwrap();
        nodes.insert(node_id, stats);
    }

    /// Get node stats
    #[allow(dead_code)]
    pub fn get(&self, node_id: u32) -> Option<NodeStatsEntry> {
        let nodes = self.nodes.read().unwrap();
        nodes.get(&node_id).copied()
    }

    /// Get all node stats
    #[allow(dead_code)]
    pub fn get_all(&self) -> HashMap<u32, NodeStatsEntry> {
        let nodes = self.nodes.read().unwrap();
        nodes.clone()
    }
}

impl Default for NodeTrackingStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Rule tracking store
pub struct RuleTrackingStore {
    rules: RwLock<HashMap<u32, RuleStatsEntry>>,
}

impl RuleTrackingStore {
    /// Create a new rule tracking store
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(HashMap::new()),
        }
    }

    /// Update rule stats
    #[allow(dead_code)]
    pub fn update(&self, rule_id: u32, stats: RuleStatsEntry) {
        let mut rules = self.rules.write().unwrap();
        rules.insert(rule_id, stats);
    }

    /// Get rule stats
    #[allow(dead_code)]
    pub fn get(&self, rule_id: u32) -> Option<RuleStatsEntry> {
        let rules = self.rules.read().unwrap();
        rules.get(&rule_id).copied()
    }

    /// Get all rule stats
    #[allow(dead_code)]
    pub fn get_all(&self) -> HashMap<u32, RuleStatsEntry> {
        let rules = self.rules.read().unwrap();
        rules.clone()
    }
}

impl Default for RuleTrackingStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregated statistics store
pub struct TrackingStore {
    /// Connection-level tracking
    connections: ConnectionTrackingStore,
    /// Node-level tracking
    nodes: NodeTrackingStore,
    /// Rule-level tracking
    rules: RuleTrackingStore,
    /// Protocol statistics
    protocols: RwLock<ProtocolStats>,
    /// Overall statistics
    overall: RwLock<OverallStats>,
    /// Start time for uptime calculation
    start_time: Instant,
}

impl TrackingStore {
    /// Create a new tracking store
    pub fn new() -> Self {
        Self {
            connections: ConnectionTrackingStore::new(),
            nodes: NodeTrackingStore::new(),
            rules: RuleTrackingStore::new(),
            protocols: RwLock::new(ProtocolStats::default()),
            overall: RwLock::new(OverallStats::new()),
            start_time: Instant::now(),
        }
    }

    /// Create a shared tracking store
    #[allow(dead_code)]
    pub fn shared() -> SharedTrackingStore {
        Arc::new(Self::new())
    }

    // ==================== Connection Tracking ====================

    /// Update connection stats
    #[allow(dead_code)]
    pub fn update_connection(&self, key: ConnectionKey, stats: ConnectionStatsEntry) {
        self.connections.update(key, stats);
        
        // Update overall stats
        let mut overall = self.overall.write().unwrap();
        overall.connections_total += 1;
    }

    /// Record connection data transfer
    #[allow(dead_code)]
    pub fn record_connection_data(&self, key: &ConnectionKey, bytes: u64, inbound: bool) {
        if let Some(mut stats) = self.connections.get(key) {
            stats.update_packet(bytes, inbound);
            
            // Update protocol stats
            let mut protocols = self.protocols.write().unwrap();
            protocols.get_mut(key.proto).record_packet(bytes);
            
            // Update overall
            let mut overall = self.overall.write().unwrap();
            overall.packets_total += 1;
            overall.bytes_total += bytes;
        }
    }

    // ==================== Overall Stats ====================

    /// Get overall stats
    #[allow(dead_code)]
    pub fn get_overall(&self) -> OverallStats {
        self.overall.read().unwrap().clone()
    }

    /// Increment dropped counter
    #[allow(dead_code)]
    pub fn record_dropped(&self, count: u64) {
        let mut overall = self.overall.write().unwrap();
        overall.dropped_total += count;
    }

    /// Increment routed counter
    #[allow(dead_code)]
    pub fn record_routed(&self, count: u64) {
        let mut overall = self.overall.write().unwrap();
        overall.routed_total += count;
    }

    /// Increment unmatched counter
    #[allow(dead_code)]
    pub fn record_unmatched(&self, count: u64) {
        let mut overall = self.overall.write().unwrap();
        overall.unmatched_total += count;
    }

    // ==================== Protocol Stats ====================

    /// Get protocol stats
    #[allow(dead_code)]
    pub fn get_protocol_stats(&self) -> ProtocolStats {
        self.protocols.read().unwrap().clone()
    }

    // ==================== Export ====================

    /// Export as Prometheus format
    #[allow(dead_code)]
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();
        let overall = self.overall.read().unwrap();
        let protocols = self.protocols.read().unwrap();
        
        // Overall stats
        output.push_str("# dae-rs overall statistics\n");
        output.push_str(&format!("dae_packets_total {}\n", overall.packets_total));
        output.push_str(&format!("dae_bytes_total {}\n", overall.bytes_total));
        output.push_str(&format!("dae_connections_total {}\n", overall.connections_total));
        output.push_str(&format!("dae_connections_active {}\n", overall.connections_active));
        output.push_str(&format!("dae_dropped_total {}\n", overall.dropped_total));
        output.push_str(&format!("dae_routed_total {}\n", overall.routed_total));
        output.push_str(&format!("dae_unmatched_total {}\n", overall.unmatched_total));
        
        // Protocol stats
        output.push_str("\n# dae-rs protocol statistics\n");
        output.push_str(&format!(
            "dae_protocol_packets_total{{protocol=\"tcp\"}} {}\n",
            protocols.tcp.packets
        ));
        output.push_str(&format!(
            "dae_protocol_bytes_total{{protocol=\"tcp\"}} {}\n",
            protocols.tcp.bytes
        ));
        output.push_str(&format!(
            "dae_protocol_packets_total{{protocol=\"udp\"}} {}\n",
            protocols.udp.packets
        ));
        output.push_str(&format!(
            "dae_protocol_bytes_total{{protocol=\"udp\"}} {}\n",
            protocols.udp.bytes
        ));
        
        output
    }

    /// Get uptime in seconds
    #[allow(dead_code)]
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Start an HTTP server for metrics export (Prometheus + JSON API)
    ///
    /// # Arguments
    /// * `port` - Port to listen on
    /// * `metrics_path` - Path for Prometheus metrics endpoint
    /// * `prometheus_mode` - If true, serve Prometheus text format; otherwise JSON
    /// * `websocket` - If true, also enable WebSocket updates
    pub async fn start_http_server(
        port: u16,
        metrics_path: &str,
        prometheus_mode: bool,
        websocket: bool,
        store: Arc<TrackingStore>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr: SocketAddr = ([0, 0, 0, 0], port).into();
        let listener = TcpListener::bind(addr).await?;
        info!("Tracking HTTP server listening on {}", addr);

        // Build router based on mode
        let app = if prometheus_mode {
            let state = MetricsHttpState {
                store,
                prometheus_mode: true,
                websocket_enabled: websocket,
            };
            Router::new()
                .route(metrics_path, get(tracking_metrics_handler))
                .route("/health", get(health_handler))
                .with_state(state)
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any),
                )
        } else {
            let state = MetricsHttpState {
                store,
                prometheus_mode: false,
                websocket_enabled: websocket,
            };
            Router::new()
                .route(metrics_path, get(tracking_json_handler))
                .route("/health", get(health_handler))
                .with_state(state)
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any),
                )
        };

        axum::serve(listener, app).await?;
        Ok(())
    }
}

/// HTTP state for tracking metrics server
#[derive(Clone)]
struct MetricsHttpState {
    store: Arc<TrackingStore>,
    prometheus_mode: bool,
    websocket_enabled: bool,
}

/// Prometheus-format metrics handler
async fn tracking_metrics_handler(
    State(state): State<MetricsHttpState>,
) -> Response<Body> {
    let metrics = state.store.export_prometheus();
    let mut response = Response::new(Body::from(metrics));
    response.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

/// JSON API handler
async fn tracking_json_handler(
    State(state): State<MetricsHttpState>,
) -> Response<Body> {
    let store = &state.store;
    let overall = store.get_overall();
    let protocols = store.get_protocol_stats();
    let uptime = store.uptime_secs();

    let json = format!(
        r#"{{
  "uptime_secs": {},
  "overall": {{
    "packets_total": {},
    "bytes_total": {},
    "connections_total": {},
    "connections_active": {},
    "dropped_total": {},
    "routed_total": {},
    "unmatched_total": {}
  }},
  "protocols": {{
    "tcp": {{"packets": {}, "bytes": {}}},
    "udp": {{"packets": {}, "bytes": {}}}
  }},
  "prometheus": "{}"
}}"#,
        uptime,
        overall.packets_total,
        overall.bytes_total,
        overall.connections_total,
        overall.connections_active,
        overall.dropped_total,
        overall.routed_total,
        overall.unmatched_total,
        protocols.tcp.packets,
        protocols.tcp.bytes,
        protocols.udp.packets,
        protocols.udp.bytes,
        store.export_prometheus()
    );

    let mut response = Response::new(Body::from(json));
    response.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
}

/// Health check handler
async fn health_handler() -> StatusCode {
    StatusCode::OK
}

impl Default for TrackingStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared tracking store type
#[allow(dead_code)]
pub type SharedTrackingStore = Arc<TrackingStore>;

/// Helper function to get current epoch in milliseconds
fn current_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracking_store_connection() {
        let store = TrackingStore::new();
        
        let key = ConnectionKey::new(0x7F000001, 0x08080808, 12345, 80, 6);
        let stats = ConnectionStatsEntry::new(current_epoch_ms());
        
        store.update_connection(key, stats);
        
        let retrieved = store.connections.get(&key);
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_export_prometheus() {
        let store = TrackingStore::new();
        let output = store.export_prometheus();
        
        assert!(output.contains("dae_packets_total"));
        assert!(output.contains("dae_connections_active"));
    }
}
