//! Tracking store for user-space statistics aggregation
//!
//! Provides in-memory storage and aggregation for tracking data.
//!
//! # Implementation Status
//!
//! This module is **partially implemented**. It uses `RwLock<HashMap>` instead
//! of the initially planned `dashmap` dependency. The current implementation
//! works but may have performance limitations under high concurrency.
//!
//! See issue #66 on GitHub for tracking potential optimization (e.g., dashmap
//! or concurrent hashmap replacement).

use crate::ebpf_integration::EbpfMaps;
use crate::tracking::types::*;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use dae_ebpf_common::stats::{idx as ebpf_stats_idx, StatsEntry};
use serde::{Deserialize, Serialize};
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

    /// Record a rule match event
    ///
    /// # Arguments
    /// * `rule_id` - Unique identifier for the rule
    /// * `rule_type` - Type of rule (0=Domain, 1=DomainSuffix, 2=DomainKeyword, 3=IpCidr, 4=GeoIp, 5=Process)
    /// * `action` - Action taken (0=Pass, 1=Proxy, 2=Drop)
    /// * `bytes` - Number of bytes for this match
    #[allow(dead_code)]
    pub fn record_match(&self, rule_id: u32, rule_type: u8, action: u8, bytes: u64) {
        let mut rules = self.rules.write().unwrap();
        let stats = rules
            .entry(rule_id)
            .or_insert_with(|| RuleStatsEntry::new(rule_id, rule_type));
        stats.record_match(crate::tracking::types::RuleAction::from(action), bytes);
    }
}

impl Default for RuleTrackingStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregated statistics store
#[allow(dead_code)]
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
    /// Protocol-specific tracking info (keyed by protocol name)
    protocol_tracking: RwLock<std::collections::HashMap<String, ProtocolTrackingInfo>>,
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
            protocol_tracking: RwLock::new(std::collections::HashMap::new()),
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
        // Record previous state for transition tracking
        let prev_state = self.connections.get(&key).map(|s| s.state).unwrap_or(0);

        self.connections.update(key, stats);

        // Update metrics with state transition
        crate::metrics::inc_connection_state(stats.state);

        // Update active connections gauge based on state transitions
        let active_count = self.get_active_connection_count() as i64;
        crate::metrics::set_active_connections(active_count);

        // Update overall stats
        let mut overall = self.overall.write().unwrap();
        overall.connections_total += 1;
        // Track active connections - only transition if state actually changed
        let is_closing_or_closed = stats.state == ConnectionState::Closed as u8
            || stats.state == ConnectionState::Closing as u8;
        let was_closing_or_closed = prev_state == ConnectionState::Closed as u8
            || prev_state == ConnectionState::Closing as u8;
        let is_new_or_established = stats.state == ConnectionState::New as u8
            || stats.state == ConnectionState::Established as u8;
        let was_closed_or_zero = prev_state == ConnectionState::Closed as u8
            || prev_state == ConnectionState::Closing as u8
            || prev_state == 0;

        if is_closing_or_closed && !was_closing_or_closed {
            overall.connections_active = overall.connections_active.saturating_sub(1);
        } else if is_new_or_established && was_closed_or_zero {
            overall.connections_active = overall.connections_active.saturating_add(1);
        }
    }

    /// Record connection data transfer
    #[allow(dead_code)]
    pub fn record_connection_data(&self, key: &ConnectionKey, bytes: u64, inbound: bool) {
        if let Some(mut stats) = self.connections.get(key) {
            stats.update_packet(bytes, inbound);

            // Update protocol stats
            let mut protocols = self.protocols.write().unwrap();
            protocols.get_mut(key.proto).record_packet(bytes);

            // Update tracking metrics
            let transport = crate::metrics::transport_name(key.proto);
            if inbound {
                crate::metrics::inc_tracking_bytes_in(transport, bytes);
            } else {
                crate::metrics::inc_tracking_bytes_out(transport, bytes);
            }
            crate::metrics::inc_tracking_packets(transport);

            // Update overall
            let mut overall = self.overall.write().unwrap();
            overall.packets_total += 1;
            overall.bytes_total += bytes;
        }
    }

    /// Record proxy hop completion for a connection
    ///
    /// Updates the hop index and latency for a connection when a proxy hop completes.
    /// This is used to track multi-hop proxy chain traversal.
    ///
    /// # Arguments
    /// * `key` - The connection key
    /// * `hop_index` - The hop index (0 = direct, 1+ = proxy hop number)
    /// * `hop_latency_ms` - Latency of this hop in milliseconds
    /// * `_success` - Whether the hop succeeded (reserved for future use)
    #[allow(dead_code)]
    pub fn record_proxy_hop(
        &self,
        key: &ConnectionKey,
        hop_index: u8,
        hop_latency_ms: u32,
        _success: bool,
    ) {
        if let Some(mut stats) = self.connections.get(key) {
            stats.hop_index = hop_index;
            stats.hop_latency_ms = hop_latency_ms;
            self.connections.update(*key, stats);
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
        crate::metrics::inc_dropped(count);
        let mut overall = self.overall.write().unwrap();
        overall.dropped_total += count;
    }

    /// Increment routed counter
    #[allow(dead_code)]
    pub fn record_routed(&self, count: u64) {
        crate::metrics::inc_routed(count);
        let mut overall = self.overall.write().unwrap();
        overall.routed_total += count;
    }

    /// Increment unmatched counter
    #[allow(dead_code)]
    pub fn record_unmatched(&self, count: u64) {
        crate::metrics::inc_unmatched(count);
        let mut overall = self.overall.write().unwrap();
        overall.unmatched_total += count;
    }

    // ==================== DNS Stats ====================

    /// Record a DNS cache hit
    #[allow(dead_code)]
    pub fn record_dns_cache_hit(&self) {
        let mut overall = self.overall.write().unwrap();
        overall.dns_queries_total += 1;
        overall.dns_cache_hits += 1;
    }

    /// Record a DNS cache miss
    #[allow(dead_code)]
    pub fn record_dns_cache_miss(&self) {
        let mut overall = self.overall.write().unwrap();
        overall.dns_queries_total += 1;
        overall.dns_cache_misses += 1;
    }

    /// Record a DNS query with latency
    ///
    /// # Arguments
    /// * `latency_ms` - Query latency in milliseconds
    #[allow(dead_code)]
    pub fn record_dns_query(&self, latency_ms: u64) {
        let mut overall = self.overall.write().unwrap();
        overall.dns_queries_total += 1;
        overall.dns_latency_sum_ms += latency_ms;
        overall.dns_latency_count += 1;
    }

    /// Record a DNS upstream switch (fallback triggered)
    #[allow(dead_code)]
    pub fn record_dns_upstream_switch(&self) {
        let mut overall = self.overall.write().unwrap();
        overall.dns_upstream_switches += 1;
    }

    /// Record a DNS error
    #[allow(dead_code)]
    pub fn record_dns_error(&self) {
        let mut overall = self.overall.write().unwrap();
        overall.dns_queries_total += 1;
        overall.dns_errors += 1;
    }

    // ==================== TLS Handshake Stats ====================

    /// Record a TLS handshake start
    ///
    /// Returns the handshake start timestamp for calculating latency on completion.
    ///
    /// # Returns
    /// * `u64` - The handshake start timestamp in epoch milliseconds
    #[allow(dead_code)]
    pub fn record_tls_handshake_start(&self) -> u64 {
        let timestamp = current_epoch_ms();
        let mut overall = self.overall.write().unwrap();
        overall.tls_handshakes_total += 1;
        timestamp
    }

    /// Record a TLS handshake success
    ///
    /// # Arguments
    /// * `start_time` - The handshake start timestamp from `record_tls_handshake_start`
    /// * `tls_version` - TLS version used (e.g., 0x0303 for TLS 1.2, 0x0304 for TLS 1.3)
    /// * `cipher_suite` - Cipher suite ID used
    #[allow(dead_code)]
    pub fn record_tls_handshake_success(
        &self,
        start_time: u64,
        _tls_version: u16,
        _cipher_suite: u16,
    ) {
        let latency_ms = current_epoch_ms().saturating_sub(start_time);
        let mut overall = self.overall.write().unwrap();
        overall.tls_handshake_successes += 1;
        overall.tls_handshake_latency_sum_ms += latency_ms;
        overall.tls_handshake_latency_count += 1;
    }

    /// Record a TLS handshake failure
    ///
    /// # Arguments
    /// * `start_time` - The handshake start timestamp from `record_tls_handshake_start`
    /// * `error` - Error message describing the failure
    #[allow(dead_code)]
    pub fn record_tls_handshake_failure(&self, start_time: u64, error: &str) {
        let latency_ms = current_epoch_ms().saturating_sub(start_time);
        let mut overall = self.overall.write().unwrap();
        overall.tls_handshake_failures += 1;
        overall.tls_handshake_latency_sum_ms += latency_ms;
        overall.tls_handshake_latency_count += 1;
        overall.tls_handshake_last_error = error.to_string();
    }

    // ==================== eBPF Stats Polling ====================

    /// Poll eBPF statistics and merge into overall stats
    ///
    /// This method reads stats from the eBPF PerCpuArray maps and merges
    /// them into the TrackingStore's overall statistics. This is typically
    /// called periodically (e.g., every 5 seconds) to sync eBPF counters
    /// into user-space tracking.
    ///
    /// # Arguments
    /// * `ebpf_maps` - The eBPF maps to poll stats from
    ///
    /// # Phase 1
    /// Phase 1 implements simple polling that merges eBPF stats into overall stats.
    /// Future phases may add per-connection and per-protocol eBPF stat tracking.
    #[allow(dead_code)]
    pub fn poll_stats(&self, ebpf_maps: &EbpfMaps) {
        let Some(ref stats_map) = ebpf_maps.stats else {
            return;
        };

        let ebpf_stats: HashMap<u32, StatsEntry> = stats_map.get_all();
        if ebpf_stats.is_empty() {
            return;
        }

        let mut overall = self.overall.write().unwrap();

        // Merge overall stats from eBPF
        if let Some(overall_entry) = ebpf_stats.get(&ebpf_stats_idx::OVERALL) {
            // For eBPF stats, we track deltas. Since eBPF PerCpuArray accumulates,
            // we use the values directly for now. In a full implementation,
            // we'd track previous values and compute deltas.
            overall.packets_total = overall.packets_total.saturating_add(overall_entry.packets);
            overall.bytes_total = overall.bytes_total.saturating_add(overall_entry.bytes);
            overall.dropped_total = overall.dropped_total.saturating_add(overall_entry.dropped);
            overall.routed_total = overall.routed_total.saturating_add(overall_entry.routed);
            overall.unmatched_total = overall
                .unmatched_total
                .saturating_add(overall_entry.unmatched);
        }

        // Merge protocol stats
        let mut protocols = self.protocols.write().unwrap();

        if let Some(tcp_entry) = ebpf_stats.get(&ebpf_stats_idx::TCP) {
            protocols.tcp.packets = protocols.tcp.packets.saturating_add(tcp_entry.packets);
            protocols.tcp.bytes = protocols.tcp.bytes.saturating_add(tcp_entry.bytes);
        }

        if let Some(udp_entry) = ebpf_stats.get(&ebpf_stats_idx::UDP) {
            protocols.udp.packets = protocols.udp.packets.saturating_add(udp_entry.packets);
            protocols.udp.bytes = protocols.udp.bytes.saturating_add(udp_entry.bytes);
        }

        if let Some(icmp_entry) = ebpf_stats.get(&ebpf_stats_idx::ICMP) {
            protocols.icmp.packets = protocols.icmp.packets.saturating_add(icmp_entry.packets);
            protocols.icmp.bytes = protocols.icmp.bytes.saturating_add(icmp_entry.bytes);
        }

        // Note: DNS stats from eBPF would use ebpf_stats_idx::DNS (index 4)
        // but dae_ebpf_common::stats::idx only defines up to OTHER (index 4).
        // DNS tracking is handled via user-space MacDnsResolver integration instead.
    }

    // ==================== Protocol Stats ====================

    /// Get protocol stats
    #[allow(dead_code)]
    pub fn get_protocol_stats(&self) -> ProtocolStats {
        self.protocols.read().unwrap().clone()
    }

    // ==================== Protocol-Specific Tracking ====================

    /// Record protocol-specific tracking information
    ///
    /// This method records detailed tracking information for proxy protocols
    /// such as VLESS, VMess, Trojan, Shadowsocks, and HTTP Proxy.
    ///
    /// # Arguments
    ///
    /// * `info` - Protocol tracking information containing protocol name,
    ///   bytes transferred, and protocol-specific metadata
    ///
    /// # Example
    ///
    /// ```ignore
    /// let info = ProtocolTrackingInfo::new("vless")
    ///     .with_bytes_in(1024)
    ///     .with_bytes_out(2048)
    ///     .with_metadata("uuid", "550e8400-e29b...")
    ///     .with_metadata("flow", "vision");
    /// store.record_protocol_tracking(info);
    /// ```
    #[allow(dead_code)]
    pub fn record_protocol_tracking(&self, info: ProtocolTrackingInfo) {
        let mut tracking = self.protocol_tracking.write().unwrap();
        let entry = tracking.entry(info.protocol.clone()).or_insert_with(|| {
            // New protocol entry - increment connection counter
            crate::metrics::inc_proxy_protocol_connection(&info.protocol);
            ProtocolTrackingInfo::new(&info.protocol)
        });

        // Track bytes if non-zero (indicates delta update)
        if info.bytes_in > 0 {
            crate::metrics::inc_proxy_protocol_bytes_in(&info.protocol, info.bytes_in);
        }
        if info.bytes_out > 0 {
            crate::metrics::inc_proxy_protocol_bytes_out(&info.protocol, info.bytes_out);
        }

        entry.bytes_in += info.bytes_in;
        entry.bytes_out += info.bytes_out;
        // Merge metadata (last write wins for duplicate keys)
        for (k, v) in info.metadata {
            entry.metadata.insert(k, v);
        }
    }

    /// Get protocol-specific tracking info
    ///
    /// # Arguments
    ///
    /// * `protocol` - Protocol name (e.g., "vless", "vmess", "trojan")
    #[allow(dead_code)]
    pub fn get_protocol_tracking(&self, protocol: &str) -> Option<ProtocolTrackingInfo> {
        let tracking = self.protocol_tracking.read().unwrap();
        tracking.get(protocol).cloned()
    }

    /// Get all protocol-specific tracking info
    #[allow(dead_code)]
    pub fn get_all_protocol_tracking(
        &self,
    ) -> std::collections::HashMap<String, ProtocolTrackingInfo> {
        let tracking = self.protocol_tracking.read().unwrap();
        tracking.clone()
    }

    // ==================== Accessor Methods ====================

    /// Get connection tracking store
    #[allow(dead_code)]
    pub fn connections(&self) -> &ConnectionTrackingStore {
        &self.connections
    }

    /// Get node tracking store
    #[allow(dead_code)]
    pub fn nodes(&self) -> &NodeTrackingStore {
        &self.nodes
    }

    /// Get rule tracking store
    #[allow(dead_code)]
    pub fn rules(&self) -> &RuleTrackingStore {
        &self.rules
    }

    /// Get number of active connections (TCP and UDP combined)
    #[allow(dead_code)]
    pub fn get_active_connection_count(&self) -> usize {
        self.connections.get_active().len()
    }

    /// Get number of active TCP connections
    #[allow(dead_code)]
    pub fn get_active_tcp_count(&self) -> usize {
        self.connections
            .get_active()
            .iter()
            .filter(|(key, _)| key.proto == 6) // TCP
            .filter(|(_, stats)| stats.state != ConnectionState::Closed as u8)
            .count()
    }

    /// Get number of active UDP sessions
    #[allow(dead_code)]
    pub fn get_active_udp_count(&self) -> usize {
        self.connections
            .get_active()
            .iter()
            .filter(|(key, _)| key.proto == 17) // UDP
            .filter(|(_, stats)| stats.state != ConnectionState::Closed as u8)
            .count()
    }

    /// Get number of configured nodes
    #[allow(dead_code)]
    pub fn get_node_count(&self) -> usize {
        self.nodes.get_all().len()
    }

    /// Get number of configured rules
    #[allow(dead_code)]
    pub fn get_rule_count(&self) -> usize {
        self.rules.get_all().len()
    }

    // ==================== Rule Tracking ====================

    /// Record a rule match event
    ///
    /// # Arguments
    /// * `rule_id` - Unique identifier for the rule
    /// * `rule_type` - Type of rule (0=Domain, 1=DomainSuffix, 2=DomainKeyword, 3=IpCidr, 4=GeoIp, 5=Process)
    /// * `action` - Action taken (0=Pass, 1=Proxy, 2=Drop)
    /// * `bytes` - Number of bytes for this match
    #[allow(dead_code)]
    pub fn record_rule_match(&self, rule_id: u32, rule_type: u8, action: u8, bytes: u64) {
        // Update rule stats
        self.rules.record_match(rule_id, rule_type, action, bytes);

        // Update Prometheus metrics
        crate::metrics::inc_rule_match_by_type(rule_type);
        crate::metrics::inc_rule_match_by_action(action);
        crate::metrics::inc_rule_match_bytes(rule_type, bytes);
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
        output.push_str(&format!(
            "dae_connections_total {}\n",
            overall.connections_total
        ));
        output.push_str(&format!(
            "dae_connections_active {}\n",
            overall.connections_active
        ));
        output.push_str(&format!("dae_dropped_total {}\n", overall.dropped_total));
        output.push_str(&format!("dae_routed_total {}\n", overall.routed_total));
        output.push_str(&format!(
            "dae_unmatched_total {}\n",
            overall.unmatched_total
        ));

        // DNS stats
        output.push_str("\n# dae-rs DNS statistics\n");
        output.push_str(&format!(
            "dae_dns_queries_total {}\n",
            overall.dns_queries_total
        ));
        output.push_str(&format!("dae_dns_cache_hits {}\n", overall.dns_cache_hits));
        output.push_str(&format!(
            "dae_dns_cache_misses {}\n",
            overall.dns_cache_misses
        ));
        output.push_str(&format!(
            "dae_dns_upstream_switches {}\n",
            overall.dns_upstream_switches
        ));
        output.push_str(&format!("dae_dns_errors {}\n", overall.dns_errors));
        output.push_str(&format!(
            "dae_dns_latency_avg_ms {}\n",
            overall.dns_avg_latency_ms()
        ));

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

        let state = MetricsHttpState {
            store,
            prometheus_mode,
            websocket_enabled: websocket,
        };

        // Build router with all endpoints
        let app = Router::new()
            // Prometheus endpoint
            .route(metrics_path, get(tracking_metrics_handler))
            // Health check
            .route("/health", get(health_handler))
            // Tracking API endpoints
            .route("/api/tracking/overview", get(api_overview_handler))
            .route("/api/tracking/connections", get(api_connections_handler))
            .route(
                "/api/tracking/connections/*key",
                get(api_connection_detail_handler),
            )
            .route("/api/tracking/protocols", get(api_protocols_handler))
            .route("/api/tracking/rules", get(api_rules_handler))
            .route("/api/tracking/nodes", get(api_nodes_handler))
            .with_state(state)
            .layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods(Any)
                    .allow_headers(Any),
            );

        axum::serve(listener, app).await?;
        Ok(())
    }
}

/// HTTP state for tracking metrics server
#[derive(Clone)]
#[allow(dead_code)]
struct MetricsHttpState {
    store: Arc<TrackingStore>,
    prometheus_mode: bool,
    websocket_enabled: bool,
}

/// Prometheus-format metrics handler
async fn tracking_metrics_handler(State(state): State<MetricsHttpState>) -> Response<Body> {
    let metrics = state.store.export_prometheus();
    let mut response = Response::new(Body::from(metrics));
    response.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

/// JSON API handler (legacy fallback)
#[allow(dead_code)]
async fn tracking_json_handler(State(state): State<MetricsHttpState>) -> Response<Body> {
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

// =============================================================================
// New Tracking API Handlers
// =============================================================================

use crate::control_types::{
    ApiConnectionInfo, ApiConnectionsResponse, ApiNodeStats, ApiNodesResponse, ApiOverviewResponse,
    ApiOverviewStats, ApiProtocolStats, ApiProxyProtocolInfo, ApiProxyProtocolsResponse,
    ApiRuleStats, ApiRulesResponse, ApiTransportProtocolsResponse,
};

/// Query parameters for connections endpoint
#[derive(Debug, Deserialize)]
pub struct ConnectionsQuery {
    pub state: Option<String>,    // active, closed, all
    pub limit: Option<usize>,     // max connections to return
    pub protocol: Option<String>, // tcp, udp
    pub sort_by: Option<String>,  // bytes_in, bytes_out, last_time
}

/// Convert ConnectionKey to string representation
fn connection_key_to_string(key: &ConnectionKey) -> String {
    format!(
        "{}:{:05}-{}:{:05}-{}",
        u32_to_ip(key.src_ip),
        key.src_port,
        u32_to_ip(key.dst_ip),
        key.dst_port,
        key.proto
    )
}

/// Convert u32 IP to string
fn u32_to_ip(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

/// Connection state to string
fn connection_state_to_string(state: u8) -> String {
    match state {
        0 => "NEW".to_string(),
        1 => "ESTABLISHED".to_string(),
        2 => "CLOSING".to_string(),
        3 => "CLOSED".to_string(),
        _ => format!("UNKNOWN({})", state),
    }
}

/// Rule type to string
fn rule_type_to_string(rule_type: u8) -> String {
    match rule_type {
        0 => "DOMAIN".to_string(),
        1 => "DOMAIN_SUFFIX".to_string(),
        2 => "DOMAIN_KEYWORD".to_string(),
        3 => "IP_CIDR".to_string(),
        4 => "GEO_IP".to_string(),
        5 => "PROCESS".to_string(),
        _ => format!("UNKNOWN({})", rule_type),
    }
}

/// Node status to string
fn node_status_to_string(status: u8) -> String {
    match status {
        0 => "UP".to_string(),
        1 => "DOWN".to_string(),
        2 => "DEGRADED".to_string(),
        _ => format!("UNKNOWN({})", status),
    }
}

/// GET /api/tracking/overview - Overall statistics
async fn api_overview_handler(State(state): State<MetricsHttpState>) -> Response<Body> {
    let store = &state.store;
    let overall = store.get_overall();
    let protocols = store.get_protocol_stats();
    let uptime = store.uptime_secs();

    let response = ApiOverviewResponse {
        overall: ApiOverviewStats {
            uptime_secs: uptime,
            packets_total: overall.packets_total,
            bytes_total: overall.bytes_total,
            connections_total: overall.connections_total,
            connections_active: overall.connections_active,
            dropped_total: overall.dropped_total,
            routed_total: overall.routed_total,
            unmatched_total: overall.unmatched_total,
            packets_per_second: overall.packets_per_second(uptime),
            bytes_per_second: overall.bytes_per_second(uptime),
            dns_queries_total: overall.dns_queries_total,
            dns_cache_hits: overall.dns_cache_hits,
            dns_cache_misses: overall.dns_cache_misses,
            dns_upstream_switches: overall.dns_upstream_switches,
            dns_errors: overall.dns_errors,
            dns_avg_latency_ms: overall.dns_avg_latency_ms(),
        },
        transport_protocols: ApiTransportProtocolsResponse {
            tcp: ApiProtocolStats {
                protocol: "tcp".to_string(),
                packets: protocols.tcp.packets,
                bytes: protocols.tcp.bytes,
                connections: protocols.tcp.connections,
                active_connections: protocols.tcp.active_connections,
            },
            udp: ApiProtocolStats {
                protocol: "udp".to_string(),
                packets: protocols.udp.packets,
                bytes: protocols.udp.bytes,
                connections: protocols.udp.connections,
                active_connections: protocols.udp.active_connections,
            },
            icmp: ApiProtocolStats {
                protocol: "icmp".to_string(),
                packets: protocols.icmp.packets,
                bytes: protocols.icmp.bytes,
                connections: protocols.icmp.connections,
                active_connections: protocols.icmp.active_connections,
            },
        },
    };

    let json = serde_json::to_string_pretty(&response).unwrap_or_default();
    let mut res = Response::new(Body::from(json));
    res.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    res
}

/// GET /api/tracking/connections - List connections with filtering
async fn api_connections_handler(
    State(state): State<MetricsHttpState>,
    Query(query): Query<ConnectionsQuery>,
) -> Response<Body> {
    let store = &state.store;
    let all_connections = store.connections.get_active();
    let _total_count = all_connections.len();

    // Count active
    let active_count = all_connections
        .iter()
        .filter(|(_, stats)| stats.state != ConnectionState::Closed as u8)
        .count();

    // Apply filters - clone to avoid borrow issues
    let mut filtered: Vec<_> = all_connections.clone().into_iter().collect();

    // Filter by state
    if let Some(ref state_filter) = query.state {
        match state_filter.as_str() {
            "active" => {
                filtered.retain(|(_, stats)| stats.state != ConnectionState::Closed as u8);
            }
            "closed" => {
                filtered.retain(|(_, stats)| stats.state == ConnectionState::Closed as u8);
            }
            "all" => {} // No filter
            _ => {}     // Unknown filter - no filter applied
        }
    }

    // Filter by protocol
    if let Some(ref proto_filter) = query.protocol {
        let proto_num = match proto_filter.to_lowercase().as_str() {
            "tcp" => 6,
            "udp" => 17,
            "icmp" => 1,
            _ => 0,
        };
        if proto_num > 0 {
            filtered.retain(|(key, _)| key.proto == proto_num);
        }
    }

    // Sort
    if let Some(ref sort_by) = query.sort_by {
        match sort_by.as_str() {
            "bytes_in" => filtered.sort_by(|a, b| b.1.bytes_in.cmp(&a.1.bytes_in)),
            "bytes_out" => filtered.sort_by(|a, b| b.1.bytes_out.cmp(&a.1.bytes_out)),
            "last_time" => filtered.sort_by(|a, b| b.1.last_time.cmp(&a.1.last_time)),
            _ => filtered.sort_by(|a, b| b.1.last_time.cmp(&a.1.last_time)),
        }
    } else {
        filtered.sort_by(|a, b| b.1.last_time.cmp(&a.1.last_time));
    }

    // Apply limit
    let limit = query.limit.unwrap_or(100);
    let total_after_filter = filtered.len();
    filtered.truncate(limit);

    // Convert to API format
    let connections: Vec<ApiConnectionInfo> = filtered
        .into_iter()
        .map(|(key, stats)| {
            let now = current_epoch_ms();
            ApiConnectionInfo {
                key: connection_key_to_string(&key),
                src_ip: u32_to_ip(key.src_ip),
                src_port: key.src_port,
                dst_ip: u32_to_ip(key.dst_ip),
                dst_port: key.dst_port,
                proto: key.protocol_name().to_string(),
                packets_in: stats.packets_in,
                packets_out: stats.packets_out,
                bytes_in: stats.bytes_in,
                bytes_out: stats.bytes_out,
                state: connection_state_to_string(stats.state),
                node_id: stats.node_id,
                rule_id: stats.rule_id,
                start_time: stats.start_time,
                last_time: stats.last_time,
                age_ms: now.saturating_sub(stats.start_time),
                idle_ms: now.saturating_sub(stats.last_time),
            }
        })
        .collect();

    let response = ApiConnectionsResponse {
        total: total_after_filter,
        active: active_count,
        connections,
    };

    let json = serde_json::to_string_pretty(&response).unwrap_or_default();
    let mut res = Response::new(Body::from(json));
    res.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    res
}

/// GET /api/tracking/connections/:key - Get specific connection
async fn api_connection_detail_handler(
    State(state): State<MetricsHttpState>,
    Path(key_str): Path<String>,
) -> Response<Body> {
    let store = &state.store;

    // Parse the key string (format: src_ip:port-dst_ip:port-proto)
    let parts: Vec<&str> = key_str.split('-').collect();
    if parts.len() != 3 {
        let error = Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(
                "Invalid key format. Expected: src_ip:port-dst_ip:port-proto",
            ))
            .unwrap();
        return error;
    }

    // Parse source
    let src_parts: Vec<&str> = parts[0].split(':').collect();
    if src_parts.len() != 2 {
        let error = Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Invalid source format. Expected: ip:port"))
            .unwrap();
        return error;
    }

    let src_ip = ip_to_u32(src_parts[0]);
    let src_port: u16 = src_parts[1].parse().unwrap_or(0);

    // Parse destination
    let dst_parts: Vec<&str> = parts[1].split(':').collect();
    if dst_parts.len() != 2 {
        let error = Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Invalid destination format. Expected: ip:port"))
            .unwrap();
        return error;
    }

    let dst_ip = ip_to_u32(dst_parts[0]);
    let dst_port: u16 = dst_parts[1].parse().unwrap_or(0);

    // Parse protocol
    let proto = match parts[2] {
        "TCP" | "tcp" | "6" => 6,
        "UDP" | "udp" | "17" => 17,
        "ICMP" | "icmp" | "1" => 1,
        _ => 0,
    };

    let key = ConnectionKey::new(src_ip, dst_ip, src_port, dst_port, proto);

    // Try to get connection stats
    if let Some(stats) = store.connections.get(&key) {
        let now = current_epoch_ms();
        let info = ApiConnectionInfo {
            key: connection_key_to_string(&key),
            src_ip: u32_to_ip(key.src_ip),
            src_port: key.src_port,
            dst_ip: u32_to_ip(key.dst_ip),
            dst_port: key.dst_port,
            proto: key.protocol_name().to_string(),
            packets_in: stats.packets_in,
            packets_out: stats.packets_out,
            bytes_in: stats.bytes_in,
            bytes_out: stats.bytes_out,
            state: connection_state_to_string(stats.state),
            node_id: stats.node_id,
            rule_id: stats.rule_id,
            start_time: stats.start_time,
            last_time: stats.last_time,
            age_ms: now.saturating_sub(stats.start_time),
            idle_ms: now.saturating_sub(stats.last_time),
        };

        let json = serde_json::to_string_pretty(&info).unwrap_or_default();
        let mut res = Response::new(Body::from(json));
        res.headers_mut().insert(
            "Content-Type",
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        res
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Connection not found"))
            .unwrap()
    }
}

/// Convert IP string to u32
fn ip_to_u32(ip: &str) -> u32 {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return 0;
    }
    let a: u32 = parts[0].parse().unwrap_or(0);
    let b: u32 = parts[1].parse().unwrap_or(0);
    let c: u32 = parts[2].parse().unwrap_or(0);
    let d: u32 = parts[3].parse().unwrap_or(0);
    (a << 24) | (b << 16) | (c << 8) | d
}

/// GET /api/tracking/protocols - Per-protocol breakdown
async fn api_protocols_handler(State(state): State<MetricsHttpState>) -> Response<Body> {
    let store = &state.store;
    let transport_protocols = store.get_protocol_stats();
    let proxy_protocols = store.get_all_protocol_tracking();

    // Transport protocol stats
    let transport = ApiTransportProtocolsResponse {
        tcp: ApiProtocolStats {
            protocol: "tcp".to_string(),
            packets: transport_protocols.tcp.packets,
            bytes: transport_protocols.tcp.bytes,
            connections: transport_protocols.tcp.connections,
            active_connections: transport_protocols.tcp.active_connections,
        },
        udp: ApiProtocolStats {
            protocol: "udp".to_string(),
            packets: transport_protocols.udp.packets,
            bytes: transport_protocols.udp.bytes,
            connections: transport_protocols.udp.connections,
            active_connections: transport_protocols.udp.active_connections,
        },
        icmp: ApiProtocolStats {
            protocol: "icmp".to_string(),
            packets: transport_protocols.icmp.packets,
            bytes: transport_protocols.icmp.bytes,
            connections: transport_protocols.icmp.connections,
            active_connections: transport_protocols.icmp.active_connections,
        },
    };

    // Proxy protocol stats
    let proxy: Vec<ApiProxyProtocolInfo> = proxy_protocols
        .into_values()
        .map(|p| ApiProxyProtocolInfo {
            protocol: p.protocol.clone(),
            bytes_in: p.bytes_in,
            bytes_out: p.bytes_out,
            total_bytes: p.total_bytes(),
            metadata: p.metadata,
        })
        .collect();

    #[derive(Serialize)]
    struct ProtocolsResponse {
        transport: ApiTransportProtocolsResponse,
        proxy: ApiProxyProtocolsResponse,
    }

    let response = ProtocolsResponse {
        transport,
        proxy: ApiProxyProtocolsResponse { protocols: proxy },
    };

    let json = serde_json::to_string_pretty(&response).unwrap_or_default();
    let mut res = Response::new(Body::from(json));
    res.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    res
}

/// GET /api/tracking/rules - Rule match statistics
async fn api_rules_handler(State(state): State<MetricsHttpState>) -> Response<Body> {
    let store = &state.store;
    let all_rules = store.rules.get_all();

    let rules: Vec<ApiRuleStats> = all_rules
        .into_values()
        .map(|r| ApiRuleStats {
            rule_id: r.rule_id,
            rule_type: rule_type_to_string(r.rule_type),
            match_count: r.match_count,
            pass_count: r.pass_count,
            proxy_count: r.proxy_count,
            drop_count: r.drop_count,
            bytes_matched: r.bytes_matched,
        })
        .collect();

    let response = ApiRulesResponse {
        total_rules: rules.len(),
        rules,
    };

    let json = serde_json::to_string_pretty(&response).unwrap_or_default();
    let mut res = Response::new(Body::from(json));
    res.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    res
}

/// GET /api/tracking/nodes - Per-node statistics
async fn api_nodes_handler(State(state): State<MetricsHttpState>) -> Response<Body> {
    let store = &state.store;
    let all_nodes = store.nodes.get_all();

    let nodes: Vec<ApiNodeStats> = all_nodes
        .into_iter()
        .map(|(node_id, n)| ApiNodeStats {
            node_id,
            total_requests: n.total_requests,
            successful_requests: n.successful_requests,
            failed_requests: n.failed_requests,
            bytes_sent: n.bytes_sent,
            bytes_received: n.bytes_received,
            latency_avg_ms: n.latency_avg(),
            latency_p50_ms: n.latency_p50,
            latency_p90_ms: n.latency_p90,
            latency_p99_ms: n.latency_p99,
            success_rate: n.success_rate(),
            status: node_status_to_string(n.status),
        })
        .collect();

    let response = ApiNodesResponse {
        total_nodes: nodes.len(),
        nodes,
    };

    let json = serde_json::to_string_pretty(&response).unwrap_or_default();
    let mut res = Response::new(Body::from(json));
    res.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    res
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
