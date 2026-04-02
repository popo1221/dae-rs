//! Gauge metrics for dae-proxy
//!
//! Gauges can go up and down in value.

use lazy_static::lazy_static;
use prometheus::{Gauge, GaugeVec, IntGauge, IntGaugeVec, Opts, Registry};

lazy_static! {
    /// Current number of active connections
    pub static ref ACTIVE_CONNECTIONS_GAUGE: IntGauge =
        IntGauge::new("dae_active_connections", "Current number of active connections").unwrap();

    /// Current number of active TCP connections
    pub static ref ACTIVE_TCP_CONNECTIONS_GAUGE: IntGauge =
        IntGauge::new("dae_active_tcp_connections", "Current number of active TCP connections").unwrap();

    /// Current number of active UDP connections
    pub static ref ACTIVE_UDP_CONNECTIONS_GAUGE: IntGauge =
        IntGauge::new("dae_active_udp_connections", "Current number of active UDP connections").unwrap();

    /// Current connection pool size
    pub static ref CONNECTION_POOL_SIZE_GAUGE: IntGauge =
        IntGauge::new("dae_connection_pool_size", "Current connection pool size").unwrap();

    /// Node count by status
    pub static ref NODE_COUNT_GAUGE: IntGaugeVec =
        IntGaugeVec::new(Opts::new("dae_node_count", "Number of nodes by status"), &["status"]).unwrap();

    /// Node latency in milliseconds
    pub static ref NODE_LATENCY_GAUGE: GaugeVec =
        GaugeVec::new(Opts::new("dae_node_latency_ms", "Node latency in milliseconds"), &["node_id"]).unwrap();

    /// Memory usage in bytes
    pub static ref MEMORY_USAGE_GAUGE: Gauge =
        Gauge::new("dae_memory_usage_bytes", "Memory usage in bytes").unwrap();

    /// eBPF map entries
    pub static ref EBPF_MAP_ENTRIES_GAUGE: IntGaugeVec =
        IntGaugeVec::new(Opts::new("dae_ebpf_map_entries", "Number of entries in eBPF maps"), &["map_name"]).unwrap();
}

/// Register all gauge metrics with a registry
pub fn register_gauges(registry: &Registry) -> Result<(), prometheus::Error> {
    registry.register(Box::new(ACTIVE_CONNECTIONS_GAUGE.clone()))?;
    registry.register(Box::new(ACTIVE_TCP_CONNECTIONS_GAUGE.clone()))?;
    registry.register(Box::new(ACTIVE_UDP_CONNECTIONS_GAUGE.clone()))?;
    registry.register(Box::new(CONNECTION_POOL_SIZE_GAUGE.clone()))?;
    registry.register(Box::new((*NODE_COUNT_GAUGE).clone()))?;
    registry.register(Box::new((*NODE_LATENCY_GAUGE).clone()))?;
    registry.register(Box::new(MEMORY_USAGE_GAUGE.clone()))?;
    registry.register(Box::new((*EBPF_MAP_ENTRIES_GAUGE).clone()))?;
    Ok(())
}

/// Increment active connections
#[inline]
pub fn inc_active_connections() {
    ACTIVE_CONNECTIONS_GAUGE.inc();
}

/// Decrement active connections
#[inline]
pub fn dec_active_connections() {
    ACTIVE_CONNECTIONS_GAUGE.dec();
}

/// Increment active TCP connections
#[inline]
pub fn inc_active_tcp_connections() {
    ACTIVE_TCP_CONNECTIONS_GAUGE.inc();
}

/// Decrement active TCP connections
#[inline]
pub fn dec_active_tcp_connections() {
    ACTIVE_TCP_CONNECTIONS_GAUGE.dec();
}

/// Increment active UDP connections
#[inline]
pub fn inc_active_udp_connections() {
    ACTIVE_UDP_CONNECTIONS_GAUGE.inc();
}

/// Decrement active UDP connections
#[inline]
pub fn dec_active_udp_connections() {
    ACTIVE_UDP_CONNECTIONS_GAUGE.dec();
}

/// Set connection pool size
#[inline]
pub fn set_connection_pool_size(size: i64) {
    CONNECTION_POOL_SIZE_GAUGE.set(size);
}

/// Set node count by status
#[inline]
pub fn set_node_count(status: &str, count: i64) {
    NODE_COUNT_GAUGE.with_label_values(&[status]).set(count);
}

/// Set node latency
#[inline]
pub fn set_node_latency(node_id: &str, latency_ms: f64) {
    NODE_LATENCY_GAUGE
        .with_label_values(&[node_id])
        .set(latency_ms);
}

/// Set memory usage
#[inline]
pub fn set_memory_usage(bytes: f64) {
    MEMORY_USAGE_GAUGE.set(bytes);
}

/// Set eBPF map entries
#[inline]
pub fn set_ebpf_map_entries(map_name: &str, entries: i64) {
    EBPF_MAP_ENTRIES_GAUGE
        .with_label_values(&[map_name])
        .set(entries);
}
