//! Tracking metrics for dae-proxy
//!
//! Prometheus metrics derived from TrackingStore data.
//!
//! This module provides counters, gauges, and histograms that track:
//! - Connection state transitions (New, Established, Closing, Closed)
//! - Per-protocol bytes (TCP, UDP, VLESS, VMess, Trojan, Shadowsocks, HTTP)
//! - Per-node traffic
//! - Per-rule match counts (by rule_type and action)

use lazy_static::lazy_static;
use prometheus::{IntCounter, IntCounterVec, IntGauge, Opts, Registry};

lazy_static! {
    // ========================================================================
    // Connection State Metrics
    // ========================================================================

    /// Total connections by final state
    pub static ref CONNECTION_STATE_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("dae_tracking_connections_total", "Total connections by final state"),
        &["state"],
    ).unwrap();

    /// Active connections gauge (mirrors dae_active_connections but keyed by transport)
    pub static ref TRACKING_ACTIVE_CONNECTIONS_GAUGE: IntGauge = IntGauge::new(
        "dae_tracking_active_connections",
        "Current number of tracked active connections",
    ).unwrap();

    // ========================================================================
    // Per-Transport (TCP/UDP) Bytes Metrics
    // ========================================================================

    /// Inbound bytes by transport protocol
    pub static ref TRACKING_BYTES_IN_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("dae_tracking_bytes_in_total", "Total inbound bytes by transport"),
        &["transport"],
    ).unwrap();

    /// Outbound bytes by transport protocol
    pub static ref TRACKING_BYTES_OUT_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("dae_tracking_bytes_out_total", "Total outbound bytes by transport"),
        &["transport"],
    ).unwrap();

    /// Packets by transport protocol
    pub static ref TRACKING_PACKETS_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("dae_tracking_packets_total", "Total packets by transport"),
        &["transport"],
    ).unwrap();

    // ========================================================================
    // Per-Proxy-Protocol (VLESS/VMess/Trojan/etc.) Metrics
    // ========================================================================

    /// Inbound bytes by proxy protocol
    pub static ref PROXY_PROTOCOL_BYTES_IN_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("dae_proxy_protocol_bytes_in_total", "Total inbound bytes by proxy protocol"),
        &["protocol"],
    ).unwrap();

    /// Outbound bytes by proxy protocol
    pub static ref PROXY_PROTOCOL_BYTES_OUT_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("dae_proxy_protocol_bytes_out_total", "Total outbound bytes by proxy protocol"),
        &["protocol"],
    ).unwrap();

    /// Connections by proxy protocol
    pub static ref PROXY_PROTOCOL_CONNECTIONS_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("dae_proxy_protocol_connections_total", "Total connections by proxy protocol"),
        &["protocol"],
    ).unwrap();

    // ========================================================================
    // Per-Node Traffic Metrics
    // ========================================================================

    /// Inbound bytes by node
    pub static ref NODE_BYTES_IN_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("dae_node_bytes_in_total", "Total inbound bytes by node"),
        &["node_id"],
    ).unwrap();

    /// Outbound bytes by node
    pub static ref NODE_BYTES_OUT_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("dae_node_bytes_out_total", "Total outbound bytes by node"),
        &["node_id"],
    ).unwrap();

    /// Requests by node
    pub static ref NODE_REQUESTS_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("dae_node_requests_total", "Total requests by node"),
        &["node_id"],
    ).unwrap();

    // ========================================================================
    // Rule Match Metrics
    // ========================================================================

    /// Rule match count by rule type
    pub static ref RULE_MATCH_BY_TYPE_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("dae_rule_matches_by_type_total", "Total rule matches by rule type"),
        &["rule_type"],
    ).unwrap();

    /// Rule match count by action taken
    pub static ref RULE_MATCH_BY_ACTION_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("dae_rule_matches_by_action_total", "Total rule matches by action"),
        &["action"],
    ).unwrap();

    /// Rule match bytes by rule type
    pub static ref RULE_MATCH_BYTES_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("dae_rule_match_bytes_total", "Total bytes matched by rule type"),
        &["rule_type"],
    ).unwrap();

    // ========================================================================
    // Overall Stats Metrics
    // ========================================================================

    /// Total dropped packets
    pub static ref DROPPED_COUNTER: IntCounter = IntCounter::new(
        "dae_tracking_dropped_total",
        "Total dropped packets",
    ).unwrap();

    /// Total routed packets
    pub static ref ROUTED_COUNTER: IntCounter = IntCounter::new(
        "dae_tracking_routed_total",
        "Total routed packets",
    ).unwrap();

    /// Total unmatched packets
    pub static ref UNMATCHED_COUNTER: IntCounter = IntCounter::new(
        "dae_tracking_unmatched_total",
        "Total unmatched packets",
    ).unwrap();
}

/// Register all tracking metrics with a registry
pub fn register_tracking_metrics(registry: &Registry) -> Result<(), prometheus::Error> {
    registry.register(Box::new(CONNECTION_STATE_COUNTER.clone()))?;
    registry.register(Box::new(TRACKING_ACTIVE_CONNECTIONS_GAUGE.clone()))?;
    registry.register(Box::new((*TRACKING_BYTES_IN_COUNTER).clone()))?;
    registry.register(Box::new((*TRACKING_BYTES_OUT_COUNTER).clone()))?;
    registry.register(Box::new((*TRACKING_PACKETS_COUNTER).clone()))?;
    registry.register(Box::new((*PROXY_PROTOCOL_BYTES_IN_COUNTER).clone()))?;
    registry.register(Box::new((*PROXY_PROTOCOL_BYTES_OUT_COUNTER).clone()))?;
    registry.register(Box::new((*PROXY_PROTOCOL_CONNECTIONS_COUNTER).clone()))?;
    registry.register(Box::new((*NODE_BYTES_IN_COUNTER).clone()))?;
    registry.register(Box::new((*NODE_BYTES_OUT_COUNTER).clone()))?;
    registry.register(Box::new((*NODE_REQUESTS_COUNTER).clone()))?;
    registry.register(Box::new((*RULE_MATCH_BY_TYPE_COUNTER).clone()))?;
    registry.register(Box::new((*RULE_MATCH_BY_ACTION_COUNTER).clone()))?;
    registry.register(Box::new((*RULE_MATCH_BYTES_COUNTER).clone()))?;
    registry.register(Box::new(DROPPED_COUNTER.clone()))?;
    registry.register(Box::new(ROUTED_COUNTER.clone()))?;
    registry.register(Box::new(UNMATCHED_COUNTER.clone()))?;
    Ok(())
}

// ========================================================================
// Helper functions to convert enums to string labels
// ========================================================================

/// Get connection state name from u8 value
#[inline]
pub fn connection_state_name(state: u8) -> &'static str {
    match state {
        0 => "new",
        1 => "established",
        2 => "closing",
        3 => "closed",
        _ => "unknown",
    }
}

/// Get transport name from protocol number
#[inline]
pub fn transport_name(proto: u8) -> &'static str {
    match proto {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        _ => "other",
    }
}

/// Get rule type name from u8 value
#[inline]
pub fn rule_type_name(rule_type: u8) -> &'static str {
    match rule_type {
        0 => "domain",
        1 => "domain_suffix",
        2 => "domain_keyword",
        3 => "ip_cidr",
        4 => "geoip",
        5 => "process",
        _ => "unknown",
    }
}

/// Get rule action name from u8 value
#[inline]
pub fn rule_action_name(action: u8) -> &'static str {
    match action {
        0 => "pass",
        1 => "proxy",
        2 => "drop",
        3 => "default",
        4 => "direct",
        5 => "must_direct",
        _ => "unknown",
    }
}

// ========================================================================
// Metrics update functions (to be called from TrackingStore)
// ========================================================================

/// Record connection state transition
#[inline]
pub fn inc_connection_state(state: u8) {
    CONNECTION_STATE_COUNTER
        .with_label_values(&[connection_state_name(state)])
        .inc();
}

/// Set active connections gauge
#[inline]
pub fn set_active_connections(count: i64) {
    TRACKING_ACTIVE_CONNECTIONS_GAUGE.set(count);
}

/// Increment bytes in for a transport
#[inline]
pub fn inc_tracking_bytes_in(transport: &str, bytes: u64) {
    TRACKING_BYTES_IN_COUNTER
        .with_label_values(&[transport])
        .inc_by(bytes);
}

/// Increment bytes out for a transport
#[inline]
pub fn inc_tracking_bytes_out(transport: &str, bytes: u64) {
    TRACKING_BYTES_OUT_COUNTER
        .with_label_values(&[transport])
        .inc_by(bytes);
}

/// Increment packets for a transport
#[inline]
pub fn inc_tracking_packets(transport: &str) {
    TRACKING_PACKETS_COUNTER
        .with_label_values(&[transport])
        .inc();
}

/// Increment proxy protocol bytes in
#[inline]
pub fn inc_proxy_protocol_bytes_in(protocol: &str, bytes: u64) {
    PROXY_PROTOCOL_BYTES_IN_COUNTER
        .with_label_values(&[protocol])
        .inc_by(bytes);
}

/// Increment proxy protocol bytes out
#[inline]
pub fn inc_proxy_protocol_bytes_out(protocol: &str, bytes: u64) {
    PROXY_PROTOCOL_BYTES_OUT_COUNTER
        .with_label_values(&[protocol])
        .inc_by(bytes);
}

/// Increment proxy protocol connections
#[inline]
pub fn inc_proxy_protocol_connection(protocol: &str) {
    PROXY_PROTOCOL_CONNECTIONS_COUNTER
        .with_label_values(&[protocol])
        .inc();
}

/// Increment node bytes in
#[inline]
pub fn inc_node_bytes_in(node_id: u32, bytes: u64) {
    NODE_BYTES_IN_COUNTER
        .with_label_values(&[&node_id.to_string()])
        .inc_by(bytes);
}

/// Increment node bytes out
#[inline]
pub fn inc_node_bytes_out(node_id: u32, bytes: u64) {
    NODE_BYTES_OUT_COUNTER
        .with_label_values(&[&node_id.to_string()])
        .inc_by(bytes);
}

/// Increment node requests
#[inline]
pub fn inc_node_requests(node_id: u32) {
    NODE_REQUESTS_COUNTER
        .with_label_values(&[&node_id.to_string()])
        .inc();
}

/// Increment rule match by type
#[inline]
pub fn inc_rule_match_by_type(rule_type: u8) {
    RULE_MATCH_BY_TYPE_COUNTER
        .with_label_values(&[rule_type_name(rule_type)])
        .inc();
}

/// Increment rule match by action
#[inline]
pub fn inc_rule_match_by_action(action: u8) {
    RULE_MATCH_BY_ACTION_COUNTER
        .with_label_values(&[rule_action_name(action)])
        .inc();
}

/// Increment rule match bytes
#[inline]
pub fn inc_rule_match_bytes(rule_type: u8, bytes: u64) {
    RULE_MATCH_BYTES_COUNTER
        .with_label_values(&[rule_type_name(rule_type)])
        .inc_by(bytes);
}

/// Record dropped packets
#[inline]
pub fn inc_dropped(count: u64) {
    DROPPED_COUNTER.inc_by(count);
}

/// Record routed packets
#[inline]
pub fn inc_routed(count: u64) {
    ROUTED_COUNTER.inc_by(count);
}

/// Record unmatched packets
#[inline]
pub fn inc_unmatched(count: u64) {
    UNMATCHED_COUNTER.inc_by(count);
}
