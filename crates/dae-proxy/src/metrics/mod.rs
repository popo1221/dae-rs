//! Metrics module for dae-proxy
//!
//! Provides Prometheus-compatible metrics collection and export.
//!
//! # Metrics
//!
//! - `dae_connection_total`: Total number of connections created (Counter)
//! - `dae_active_connections`: Current number of active connections (Gauge)
//! - `dae_bytes_sent_total`: Total bytes sent (Counter)
//! - `dae_bytes_received_total`: Total bytes received (Counter)
//! - `dae_connection_duration_seconds`: Connection duration histogram (Histogram)
//! - `dae_rule_matches_total`: Total rule matches by rule type (Counter)

pub mod counter;
pub mod gauge;
pub mod histogram;
pub mod prometheus;
pub mod tracking;

// Re-export counter functions
pub use counter::{
    inc_bytes_received, inc_bytes_sent, inc_connection, inc_dns_resolution, inc_error,
    inc_node_latency_test, inc_rule_match, BYTES_RECEIVED_COUNTER, BYTES_SENT_COUNTER,
    CONNECTION_COUNTER, DNS_RESOLUTION_COUNTER, ERROR_COUNTER, NODE_LATENCY_TEST_COUNTER,
    RULE_MATCH_COUNTER,
};

// Re-export gauge functions
pub use gauge::{
    dec_active_connections, dec_active_tcp_connections, dec_active_udp_connections,
    inc_active_connections, inc_active_tcp_connections, inc_active_udp_connections,
    set_connection_pool_size, set_ebpf_map_entries, set_memory_usage, set_node_count,
    set_node_latency, ACTIVE_CONNECTIONS_GAUGE, ACTIVE_TCP_CONNECTIONS_GAUGE,
    ACTIVE_UDP_CONNECTIONS_GAUGE, CONNECTION_POOL_SIZE_GAUGE, EBPF_MAP_ENTRIES_GAUGE,
    MEMORY_USAGE_GAUGE, NODE_COUNT_GAUGE, NODE_LATENCY_GAUGE,
};

// Re-export histogram functions
pub use histogram::{
    observe_connection_duration, observe_dns_latency, observe_ebpf_latency, observe_node_latency,
    observe_request_size, observe_response_time, observe_rule_match_latency,
    CONNECTION_DURATION_HISTOGRAM, DNS_RESOLUTION_LATENCY_HISTOGRAM, EBPF_LATENCY_HISTOGRAM,
    NODE_LATENCY_HISTOGRAM, REQUEST_SIZE_HISTOGRAM, RESPONSE_TIME_HISTOGRAM,
    RULE_MATCH_LATENCY_HISTOGRAM,
};

// Re-export prometheus server
pub use prometheus::{start_metrics_server, stop_metrics_server, MetricsServer};

// Re-export tracking metrics functions
pub use tracking::{
    connection_state_name, inc_connection_state, inc_dropped, inc_node_bytes_in,
    inc_node_bytes_out, inc_proxy_protocol_bytes_in, inc_proxy_protocol_bytes_out,
    inc_proxy_protocol_connection, inc_routed, inc_rule_match_by_action, inc_rule_match_by_type,
    inc_rule_match_bytes, inc_tracking_bytes_in, inc_tracking_bytes_out, inc_tracking_packets,
    inc_unmatched, register_tracking_metrics, rule_action_name, rule_type_name,
    set_active_connections, transport_name, CONNECTION_STATE_COUNTER, DROPPED_COUNTER,
    NODE_BYTES_IN_COUNTER, NODE_BYTES_OUT_COUNTER, NODE_REQUESTS_COUNTER,
    PROXY_PROTOCOL_BYTES_IN_COUNTER, PROXY_PROTOCOL_BYTES_OUT_COUNTER,
    PROXY_PROTOCOL_CONNECTIONS_COUNTER, ROUTED_COUNTER, RULE_MATCH_BYTES_COUNTER,
    RULE_MATCH_BY_ACTION_COUNTER, RULE_MATCH_BY_TYPE_COUNTER, TRACKING_ACTIVE_CONNECTIONS_GAUGE,
    TRACKING_BYTES_IN_COUNTER, TRACKING_BYTES_OUT_COUNTER, TRACKING_PACKETS_COUNTER,
    UNMATCHED_COUNTER,
};
