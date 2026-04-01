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

// Re-export counter functions
pub use counter::{
    inc_connection, inc_bytes_sent, inc_bytes_received,
    inc_rule_match, inc_dns_resolution, inc_error, inc_node_latency_test,
    CONNECTION_COUNTER, BYTES_SENT_COUNTER, BYTES_RECEIVED_COUNTER,
    RULE_MATCH_COUNTER, DNS_RESOLUTION_COUNTER, ERROR_COUNTER, NODE_LATENCY_TEST_COUNTER,
};

// Re-export gauge functions
pub use gauge::{
    inc_active_connections, dec_active_connections,
    inc_active_tcp_connections, dec_active_tcp_connections,
    inc_active_udp_connections, dec_active_udp_connections,
    set_connection_pool_size, set_node_count, set_node_latency,
    set_memory_usage, set_ebpf_map_entries,
    ACTIVE_CONNECTIONS_GAUGE, ACTIVE_TCP_CONNECTIONS_GAUGE,
    ACTIVE_UDP_CONNECTIONS_GAUGE, CONNECTION_POOL_SIZE_GAUGE,
    NODE_COUNT_GAUGE, NODE_LATENCY_GAUGE, MEMORY_USAGE_GAUGE, EBPF_MAP_ENTRIES_GAUGE,
};

// Re-export histogram functions
pub use histogram::{
    observe_connection_duration, observe_request_size,
    observe_response_time, observe_dns_latency,
    observe_ebpf_latency, observe_rule_match_latency, observe_node_latency,
    CONNECTION_DURATION_HISTOGRAM, REQUEST_SIZE_HISTOGRAM,
    RESPONSE_TIME_HISTOGRAM, DNS_RESOLUTION_LATENCY_HISTOGRAM,
    EBPF_LATENCY_HISTOGRAM, RULE_MATCH_LATENCY_HISTOGRAM, NODE_LATENCY_HISTOGRAM,
};

// Re-export prometheus server
pub use prometheus::{MetricsServer, start_metrics_server, stop_metrics_server};
