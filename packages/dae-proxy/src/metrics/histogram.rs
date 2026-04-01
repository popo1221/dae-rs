//! Histogram metrics for dae-proxy
//!
//! Histograms measure distributions of values.

use lazy_static::lazy_static;
use prometheus::{Histogram, HistogramOpts, HistogramVec, Registry};

lazy_static! {
    /// Connection duration in seconds
    pub static ref CONNECTION_DURATION_HISTOGRAM: HistogramVec =
        HistogramVec::new(
            HistogramOpts::new("dae_connection_duration_seconds", "Connection duration in seconds")
                .buckets(vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0]),
            &["protocol"],
        ).unwrap();

    /// Request size in bytes
    pub static ref REQUEST_SIZE_HISTOGRAM: HistogramVec =
        HistogramVec::new(
            HistogramOpts::new("dae_request_size_bytes", "Request size in bytes")
                .buckets(vec![64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0]),
            &["direction"],
        ).unwrap();

    /// Response time in seconds
    pub static ref RESPONSE_TIME_HISTOGRAM: HistogramVec =
        HistogramVec::new(
            HistogramOpts::new("dae_response_time_seconds", "Response time in seconds")
                .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
            &["transport"],
        ).unwrap();

    /// DNS resolution latency in seconds
    pub static ref DNS_RESOLUTION_LATENCY_HISTOGRAM: Histogram =
        Histogram::with_opts(
            HistogramOpts::new("dae_dns_resolution_latency_seconds", "DNS resolution latency in seconds")
                .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
        ).unwrap();

    /// eBPF processing latency in seconds
    pub static ref EBPF_LATENCY_HISTOGRAM: HistogramVec =
        HistogramVec::new(
            HistogramOpts::new("dae_ebpf_latency_seconds", "eBPF processing latency in seconds")
                .buckets(vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01]),
            &["operation"],
        ).unwrap();

    /// Rule matching latency in seconds
    pub static ref RULE_MATCH_LATENCY_HISTOGRAM: Histogram =
        Histogram::with_opts(
            HistogramOpts::new("dae_rule_match_latency_seconds", "Rule matching latency in seconds")
                .buckets(vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005]),
        ).unwrap();

    /// Node latency histogram in seconds
    pub static ref NODE_LATENCY_HISTOGRAM: HistogramVec =
        HistogramVec::new(
            HistogramOpts::new("dae_node_latency_seconds", "Node latency histogram in seconds")
                .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["node_id"],
        ).unwrap();
}

/// Register all histogram metrics with a registry
pub fn register_histograms(registry: &Registry) -> Result<(), prometheus::Error> {
    registry.register(Box::new((*CONNECTION_DURATION_HISTOGRAM).clone()))?;
    registry.register(Box::new((*REQUEST_SIZE_HISTOGRAM).clone()))?;
    registry.register(Box::new((*RESPONSE_TIME_HISTOGRAM).clone()))?;
    registry.register(Box::new(DNS_RESOLUTION_LATENCY_HISTOGRAM.clone()))?;
    registry.register(Box::new((*EBPF_LATENCY_HISTOGRAM).clone()))?;
    registry.register(Box::new(RULE_MATCH_LATENCY_HISTOGRAM.clone()))?;
    registry.register(Box::new((*NODE_LATENCY_HISTOGRAM).clone()))?;
    Ok(())
}

/// Observe connection duration
#[inline]
pub fn observe_connection_duration(protocol: &str, duration_secs: f64) {
    CONNECTION_DURATION_HISTOGRAM.with_label_values(&[protocol]).observe(duration_secs);
}

/// Observe request size
#[inline]
pub fn observe_request_size(direction: &str, bytes: f64) {
    REQUEST_SIZE_HISTOGRAM.with_label_values(&[direction]).observe(bytes);
}

/// Observe response time
#[inline]
pub fn observe_response_time(transport: &str, seconds: f64) {
    RESPONSE_TIME_HISTOGRAM.with_label_values(&[transport]).observe(seconds);
}

/// Observe DNS resolution latency
#[inline]
pub fn observe_dns_latency(seconds: f64) {
    DNS_RESOLUTION_LATENCY_HISTOGRAM.observe(seconds);
}

/// Observe eBPF operation latency
#[inline]
pub fn observe_ebpf_latency(operation: &str, seconds: f64) {
    EBPF_LATENCY_HISTOGRAM.with_label_values(&[operation]).observe(seconds);
}

/// Observe rule match latency
#[inline]
pub fn observe_rule_match_latency(seconds: f64) {
    RULE_MATCH_LATENCY_HISTOGRAM.observe(seconds);
}

/// Observe node latency
#[inline]
pub fn observe_node_latency(node_id: &str, seconds: f64) {
    NODE_LATENCY_HISTOGRAM.with_label_values(&[node_id]).observe(seconds);
}
