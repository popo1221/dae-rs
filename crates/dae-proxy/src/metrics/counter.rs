//! Counter metrics for dae-proxy
//!
//! Counters monotonically increase in value.

use lazy_static::lazy_static;
use prometheus::{IntCounter, IntCounterVec, Opts, Registry};

lazy_static! {
    /// Total connections created
    pub static ref CONNECTION_COUNTER: IntCounter =
        IntCounter::new("dae_connection_total", "Total number of connections created").unwrap();

    /// Bytes sent by transport type
    pub static ref BYTES_SENT_COUNTER: IntCounterVec =
        IntCounterVec::new(Opts::new("dae_bytes_sent_total", "Total bytes sent"), &["transport"]).unwrap();

    /// Bytes received by transport type
    pub static ref BYTES_RECEIVED_COUNTER: IntCounterVec =
        IntCounterVec::new(Opts::new("dae_bytes_received_total", "Total bytes received"), &["transport"]).unwrap();

    /// Rule matches by rule type
    pub static ref RULE_MATCH_COUNTER: IntCounterVec =
        IntCounterVec::new(Opts::new("dae_rule_matches_total", "Total rule matches by type"), &["rule_type"]).unwrap();

    /// DNS resolutions by result
    pub static ref DNS_RESOLUTION_COUNTER: IntCounterVec =
        IntCounterVec::new(Opts::new("dae_dns_resolutions_total", "Total DNS resolutions"), &["result"]).unwrap();

    /// Errors by type
    pub static ref ERROR_COUNTER: IntCounterVec =
        IntCounterVec::new(Opts::new("dae_errors_total", "Total errors by type"), &["error_type"]).unwrap();

    /// Node latency tests performed
    pub static ref NODE_LATENCY_TEST_COUNTER: IntCounter =
        IntCounter::new("dae_node_latency_tests_total", "Total node latency tests performed").unwrap();
}

/// Register all counter metrics with a registry
pub fn register_counters(registry: &Registry) -> Result<(), prometheus::Error> {
    registry.register(Box::new(CONNECTION_COUNTER.clone()))?;
    registry.register(Box::new((*BYTES_SENT_COUNTER).clone()))?;
    registry.register(Box::new((*BYTES_RECEIVED_COUNTER).clone()))?;
    registry.register(Box::new((*RULE_MATCH_COUNTER).clone()))?;
    registry.register(Box::new((*DNS_RESOLUTION_COUNTER).clone()))?;
    registry.register(Box::new((*ERROR_COUNTER).clone()))?;
    registry.register(Box::new(NODE_LATENCY_TEST_COUNTER.clone()))?;
    Ok(())
}

/// Increment connection counter
#[inline]
pub fn inc_connection() {
    CONNECTION_COUNTER.inc();
}

/// Increment bytes sent
#[inline]
pub fn inc_bytes_sent(transport: &str, bytes: u64) {
    BYTES_SENT_COUNTER
        .with_label_values(&[transport])
        .inc_by(bytes);
}

/// Increment bytes received
#[inline]
pub fn inc_bytes_received(transport: &str, bytes: u64) {
    BYTES_RECEIVED_COUNTER
        .with_label_values(&[transport])
        .inc_by(bytes);
}

/// Increment rule match counter
#[inline]
pub fn inc_rule_match(rule_type: &str) {
    RULE_MATCH_COUNTER.with_label_values(&[rule_type]).inc();
}

/// Increment DNS resolution counter
#[inline]
pub fn inc_dns_resolution(result: &str) {
    DNS_RESOLUTION_COUNTER.with_label_values(&[result]).inc();
}

/// Increment error counter
#[inline]
pub fn inc_error(error_type: &str) {
    ERROR_COUNTER.with_label_values(&[error_type]).inc();
}

/// Increment node latency test counter
#[inline]
pub fn inc_node_latency_test() {
    NODE_LATENCY_TEST_COUNTER.inc();
}
