//! Control interface metrics helpers
//!
//! Helper functions for retrieving metrics from Prometheus counters.

use crate::control_types::LegacyOverallStats;
use crate::metrics::{BYTES_RECEIVED_COUNTER, BYTES_SENT_COUNTER, CONNECTION_COUNTER};

/// Get overall stats from Prometheus metrics (fallback when no tracking store)
pub fn get_overall_from_metrics() -> LegacyOverallStats {
    LegacyOverallStats {
        connections_total: CONNECTION_COUNTER.get(),
        bytes_in: get_bytes_received_total(),
        bytes_out: get_bytes_sent_total(),
        rules_hit: 0,    // Would need RULE_MATCH_COUNTER sum
        nodes_tested: 0, // Would need NODE_LATENCY_TEST_COUNTER
    }
}

/// Get total bytes received from metrics
pub fn get_bytes_received_total() -> u64 {
    // Sum across all transport labels
    BYTES_RECEIVED_COUNTER.with_label_values(&["all"]).get()
}

/// Get total bytes sent from metrics
pub fn get_bytes_sent_total() -> u64 {
    BYTES_SENT_COUNTER.with_label_values(&["all"]).get()
}
