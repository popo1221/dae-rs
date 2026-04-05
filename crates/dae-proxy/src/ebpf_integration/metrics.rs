//! eBPF Map Performance Metrics
//!
//! Provides [`EbpfMapMetrics`] for tracking operation counts and [`EbpfMapMetricsSnapshot`] for point-in-time snapshots.

use std::sync::atomic::{AtomicU64, Ordering};

// ============================================
// eBPF Map Performance Metrics
// ============================================

/// Performance metrics for eBPF map operations
///
/// Tracks operation counts for monitoring and debugging.
#[derive(Debug, Default)]
pub struct EbpfMapMetrics {
    /// Total session map lookups
    pub session_lookups: AtomicU64,
    /// Total session map inserts
    pub session_inserts: AtomicU64,
    /// Total session map removals
    pub session_removes: AtomicU64,
    /// Session lookup cache hits (found)
    pub session_hits: AtomicU64,
    /// Session lookup cache misses (not found)
    pub session_misses: AtomicU64,
    /// Total routing map lookups
    pub routing_lookups: AtomicU64,
    /// Total routing map inserts
    pub routing_inserts: AtomicU64,
    /// Routing lookup cache hits
    pub routing_hits: AtomicU64,
    /// Routing lookup cache misses
    pub routing_misses: AtomicU64,
    /// Total stats increments
    pub stats_increments: AtomicU64,
}

impl Clone for EbpfMapMetrics {
    fn clone(&self) -> Self {
        Self {
            session_lookups: AtomicU64::new(self.session_lookups.load(Ordering::Relaxed)),
            session_inserts: AtomicU64::new(self.session_inserts.load(Ordering::Relaxed)),
            session_removes: AtomicU64::new(self.session_removes.load(Ordering::Relaxed)),
            session_hits: AtomicU64::new(self.session_hits.load(Ordering::Relaxed)),
            session_misses: AtomicU64::new(self.session_misses.load(Ordering::Relaxed)),
            routing_lookups: AtomicU64::new(self.routing_lookups.load(Ordering::Relaxed)),
            routing_inserts: AtomicU64::new(self.routing_inserts.load(Ordering::Relaxed)),
            routing_hits: AtomicU64::new(self.routing_hits.load(Ordering::Relaxed)),
            routing_misses: AtomicU64::new(self.routing_misses.load(Ordering::Relaxed)),
            stats_increments: AtomicU64::new(self.stats_increments.load(Ordering::Relaxed)),
        }
    }
}

impl EbpfMapMetrics {
    /// Create new metrics counter
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a session lookup
    pub fn record_session_lookup(&self, found: bool) {
        self.session_lookups.fetch_add(1, Ordering::Relaxed);
        if found {
            self.session_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.session_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a session insert
    pub fn record_session_insert(&self) {
        self.session_inserts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a session remove
    pub fn record_session_remove(&self) {
        self.session_removes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a routing lookup
    pub fn record_routing_lookup(&self, found: bool) {
        self.routing_lookups.fetch_add(1, Ordering::Relaxed);
        if found {
            self.routing_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.routing_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a routing insert
    pub fn record_routing_insert(&self) {
        self.routing_inserts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a stats increment
    pub fn record_stats_increment(&self) {
        self.stats_increments.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of current metrics
    pub fn snapshot(&self) -> EbpfMapMetricsSnapshot {
        EbpfMapMetricsSnapshot {
            session_lookups: self.session_lookups.load(Ordering::Relaxed),
            session_inserts: self.session_inserts.load(Ordering::Relaxed),
            session_removes: self.session_removes.load(Ordering::Relaxed),
            session_hits: self.session_hits.load(Ordering::Relaxed),
            session_misses: self.session_misses.load(Ordering::Relaxed),
            routing_lookups: self.routing_lookups.load(Ordering::Relaxed),
            routing_inserts: self.routing_inserts.load(Ordering::Relaxed),
            routing_hits: self.routing_hits.load(Ordering::Relaxed),
            routing_misses: self.routing_misses.load(Ordering::Relaxed),
            stats_increments: self.stats_increments.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of eBPF map metrics at a point in time
#[derive(Debug, Clone)]
pub struct EbpfMapMetricsSnapshot {
    pub session_lookups: u64,
    pub session_inserts: u64,
    pub session_removes: u64,
    pub session_hits: u64,
    pub session_misses: u64,
    pub routing_lookups: u64,
    pub routing_inserts: u64,
    pub routing_hits: u64,
    pub routing_misses: u64,
    pub stats_increments: u64,
}

impl EbpfMapMetricsSnapshot {
    /// Calculate session lookup hit rate
    pub fn session_hit_rate(&self) -> f64 {
        let total = self.session_hits + self.session_misses;
        if total == 0 {
            0.0
        } else {
            self.session_hits as f64 / total as f64
        }
    }

    /// Calculate routing lookup hit rate
    pub fn routing_hit_rate(&self) -> f64 {
        let total = self.routing_hits + self.routing_misses;
        if total == 0 {
            0.0
        } else {
            self.routing_hits as f64 / total as f64
        }
    }
}
