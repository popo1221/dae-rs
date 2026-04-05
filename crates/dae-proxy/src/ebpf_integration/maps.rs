//! eBPF Map Handles
//!
//! Provides in-memory HashMap implementations for session, routing, and stats maps
//! as a fallback when aya BPF maps are not available.

use crate::connection_pool::ConnectionKey;
use crate::ebpf_integration::config::EbpfMapConfig;
use crate::ebpf_integration::metrics::EbpfMapMetrics;
use dae_ebpf_common::routing::RoutingEntry;
use dae_ebpf_common::session::SessionEntry;
use dae_ebpf_common::stats::StatsEntry;
use std::collections::HashMap;

use std::sync::{Arc, RwLock as StdRwLock};
use tracing::debug;

// Note: Result is used via crate::ebpf_integration::Result full path in methods

/// eBPF map handles wrapper
///
/// Provides in-memory map implementations as a fallback when aya BPF maps
/// are not available. For production with kernel BPF, use `EbpfContext`.
#[derive(Clone)]
pub struct EbpfMaps {
    /// Session map handle
    pub sessions: Option<SessionMapHandle>,
    /// Routing map handle
    pub routing: Option<RoutingMapHandle>,
    /// Stats map handle
    pub stats: Option<StatsMapHandle>,
    /// Whether using real eBPF or in-memory fallback
    is_real_ebpf: bool,
    /// Map configuration
    config: EbpfMapConfig,
    /// Performance metrics
    metrics: EbpfMapMetrics,
}

impl EbpfMaps {
    /// Create new eBPF maps wrapper with in-memory HashMap backends
    ///
    /// Uses default [`EbpfMapConfig`] with moderate capacity limits.
    pub fn new_in_memory() -> Self {
        Self::new_in_memory_with_config(EbpfMapConfig::default())
    }

    /// Create new eBPF maps wrapper with custom configuration
    ///
    /// # Arguments
    /// * `config` - Map size and capacity configuration
    pub fn new_in_memory_with_config(config: EbpfMapConfig) -> Self {
        Self {
            sessions: Some(SessionMapHandle::with_capacity(config.session_capacity)),
            routing: Some(RoutingMapHandle::with_capacity(config.routing_capacity)),
            stats: Some(StatsMapHandle::with_capacity(config.stats_capacity)),
            is_real_ebpf: false,
            config,
            metrics: EbpfMapMetrics::new(),
        }
    }

    /// Create new eBPF maps wrapper (legacy, creates None stubs)
    pub fn new() -> Self {
        Self {
            sessions: None,
            routing: None,
            stats: None,
            is_real_ebpf: false,
            config: EbpfMapConfig::default(),
            metrics: EbpfMapMetrics::new(),
        }
    }

    /// Check if all maps are initialized
    pub fn is_initialized(&self) -> bool {
        self.sessions.is_some() && self.routing.is_some() && self.stats.is_some()
    }

    /// Check if using real eBPF (vs in-memory fallback)
    pub fn is_real_ebpf(&self) -> bool {
        self.is_real_ebpf
    }

    /// Mark as real eBPF mode
    pub(crate) fn set_real_ebpf(&mut self) {
        self.is_real_ebpf = true;
    }

    /// Get the map configuration
    pub fn config(&self) -> &EbpfMapConfig {
        &self.config
    }

    /// Get performance metrics
    pub fn metrics(&self) -> &EbpfMapMetrics {
        &self.metrics
    }

    /// Get metrics snapshot
    pub fn metrics_snapshot(&self) -> super::EbpfMapMetricsSnapshot {
        self.metrics.snapshot()
    }
}

impl Default for EbpfMaps {
    fn default() -> Self {
        Self::new()
    }
}

/// Session map handle wrapper — in-memory HashMap implementation
///
/// Uses `Arc<StdRwLock<HashMap>>` for concurrent access and cloneability.
/// Suitable for user-space proxying. For kernel BPF integration,
/// replace with aya `HashMap`.
#[derive(Clone)]
pub struct SessionMapHandle {
    inner: Arc<StdRwLock<HashMap<ConnectionKey, SessionEntry>>>,
}

impl SessionMapHandle {
    /// Create a new session map handle with default capacity
    pub fn new() -> Self {
        Self::with_capacity(1024)
    }

    /// Create a new session map handle with specified capacity
    ///
    /// # Arguments
    /// * `capacity` - Initial HashMap capacity hint
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(StdRwLock::new(HashMap::with_capacity(capacity))),
        }
    }

    /// Insert or update a session
    pub fn insert(
        &self,
        key: &ConnectionKey,
        value: &SessionEntry,
    ) -> crate::ebpf_integration::Result<()> {
        let mut map = self.inner.write().unwrap();
        map.insert(*key, *value);
        debug!("Session insert: {:?} state={}", key, value.state);
        Ok(())
    }

    /// Lookup a session by key
    pub fn lookup(
        &self,
        key: &ConnectionKey,
    ) -> crate::ebpf_integration::Result<Option<SessionEntry>> {
        let map = self.inner.read().unwrap();
        Ok(map.get(key).copied())
    }

    /// Remove a session
    #[allow(dead_code)]
    pub fn remove(&self, key: &ConnectionKey) -> crate::ebpf_integration::Result<()> {
        let mut map = self.inner.write().unwrap();
        map.remove(key);
        debug!("Session remove: {:?}", key);
        Ok(())
    }

    /// Get the number of active sessions
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    /// Check if the map is empty
    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }
}

impl Default for SessionMapHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Routing map handle wrapper — in-memory HashMap implementation
///
/// Uses `Arc<StdRwLock<HashMap>>` for concurrent access and cloneability.
/// Note: this is a simple exact-match map, not an LPM (Longest Prefix Match)
/// Trie. For proper CIDR routing rules, use `EbpfContext` with real eBPF.
#[derive(Clone)]
pub struct RoutingMapHandle {
    inner: Arc<StdRwLock<HashMap<u32, RoutingEntry>>>,
}

impl RoutingMapHandle {
    /// Create a new routing map handle with default capacity
    pub fn new() -> Self {
        Self::with_capacity(256)
    }

    /// Create a new routing map handle with specified capacity
    ///
    /// # Arguments
    /// * `capacity` - Initial HashMap capacity hint
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(StdRwLock::new(HashMap::with_capacity(capacity))),
        }
    }

    /// Insert a routing entry
    pub fn insert(&self, ip: u32, entry: RoutingEntry) -> crate::ebpf_integration::Result<()> {
        let mut map = self.inner.write().unwrap();
        map.insert(ip, entry);
        debug!("Routing insert: IP {:x}", ip);
        Ok(())
    }

    /// Lookup routing for an IP address (exact match)
    pub fn lookup(&self, ip: u32) -> crate::ebpf_integration::Result<Option<RoutingEntry>> {
        let map = self.inner.read().unwrap();
        Ok(map.get(&ip).copied())
    }

    /// Remove a routing entry
    #[allow(dead_code)]
    pub fn remove(&self, ip: u32) -> crate::ebpf_integration::Result<()> {
        let mut map = self.inner.write().unwrap();
        map.remove(&ip);
        debug!("Routing remove: IP {:x}", ip);
        Ok(())
    }

    /// Get the number of routing entries
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    /// Check if the routing map is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for RoutingMapHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Stats map handle wrapper — in-memory HashMap implementation
///
/// Uses `Arc<StdRwLock<HashMap>>` for concurrent access and cloneability.
/// Note: stats counters are updated under write lock, which may cause
/// contention under very high concurrency. For production, consider atomic
/// counters or PerCPU maps (as in real aya BPF maps).
#[derive(Clone)]
pub struct StatsMapHandle {
    inner: Arc<StdRwLock<HashMap<u32, StatsEntry>>>,
}

impl StatsMapHandle {
    /// Create a new stats map handle with default capacity
    pub fn new() -> Self {
        Self::with_capacity(32)
    }

    /// Create a new stats map handle with specified capacity
    ///
    /// # Arguments
    /// * `capacity` - Initial HashMap capacity hint
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(StdRwLock::new(HashMap::with_capacity(capacity))),
        }
    }

    /// Increment a stats counter
    pub fn increment(&self, idx: u32, bytes: u64) -> crate::ebpf_integration::Result<()> {
        let mut map = self.inner.write().unwrap();
        let entry = map.entry(idx).or_default();
        entry.bytes += bytes;
        entry.packets += 1;
        debug!(
            "Stats increment: idx={}, bytes={}, total_bytes={}",
            idx, bytes, entry.bytes
        );
        Ok(())
    }

    /// Get stats for an index
    pub fn get(&self, idx: u32) -> crate::ebpf_integration::Result<Option<StatsEntry>> {
        let map = self.inner.read().unwrap();
        Ok(map.get(&idx).copied())
    }

    /// Set a stats entry directly (for bulk updates)
    pub fn set(&self, idx: u32, entry: StatsEntry) -> crate::ebpf_integration::Result<()> {
        let mut map = self.inner.write().unwrap();
        map.insert(idx, entry);
        Ok(())
    }

    /// Get all stats as a HashMap snapshot
    pub fn get_all(&self) -> HashMap<u32, StatsEntry> {
        self.inner.read().unwrap().clone()
    }

    /// Get the number of stats entries
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    /// Check if the map is empty
    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }
}

impl Default for StatsMapHandle {
    fn default() -> Self {
        Self::new()
    }
}
