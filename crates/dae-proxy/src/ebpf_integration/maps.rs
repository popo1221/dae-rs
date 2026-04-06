//! eBPF Map Handles — In-Memory HashMap Stubs
//!
//! This module provides **in-memory HashMap implementations** as a fallback when
//! real eBPF maps (via the `aya` crate) are not available or not needed.
//!
//! # When to Use Each Backend
//!
//! | Scenario | Recommended Backend | Implementation |
//! |----------|---------------------|------------------|
//! | Development / Testing | `EbpfMaps::new_in_memory()` | In-memory HashMap (this module) |
//! | User-space proxy (no kernel BPF) | `EbpfMaps::new_in_memory()` | In-memory HashMap (this module) |
//! | Production with kernel BPF | `EbpfContext` | Real aya eBPF maps |
//!
//! # Limitations of In-Memory HashMap Stubs
//!
//! These in-memory implementations are **not** suitable for production with
//! kernel eBPF because they:
//!
//! 1. **Do not share state with the kernel** — kernel BPF programs cannot read
//!    /write these maps; data stays entirely in user space.
//!
//! 2. **RoutingMapHandle uses exact-match** — The in-memory routing map performs
//!    exact IP matching (`HashMap<u32, RoutingEntry>`), not LPM (Longest Prefix
//!    Match). Proper CIDR routing (e.g., `10.0.0.0/8 → PASS`) requires a real
//!    aya [`LpmTrie`] map in `EbpfContext`.
//!
//! 3. **StatsMapHandle uses write locks** — Stats counters are updated under a
//!    [`StdRwLock`], which causes lock contention under high concurrency.
//!    Production should use aya [`PerCpuArray`] for per-CPU atomic counters.
//!
//! 4. **SessionMapHandle is process-local** — Sessions are not shared across
//!    processes or with kernel BPF programs.
//!
//! # Feature Flags
//!
//! - `ebpf` feature: Enables `EbpfContext` and real aya eBPF integration.
//!   When disabled (default), only in-memory stubs are available.
//!
//! [`LpmTrie`]: <https://docs.rs/aya/latest/aya/maps/lpm_trie/struct.LpmTrie.html>
//! [`PerCpuArray`]: <https://docs.rs/aya/latest/aya/maps/per_cpu_array/struct.PerCpuArray.html>

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

/// eBPF map handles wrapper — in-memory HashMap stubs.
///
/// This struct holds handles to session, routing, and stats maps. The
/// constructors on this struct (`new_in_memory`, `new_in_memory_with_config`)
/// create **in-memory HashMap** backends, not real kernel eBPF maps.
///
/// ## In-Memory Mode (this struct)
///
/// Use `EbpfMaps::new_in_memory()` or `EbpfMaps::new_in_memory_with_config(config)`
/// when:
/// - Running in development or testing mode.
/// - The user-space proxy is used without kernel eBPF programs.
///
/// In this mode, all map operations (`insert`, `lookup`, `remove`) go through
/// `Arc<StdRwLock<HashMap>>` — entirely in user space.
///
/// ## Real eBPF Mode (`EbpfContext`)
///
/// For production with kernel BPF programs (tc clsact or XDP), use
/// [`EbpfContext`](super::EbpfContext) instead. `EbpfContext` manages real aya
/// `HashMap`, `LpmTrie`, and `PerCpuArray` maps that are shared between kernel
/// and user space.
///
/// ## Detecting the Mode
///
/// Call [`is_real_ebpf()`](EbpfMaps::is_real_ebpf) at runtime to check which
/// backend is active. When `is_real_ebpf()` returns `false`, you are using
/// these in-memory stubs.
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

/// Session map handle wrapper — in-memory HashMap stub.
///
/// Uses `Arc<StdRwLock<HashMap<ConnectionKey, SessionEntry>>>` for concurrent
/// access and cheap cloneability (all handles share the same underlying map).
///
/// ## Limitation: Process-Local Only
///
/// **This map is entirely in user space and is not shared with kernel BPF
/// programs.** Session state created here is invisible to any tc clsact or XDP
/// programs running in the kernel. For kernel-level session tracking, use
/// `EbpfContext` with aya `HashMap`.
///
/// ## Performance
///
/// Read operations (`lookup`) acquire a read lock; write operations (`insert`,
/// `remove`) acquire the write lock. Under heavy concurrency, consider
/// partitioning or using `dashmap` for reduced lock contention.
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

/// Routing map handle wrapper — in-memory HashMap stub with **exact-match only**.
///
/// ## ⚠️ Critical Limitation: No CIDR / LPM Support
///
/// **This map performs exact IP matching (`HashMap<u32, RoutingEntry>`), NOT
/// Longest Prefix Match (LPM).** It cannot evaluate CIDR rules like
/// `10.0.0.0/8 → PASS` or `192.168.0.0/16 → DROP`.
///
/// For proper CIDR routing, you **must** use `EbpfContext` with a real aya
/// [`LpmTrie`] map, which supports longest-prefix matching in the kernel.
///
/// ## What This Map Does
///
/// - `insert(ip, entry)` — stores a routing entry keyed by a full 32-bit IP.
/// - `lookup(ip)` — finds the entry for exactly that IP, with no prefix matching.
///
/// This is only useful when routing decisions are made on specific IPs, not
/// CIDR ranges.
///
/// [`LpmTrie`]: <https://docs.rs/aya/latest/aya/maps/lpm_trie/struct.LpmTrie.html>
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

/// Stats map handle wrapper — in-memory HashMap stub.
///
/// ## ⚠️ Performance Warning: Write Lock Contention
///
/// Stats are updated under a **single write lock** (`StdRwLock`). Under high
/// concurrency (many threads updating stats simultaneously), this causes lock
/// contention and degrades performance.
///
/// For production with real traffic, use `EbpfContext` with aya [`PerCpuArray`],
/// which provides per-CPU counters that are updated lock-free in the kernel.
///
/// ## In-Memory Stub Behavior
///
/// - `increment(idx, bytes)` — acquires write lock, increments bytes/packets.
/// - `get(idx)` / `get_all()` — acquires read lock.
///
/// The `bytes` and `packets` fields are plain `u64` (not atomic), so concurrent
/// increments are not strictly safe without the lock.
///
/// [`PerCpuArray`]: <https://docs.rs/aya/latest/aya/maps/per_cpu_array/struct.PerCpuArray.html>
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
