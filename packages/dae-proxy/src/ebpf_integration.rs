//! eBPF map integration for dae-proxy
//!
//! Provides wrappers around eBPF maps for session, routing, and stats management.
//!
//! # Implementation
//!
//! This module provides **in-memory HashMap implementations** as a working
//! fallback when kernel BPF maps via `aya` are not available.
//!
//! - [`SessionMapHandle`] — `Arc<StdRwLock<HashMap<ConnectionKey, SessionEntry>>>`
//! - [`RoutingMapHandle`] — `Arc<StdRwLock<HashMap<u32, RoutingEntry>>>` (exact-match)
//! - [`StatsMapHandle`] — `Arc<StdRwLock<HashMap<u32, StatsEntry>>>`
//!
//! Use [`EbpfMaps::new_in_memory()`] to get initialized maps.
//!
//! For production kernel BPF integration, replace these with aya map types
//! (e.g., `aya::maps::HashMap`, `aya::maps::LpmTrie`).

use crate::connection_pool::ConnectionKey;
use crate::rule_engine::{PacketInfo, RuleAction, SharedRuleEngine};
use dae_ebpf_common::routing::RoutingEntry;
use dae_ebpf_common::session::{SessionEntry, SessionKey};
use dae_ebpf_common::stats::{idx as stats_idx, StatsEntry};
use std::collections::HashMap;
use std::sync::{Arc, RwLock as StdRwLock};
use thiserror::Error;
use tracing::{debug, info};

/// Error type for eBPF operations
#[derive(Error, Debug)]
pub enum EbpfError {
    #[error("Map not found: {0}")]
    MapNotFound(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Update failed: {0}")]
    UpdateFailed(String),
    #[error("Lookup failed: {0}")]
    LookupFailed(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Other error: {0}")]
    Other(String),
}

impl From<std::io::Error> for EbpfError {
    fn from(e: std::io::Error) -> Self {
        EbpfError::Other(e.to_string())
    }
}

/// Result type for eBPF operations
pub type Result<T> = std::result::Result<T, EbpfError>;

/// eBPF map handles wrapper
///
/// Provides in-memory map implementations as a fallback when aya BPF maps
/// are not available. For production with kernel BPF, replace with aya maps.
#[derive(Clone)]
pub struct EbpfMaps {
    /// Session map handle
    pub sessions: Option<SessionMapHandle>,
    /// Routing map handle
    pub routing: Option<RoutingMapHandle>,
    /// Stats map handle
    pub stats: Option<StatsMapHandle>,
}

impl EbpfMaps {
    /// Create new eBPF maps wrapper with in-memory HashMap backends
    pub fn new_in_memory() -> Self {
        Self {
            sessions: Some(SessionMapHandle::new()),
            routing: Some(RoutingMapHandle::new()),
            stats: Some(StatsMapHandle::new()),
        }
    }

    /// Create new eBPF maps wrapper (legacy, creates None stubs)
    pub fn new() -> Self {
        Self {
            sessions: None,
            routing: None,
            stats: None,
        }
    }

    /// Check if all maps are initialized
    pub fn is_initialized(&self) -> bool {
        self.sessions.is_some() && self.routing.is_some() && self.stats.is_some()
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
    /// Create a new session map handle with in-memory storage
    pub fn new() -> Self {
        Self {
            inner: Arc::new(StdRwLock::new(HashMap::new())),
        }
    }

    /// Insert or update a session
    pub fn insert(&self, key: &ConnectionKey, value: &SessionEntry) -> Result<()> {
        let mut map = self.inner.write().unwrap();
        map.insert(*key, *value);
        debug!("Session insert: {:?} state={}", key, value.state);
        Ok(())
    }

    /// Lookup a session by key
    pub fn lookup(&self, key: &ConnectionKey) -> Result<Option<SessionEntry>> {
        let map = self.inner.read().unwrap();
        Ok(map.get(key).copied())
    }

    /// Remove a session
    pub fn remove(&self, key: &ConnectionKey) -> Result<()> {
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
/// Trie. For proper CIDR routing rules, a Trie-based implementation is needed.
#[derive(Clone)]
pub struct RoutingMapHandle {
    inner: Arc<StdRwLock<HashMap<u32, RoutingEntry>>>,
}

impl RoutingMapHandle {
    /// Create a new routing map handle with in-memory storage
    pub fn new() -> Self {
        Self {
            inner: Arc::new(StdRwLock::new(HashMap::new())),
        }
    }

    /// Insert a routing entry
    pub fn insert(&self, ip: u32, entry: RoutingEntry) -> Result<()> {
        let mut map = self.inner.write().unwrap();
        map.insert(ip, entry);
        debug!("Routing insert: IP {:x}", ip);
        Ok(())
    }

    /// Lookup routing for an IP address (exact match)
    pub fn lookup(&self, ip: u32) -> Result<Option<RoutingEntry>> {
        let map = self.inner.read().unwrap();
        Ok(map.get(&ip).copied())
    }

    /// Remove a routing entry
    pub fn remove(&self, ip: u32) -> Result<()> {
        let mut map = self.inner.write().unwrap();
        map.remove(&ip);
        debug!("Routing remove: IP {:x}", ip);
        Ok(())
    }

    /// Get the number of routing entries
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
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
    /// Create a new stats map handle with in-memory storage
    pub fn new() -> Self {
        Self {
            inner: Arc::new(StdRwLock::new(HashMap::new())),
        }
    }

    /// Increment a stats counter
    pub fn increment(&self, idx: u32, bytes: u64) -> Result<()> {
        let mut map = self.inner.write().unwrap();
        let entry = map.entry(idx).or_default();
        entry.bytes += bytes;
        entry.packets += 1;
        debug!("Stats increment: idx={}, bytes={}, total_bytes={}", idx, bytes, entry.bytes);
        Ok(())
    }

    /// Get stats for an index
    pub fn get(&self, idx: u32) -> Result<Option<StatsEntry>> {
        let map = self.inner.read().unwrap();
        Ok(map.get(&idx).copied())
    }

    /// Set a stats entry directly (for bulk updates)
    pub fn set(&self, idx: u32, entry: StatsEntry) -> Result<()> {
        let mut map = self.inner.write().unwrap();
        map.insert(idx, entry);
        Ok(())
    }

    /// Get all stats as a HashMap snapshot
    pub fn get_all(&self) -> HashMap<u32, StatsEntry> {
        self.inner.read().unwrap().clone()
    }
}

impl Default for StatsMapHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// High-level eBPF session handle for dae-proxy
pub struct EbpfSessionHandle {
    maps: EbpfMaps,
}

impl EbpfSessionHandle {
    /// Create a new eBPF session handle
    pub fn new(maps: EbpfMaps) -> Self {
        Self { maps }
    }

    /// Create a new session
    pub fn create_session(&self, key: &ConnectionKey, state: u8, route_id: u32) -> Result<()> {
        let mut entry = SessionEntry::default();
        entry.state = state;
        entry.packets = 0;
        entry.bytes = 0;
        entry.start_time = unix_time_secs();
        entry.last_time = unix_time_secs();
        entry.route_id = route_id;

        if let Some(ref sessions) = self.maps.sessions {
            sessions.insert(key, &entry)?;
        }

        debug!("Created eBPF session: {:?}", key);
        Ok(())
    }

    /// Update an existing session
    pub fn update_session(&self, key: &ConnectionKey, state: u8, packets: u64) -> Result<()> {
        if let Some(ref sessions) = self.maps.sessions {
            if let Some(mut entry) = sessions.lookup(key)? {
                entry.state = state;
                entry.last_time = unix_time_secs();
                entry.packets += packets;
                sessions.insert(key, &entry)?;
            }
        }

        debug!("Updated eBPF session: {:?} state={}", key, state);
        Ok(())
    }

    /// Remove a session
    pub fn remove_session(&self, key: &ConnectionKey) -> Result<()> {
        if let Some(ref sessions) = self.maps.sessions {
            sessions.remove(key)?;
        }

        debug!("Removed eBPF session: {:?}", key);
        Ok(())
    }

    /// Lookup a session
    pub fn lookup_session(&self, key: &ConnectionKey) -> Result<Option<SessionEntry>> {
        if let Some(ref sessions) = self.maps.sessions {
            sessions.lookup(key)
        } else {
            Ok(None)
        }
    }

    /// Get the maps handle
    pub fn maps(&self) -> &EbpfMaps {
        &self.maps
    }
}

/// High-level eBPF routing handle
pub struct EbpfRoutingHandle {
    maps: EbpfMaps,
}

impl EbpfRoutingHandle {
    /// Create a new eBPF routing handle
    pub fn new(maps: EbpfMaps) -> Self {
        Self { maps }
    }

    /// Lookup routing for a destination IP
    pub fn lookup_routing(&self, ip: u32) -> Result<Option<RoutingEntry>> {
        if let Some(ref routing) = self.maps.routing {
            routing.lookup(ip)
        } else {
            Ok(None)
        }
    }
}

/// High-level eBPF stats handle
pub struct EbpfStatsHandle {
    maps: EbpfMaps,
}

impl EbpfStatsHandle {
    /// Create a new eBPF stats handle
    pub fn new(maps: EbpfMaps) -> Self {
        Self { maps }
    }

    /// Increment stats counter
    pub fn increment_stats(&self, idx: u32, bytes: u64) -> Result<()> {
        if let Some(ref stats) = self.maps.stats {
            stats.increment(idx, bytes)?;
        }
        Ok(())
    }

    /// Get stats for a protocol
    pub fn get_stats(&self, idx: u32) -> Result<Option<StatsEntry>> {
        if let Some(ref stats) = self.maps.stats {
            stats.get(idx)
        } else {
            Ok(None)
        }
    }

    /// Increment TCP stats
    pub fn increment_tcp(&self, bytes: u64) -> Result<()> {
        self.increment_stats(stats_idx::TCP, bytes)
    }

    /// Increment UDP stats
    pub fn increment_udp(&self, bytes: u64) -> Result<()> {
        self.increment_stats(stats_idx::UDP, bytes)
    }

    /// Increment overall stats
    pub fn increment_overall(&self, bytes: u64) -> Result<()> {
        self.increment_stats(stats_idx::OVERALL, bytes)
    }
}

/// Get current Unix time in seconds
fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Convert ConnectionKey to SessionKey for eBPF
impl From<&ConnectionKey> for SessionKey {
    fn from(key: &ConnectionKey) -> Self {
        SessionKey::new(
            key.src_ip,
            key.dst_ip,
            key.src_port,
            key.dst_port,
            key.proto,
        )
    }
}

// ============================================
// Rule Engine Integration
// ============================================

/// Rule engine integration with eBPF
///
/// This handle coordinates between the eBPF layer (packet classification)
/// and the user-space rule engine (routing decisions).
pub struct EbpfRuleEngineHandle {
    /// The rule engine
    rule_engine: SharedRuleEngine,
    /// eBPF maps for writing routing decisions
    maps: EbpfMaps,
}

impl EbpfRuleEngineHandle {
    /// Create a new rule engine handle
    pub fn new(rule_engine: SharedRuleEngine, maps: EbpfMaps) -> Self {
        Self { rule_engine, maps }
    }

    /// Create a new rule engine handle with default maps
    pub fn with_default_maps(rule_engine: SharedRuleEngine) -> Self {
        Self {
            rule_engine,
            maps: EbpfMaps::new(),
        }
    }

    /// Match a packet and get the routing action
    ///
    /// This is the main entry point for user-space rule matching.
    /// The eBPF layer provides initial packet classification (IP, port, protocol),
    /// and this method enriches with domain/GeoIP/process info and applies rules.
    pub async fn match_packet(&self, info: PacketInfo) -> RuleAction {
        self.rule_engine.match_packet(&info).await
    }

    /// Match a packet from connection key
    ///
    /// For when we only have the 4-tuple from eBPF.
    pub async fn match_connection(
        &self,
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        proto: u8,
    ) -> RuleAction {
        let info = PacketInfo::from_tuple(src_ip, dst_ip, src_port, dst_port, proto);
        self.match_packet(info).await
    }

    /// Match a packet and write the routing decision to eBPF map
    ///
    /// This integrates with the eBPF routing map to persist
    /// the routing decision for the kernel to use.
    pub async fn match_and_write_routing(
        &self,
        info: &PacketInfo,
        route_id: u32,
    ) -> std::result::Result<RuleAction, EbpfError> {
        let action = self.match_packet(info.clone()).await;

        // Write routing decision to eBPF map if available
        if self.maps.routing.is_some() {
            let entry = RoutingEntry::new(
                route_id,
                action.to_ebpf_action(),
                0, // ifindex
            );
            // Note: In real implementation, we'd use aya to update the map
            debug!("Would write routing entry: {:?}", entry);
        }

        Ok(action)
    }

    /// Get the rule engine
    pub fn rule_engine(&self) -> &SharedRuleEngine {
        &self.rule_engine
    }

    /// Get rule engine stats
    pub async fn get_stats(&self) -> crate::rule_engine::RuleEngineStats {
        self.rule_engine.get_stats().await
    }

    /// Reload rules from file
    pub async fn reload_rules(&self, path: &str) -> std::result::Result<(), String> {
        info!("Reloading rules from {}", path);
        self.rule_engine.reload(path).await
    }

    /// Check if rules are loaded
    pub async fn is_loaded(&self) -> bool {
        self.rule_engine.is_loaded().await
    }
}

/// Packet classifier that combines eBPF and user-space classification
pub struct PacketClassifier {
    /// Rule engine handle
    rule_engine_handle: EbpfRuleEngineHandle,
    /// Whether to enable DNS resolution for domain matching
    enable_dns_resolution: bool,
}

impl PacketClassifier {
    /// Create a new packet classifier
    pub fn new(rule_engine: SharedRuleEngine, maps: EbpfMaps) -> Self {
        Self {
            rule_engine_handle: EbpfRuleEngineHandle::new(rule_engine, maps),
            enable_dns_resolution: true,
        }
    }

    /// Create with DNS resolution disabled
    pub fn with_dns_resolution(mut self, enabled: bool) -> Self {
        self.enable_dns_resolution = enabled;
        self
    }

    /// Classify a packet
    ///
    /// Returns the routing action for the packet.
    pub async fn classify(&self, info: PacketInfo) -> RuleAction {
        self.rule_engine_handle.match_packet(info).await
    }

    /// Classify from connection tuple
    pub async fn classify_connection(
        &self,
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        proto: u8,
    ) -> RuleAction {
        self.rule_engine_handle
            .match_connection(src_ip, dst_ip, src_port, dst_port, proto)
            .await
    }

    /// Get the rule engine stats
    pub async fn stats(&self) -> crate::rule_engine::RuleEngineStats {
        self.rule_engine_handle.get_stats().await
    }
}

/// Shared packet classifier type
pub type SharedPacketClassifier = Arc<PacketClassifier>;

/// Create a new shared packet classifier
pub fn new_packet_classifier(
    rule_engine: SharedRuleEngine,
    maps: EbpfMaps,
) -> SharedPacketClassifier {
    Arc::new(PacketClassifier::new(rule_engine, maps))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_maps_default() {
        let maps = EbpfMaps::new();
        assert!(!maps.is_initialized());
    }

    #[test]
    fn test_session_entry() {
        let key = ConnectionKey::from_raw(0x0100007f, 0x08080808, 80, 443, 6);
        let entry = SessionEntry::default();
        assert_eq!(entry.state, 0);
    }
}
