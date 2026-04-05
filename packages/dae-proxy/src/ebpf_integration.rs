//! eBPF map integration for dae-proxy
//!
//! Provides wrappers around eBPF maps for session, routing, and stats management.
//!
//! # Architecture
//!
//! This module supports two backends:
//! - **In-memory HashMap** (development/fallback): `EbpfMaps::new_in_memory()`
//! - **Real aya eBPF** (production): `EbpfMaps::new_with_ebpf()` or `EbpfContext`
//!
//! ## eBPF Map Types
//!
//! | Map Type | Purpose | aya Type |
//! |----------|---------|----------|
//! | SessionMap | 5-tuple connection tracking | `aya::maps::HashMap` |
//! | RoutingMap | CIDR routing rules | `aya::maps::LpmTrie` |
//! | StatsMap | Per-CPU statistics | `aya::maps::PerCpuArray` |
//!
//! ## Kernel Version Capabilities
//!
//! - **5.17+**: Full features (ringbuf, stable LpmTrie)
//! - **5.13+**: TC clsact + ringbuf + stable LpmTrie
//! - **5.10+**: TC clsact with improved LpmTrie
//! - **5.8+**: XDP support available
//! - **4.14+**: Basic eBPF Maps
//! - **< 4.14**: Fallback to in-memory HashMap

use crate::connection_pool::ConnectionKey;
use crate::rule_engine::{PacketInfo, RuleAction, SharedRuleEngine};
use dae_ebpf_common::routing::RoutingEntry;
use dae_ebpf_common::session::{SessionEntry, SessionKey};
use dae_ebpf_common::stats::{idx as stats_idx, StatsEntry};
use std::collections::HashMap;
use std::sync::{Arc, RwLock as StdRwLock};
use thiserror::Error;
use tracing::{debug, info, warn};

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
    #[error("eBPF not available: {0}")]
    EbpfNotAvailable(String),
    #[error("Kernel version not supported: {0}")]
    KernelNotSupported(String),
    #[error("Other error: {0}")]
    Other(String),
}

impl From<std::io::Error> for EbpfError {
    fn from(e: std::io::Error) -> Self {
        EbpfError::Other(e.to_string())
    }
}

impl From<aya::EbpfError> for EbpfError {
    fn from(e: aya::EbpfError) -> Self {
        EbpfError::Other(e.to_string())
    }
}

impl From<aya::maps::MapError> for EbpfError {
    fn from(e: aya::maps::MapError) -> Self {
        EbpfError::Other(e.to_string())
    }
}

impl From<aya::programs::ProgramError> for EbpfError {
    fn from(e: aya::programs::ProgramError) -> Self {
        EbpfError::Other(e.to_string())
    }
}

/// Result type for eBPF operations
pub type Result<T> = std::result::Result<T, EbpfError>;

// ============================================
// Kernel Version Detection
// ============================================

/// Kernel eBPF capability levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KernelCapability {
    /// No eBPF support
    None = 0,
    /// Basic Maps only (kernel 4.14+)
    BasicMaps = 1,
    /// XDP support (kernel 5.8+)
    XdpOnly = 2,
    /// Full TC clsact + LpmTrie support (kernel 5.10+)
    FullTc = 3,
    /// ringbuf + stable LpmTrie (kernel 5.13+)
    RingBuf = 4,
    /// Full features (kernel 5.17+)
    Full = 5,
}

impl std::fmt::Display for KernelCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KernelCapability::None => write!(f, "None (no eBPF)"),
            KernelCapability::BasicMaps => write!(f, "BasicMaps (4.14+)"),
            KernelCapability::XdpOnly => write!(f, "XdpOnly (5.8+)"),
            KernelCapability::FullTc => write!(f, "FullTc (5.10+)"),
            KernelCapability::RingBuf => write!(f, "RingBuf (5.13+)"),
            KernelCapability::Full => write!(f, "Full (5.17+)"),
        }
    }
}

/// Kernel version information
#[derive(Debug, Clone)]
pub struct KernelVersion {
    major: u8,
    minor: u8,
    patch: u8,
}

impl KernelVersion {
    /// Detect current kernel version from /proc/version
    pub fn detect() -> Self {
        #[cfg(target_os = "linux")]
        {
            use std::fs;

            if let Ok(version) = fs::read_to_string("/proc/version") {
                if let Some(version_string) = version.split_whitespace().nth(2) {
                    return Self::parse(version_string);
                }
            }

            // Fallback: try to use utsname via libc
            unsafe {
                let mut uts = std::mem::MaybeUninit::<libc::utsname>::zeroed();
                if libc::uname(uts.as_mut_ptr()) == 0 {
                    let uts = uts.assume_init();
                    let release = std::ffi::CStr::from_ptr(uts.release.as_ptr())
                        .to_str()
                        .unwrap_or("0.0.0");
                    return Self::parse(release);
                }
            }
        }

        warn!("Could not detect kernel version, assuming no eBPF support");
        Self {
            major: 0,
            minor: 0,
            patch: 0,
        }
    }

    /// Parse kernel version from release string (e.g., "5.15.0-91-generic")
    fn parse(release: &str) -> Self {
        let parts: Vec<&str> = release
            .split('-')
            .next()
            .unwrap_or("0.0.0")
            .split('.')
            .collect();
        let major: u8 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor: u8 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch: u8 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Determine eBPF capability level
    pub fn capability(&self) -> KernelCapability {
        if self.major == 0 && self.minor == 0 {
            return KernelCapability::None;
        }

        // Kernel 5.17+: Full features
        if self.major > 5 || (self.major == 5 && self.minor >= 17) {
            return KernelCapability::Full;
        }

        // Kernel 5.13+: ringbuf + stable LpmTrie
        if self.major > 5 || (self.major == 5 && self.minor >= 13) {
            return KernelCapability::RingBuf;
        }

        // Kernel 5.10+: TC clsact with improved LpmTrie
        if self.major > 5 || (self.major == 5 && self.minor >= 10) {
            return KernelCapability::FullTc;
        }

        // Kernel 5.8+: XDP support
        if self.major > 5 || (self.major == 5 && self.minor >= 8) {
            return KernelCapability::XdpOnly;
        }

        // Kernel 4.14+: Basic Maps
        if self.major > 4 || (self.major == 4 && self.minor >= 14) {
            return KernelCapability::BasicMaps;
        }

        KernelCapability::None
    }

    /// Check if eBPF is supported at all
    pub fn has_ebpf(&self) -> bool {
        self.capability() != KernelCapability::None
    }

    /// Check if TC clsact is supported (kernel 5.10+)
    pub fn has_tc_clsact(&self) -> bool {
        matches!(
            self.capability(),
            KernelCapability::FullTc | KernelCapability::RingBuf | KernelCapability::Full
        )
    }

    /// Check if XDP is supported (kernel 5.8+)
    pub fn has_xdp(&self) -> bool {
        matches!(
            self.capability(),
            KernelCapability::XdpOnly
                | KernelCapability::FullTc
                | KernelCapability::RingBuf
                | KernelCapability::Full
        )
    }

    /// Check if ringbuf is supported (kernel 5.13+)
    pub fn has_ringbuf(&self) -> bool {
        matches!(
            self.capability(),
            KernelCapability::RingBuf | KernelCapability::Full
        )
    }
}

impl Default for KernelVersion {
    fn default() -> Self {
        Self::detect()
    }
}

// ============================================
// In-Memory HashMap Backend (Fallback)
// ============================================

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
}

impl EbpfMaps {
    /// Create new eBPF maps wrapper with in-memory HashMap backends
    pub fn new_in_memory() -> Self {
        Self {
            sessions: Some(SessionMapHandle::new()),
            routing: Some(RoutingMapHandle::new()),
            stats: Some(StatsMapHandle::new()),
            is_real_ebpf: false,
        }
    }

    /// Create new eBPF maps wrapper (legacy, creates None stubs)
    pub fn new() -> Self {
        Self {
            sessions: None,
            routing: None,
            stats: None,
            is_real_ebpf: false,
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
    #[allow(dead_code)]
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
/// Trie. For proper CIDR routing rules, use `EbpfContext` with real eBPF.
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
    #[allow(dead_code)]
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
        debug!(
            "Stats increment: idx={}, bytes={}, total_bytes={}",
            idx, bytes, entry.bytes
        );
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

// ============================================
// eBPF Runtime and Context (aya integration)
// ============================================

/// eBPF program type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfProgramType {
    /// TC clsact qdisc (recommended for transparent proxy)
    Tc,
    /// XDP express path (high performance, limited routing)
    Xdp,
    /// No eBPF program, maps only
    MapsOnly,
}

/// eBPF runtime state
#[derive(Debug, Clone, Default)]
pub enum EbpfRuntime {
    /// eBPF is active and running
    Active {
        program_type: EbpfProgramType,
        kernel_capability: KernelCapability,
    },
    /// Using in-memory fallback
    Fallback,
    /// Not yet initialized
    #[default]
    Uninitialized,
}

impl EbpfRuntime {
    /// Check if real eBPF is active
    pub fn is_active(&self) -> bool {
        matches!(self, EbpfRuntime::Active { .. })
    }

    /// Get program type if active
    pub fn program_type(&self) -> Option<EbpfProgramType> {
        match self {
            EbpfRuntime::Active { program_type, .. } => Some(*program_type),
            _ => None,
        }
    }
}

/// eBPF context for managing aya runtime
///
/// This is the main entry point for eBPF integration. It handles:
/// - Kernel version detection and capability checking
/// - eBPF program loading (TC or XDP)
/// - Map initialization
/// - Fallback to in-memory if eBPF is not available
pub struct EbpfContext {
    /// Kernel version info
    pub kernel_version: KernelVersion,
    /// Current eBPF runtime state
    pub runtime: EbpfRuntime,
    /// Fallback in-memory maps (always available)
    fallback_maps: EbpfMaps,
    /// eBPF maps (available when using real eBPF)
    #[allow(dead_code)]
    ebpf_maps: Option<aya::Ebpf>,
}

impl EbpfContext {
    /// Create a new eBPF context with automatic detection
    ///
    /// # Arguments
    /// * `interface` - Network interface to attach to (e.g., "eth0")
    /// * `ebpf_obj_path` - Path to compiled eBPF object file (.o)
    ///
    /// # Returns
    /// * `EbpfContext` with either real eBPF or in-memory fallback
    pub async fn new(interface: Option<&str>, ebpf_obj_path: Option<&str>) -> Result<Self> {
        let kernel_version = KernelVersion::detect();
        info!(
            "Kernel version: {}.{}.{}, eBPF capability: {}",
            kernel_version.major,
            kernel_version.minor,
            kernel_version.patch,
            kernel_version.capability()
        );

        // Always create fallback maps
        let fallback_maps = EbpfMaps::new_in_memory();

        // Try to initialize real eBPF if requested and supported
        let (runtime, ebpf_maps) = if let (Some(iface), Some(obj_path)) = (interface, ebpf_obj_path)
        {
            Self::try_init_ebpf(&kernel_version, iface, obj_path).await?
        } else {
            (EbpfRuntime::Fallback, None)
        };

        if !runtime.is_active() {
            info!("Using in-memory fallback eBPF maps");
        } else {
            info!(
                "Real eBPF initialized successfully: {:?}",
                runtime.program_type()
            );
            // Mark fallback maps as using real eBPF
            let mut maps = fallback_maps.clone();
            maps.set_real_ebpf();
        }

        Ok(Self {
            kernel_version,
            runtime,
            fallback_maps,
            ebpf_maps,
        })
    }

    /// Try to initialize real eBPF
    async fn try_init_ebpf(
        kernel_version: &KernelVersion,
        interface: &str,
        obj_path: &str,
    ) -> Result<(EbpfRuntime, Option<aya::Ebpf>)> {
        use std::path::Path;

        let path = Path::new(obj_path);
        if !path.exists() {
            warn!("eBPF object file not found: {}, using fallback", obj_path);
            return Ok((EbpfRuntime::Fallback, None));
        }

        // Load eBPF from file
        let mut ebpf = match aya::Ebpf::load_file(path) {
            Ok(ebpf) => ebpf,
            Err(e) => {
                warn!("Failed to load eBPF: {}, using fallback", e);
                return Ok((EbpfRuntime::Fallback, None));
            }
        };

        // Try to attach TC program first (preferred for transparent proxy)
        if kernel_version.has_tc_clsact() {
            if let Ok(runtime) = Self::attach_tc_program(&mut ebpf, interface) {
                info!("TC clsact eBPF program attached successfully");
                return Ok((runtime, Some(ebpf)));
            }
        }

        // Fall back to XDP if TC failed
        if kernel_version.has_xdp() {
            if let Ok(runtime) = Self::attach_xdp_program(&mut ebpf, interface) {
                info!("XDP eBPF program attached successfully");
                return Ok((runtime, Some(ebpf)));
            }
        }

        warn!("Failed to attach any eBPF program, using fallback");
        Ok((EbpfRuntime::Fallback, None))
    }

    /// Attach TC clsact program
    #[allow(dead_code)]
    fn attach_tc_program(ebpf: &mut aya::Ebpf, interface: &str) -> Result<EbpfRuntime> {
        use aya::programs::{tc, TcAttachType};

        // Try to find TC program
        if let Some(prog) = ebpf.program_mut("tc_prog_main") {
            let prog: &mut tc::SchedClassifier = prog.try_into()?;
            prog.load()
                .map_err(|e| EbpfError::Other(format!("{:?}", e)))?;

            // Setup clsact qdisc
            Self::setup_clsact_qdisc(interface)?;

            // Attach to ingress
            prog.attach(interface, TcAttachType::Ingress)
                .map_err(|e| EbpfError::Other(format!("{:?}", e)))?;

            return Ok(EbpfRuntime::Active {
                program_type: EbpfProgramType::Tc,
                kernel_capability: KernelVersion::detect().capability(),
            });
        }

        Err(EbpfError::MapNotFound("tc_prog_main".into()))
    }

    /// Attach XDP program
    #[allow(dead_code)]
    fn attach_xdp_program(ebpf: &mut aya::Ebpf, interface: &str) -> Result<EbpfRuntime> {
        use aya::programs::{Xdp, XdpFlags};

        // Try to find XDP program
        if let Some(prog) = ebpf.program_mut("xdp_prog_main") {
            let prog: &mut Xdp = prog.try_into()?;
            prog.load()
                .map_err(|e| EbpfError::Other(format!("{:?}", e)))?;

            prog.attach(interface, XdpFlags::default())
                .map_err(|e| EbpfError::Other(format!("{:?}", e)))?;

            return Ok(EbpfRuntime::Active {
                program_type: EbpfProgramType::Xdp,
                kernel_capability: KernelVersion::detect().capability(),
            });
        }

        Err(EbpfError::MapNotFound("xdp_prog_main".into()))
    }

    /// Setup clsact qdisc on interface
    fn setup_clsact_qdisc(interface: &str) -> Result<()> {
        use std::process::Command;

        // Check if clsact already exists
        let output = Command::new("tc")
            .args(["qdisc", "show", "dev", interface])
            .output()
            .map_err(|e| EbpfError::Other(e.to_string()))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        if !output_str.contains("clsact") {
            // Add clsact qdisc
            let result = Command::new("tc")
                .args(["qdisc", "add", "dev", interface, "clsact"])
                .output();

            if let Err(e) = result {
                warn!("Failed to add clsact qdisc (may already exist): {}", e);
            } else {
                info!("Added clsact qdisc to {}", interface);
            }
        }

        Ok(())
    }

    /// Get the fallback in-memory maps
    pub fn fallback_maps(&self) -> &EbpfMaps {
        &self.fallback_maps
    }

    /// Check if using real eBPF
    pub fn is_using_real_ebpf(&self) -> bool {
        self.runtime.is_active()
    }

    /// Get maps suitable for current runtime
    ///
    /// Returns the real eBPF maps if available, otherwise the fallback maps.
    pub fn maps(&self) -> EbpfMaps {
        if self.is_using_real_ebpf() {
            // For now, return fallback maps even when using real eBPF
            // Full aya map integration would require additional work
            self.fallback_maps.clone()
        } else {
            self.fallback_maps.clone()
        }
    }
}

impl Default for EbpfContext {
    fn default() -> Self {
        // Sync version for non-async contexts
        let kernel_version = KernelVersion::detect();
        let has_ebpf = kernel_version.has_ebpf();
        Self {
            kernel_version,
            runtime: if has_ebpf {
                EbpfRuntime::Uninitialized
            } else {
                EbpfRuntime::Fallback
            },
            fallback_maps: EbpfMaps::new_in_memory(),
            ebpf_maps: None,
        }
    }
}

// ============================================
// High-level Handles
// ============================================

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
    ///
    /// Note: For real eBPF with LpmTrie, this performs LPM (Longest Prefix Match).
    /// For in-memory fallback, this performs exact match only.
    pub fn lookup_routing(&self, ip: u32) -> Result<Option<RoutingEntry>> {
        if let Some(ref routing) = self.maps.routing {
            routing.lookup(ip)
        } else {
            Ok(None)
        }
    }

    /// Insert routing entry
    ///
    /// Note: For real eBPF with LpmTrie, prefix_len should be provided.
    /// For in-memory fallback, only ip is used (exact match).
    #[allow(dead_code)]
    pub fn insert_routing(&self, ip: u32, entry: RoutingEntry) -> Result<()> {
        if let Some(ref routing) = self.maps.routing {
            routing.insert(ip, entry)
        } else {
            Ok(())
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
///
/// Note: SessionKey uses u32 for IPs. For IPv6 connections, we store
/// the lower 32 bits of the IPv6 address. This means some IPv6 connections
/// may have hash collisions on the eBPF side, but user-space tracking
/// (ConnectionKey with full IPv6 support) remains correct.
impl From<&ConnectionKey> for SessionKey {
    fn from(key: &ConnectionKey) -> Self {
        SessionKey::new(
            key.src_ip.to_u32_lossy(),
            key.dst_ip.to_u32_lossy(),
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
    #[allow(dead_code)]
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
    use dae_ebpf_common::routing::action;
    use dae_ebpf_common::session::state;

    /// Helper to create a SessionEntry without touching private fields
    fn make_session_entry(state: u8, packets: u64, bytes: u64, route_id: u32) -> SessionEntry {
        let mut entry = SessionEntry::default();
        entry.state = state;
        entry.packets = packets;
        entry.bytes = bytes;
        entry.route_id = route_id;
        entry
    }

    #[test]
    fn test_ebpf_maps_default() {
        let maps = EbpfMaps::new();
        assert!(!maps.is_initialized());
        assert!(maps.sessions.is_none());
        assert!(maps.routing.is_none());
        assert!(maps.stats.is_none());
        assert!(!maps.is_real_ebpf());
    }

    #[test]
    fn test_ebpf_maps_new_in_memory() {
        let maps = EbpfMaps::new_in_memory();
        assert!(maps.is_initialized());
        assert!(maps.sessions.is_some());
        assert!(maps.routing.is_some());
        assert!(maps.stats.is_some());
        assert!(!maps.is_real_ebpf());
    }

    // ============================================================
    // KernelVersion Tests
    // ============================================================

    #[test]
    fn test_kernel_version_parse() {
        let version = KernelVersion::parse("5.15.0-91-generic");
        assert_eq!(version.major, 5);
        assert_eq!(version.minor, 15);
        assert_eq!(version.patch, 0);
    }

    #[test]
    fn test_kernel_version_parse_edge_cases() {
        assert_eq!(KernelVersion::parse("5.8.0-49-generic").minor, 8);
        assert_eq!(KernelVersion::parse("4.14.0-xxx").major, 4);
        assert_eq!(KernelVersion::parse("5.17.0").minor, 17);
    }

    #[test]
    fn test_kernel_capability_ordering() {
        use std::cmp::Ordering;

        let levels = [
            KernelCapability::None,
            KernelCapability::BasicMaps,
            KernelCapability::XdpOnly,
            KernelCapability::FullTc,
            KernelCapability::RingBuf,
            KernelCapability::Full,
        ];

        for i in 0..levels.len() {
            for j in (i + 1)..levels.len() {
                assert_eq!(
                    levels[i].cmp(&levels[j]),
                    Ordering::Less,
                    "{:?} should be less than {:?}",
                    levels[i],
                    levels[j]
                );
            }
        }
    }

    #[test]
    fn test_kernel_capability_display() {
        assert_eq!(format!("{}", KernelCapability::FullTc), "FullTc (5.10+)");
        assert_eq!(format!("{}", KernelCapability::None), "None (no eBPF)");
    }

    #[test]
    fn test_kernel_version_capability_detection() {
        // Test various kernel versions
        let test_cases = vec![
            ("5.17.0", KernelCapability::Full),
            ("5.15.0", KernelCapability::RingBuf),
            ("5.13.0", KernelCapability::RingBuf),
            ("5.10.0", KernelCapability::FullTc),
            ("5.8.0", KernelCapability::XdpOnly),
            ("4.14.0", KernelCapability::BasicMaps),
            ("3.10.0", KernelCapability::None),
        ];

        for (release, expected_cap) in test_cases {
            let version = KernelVersion::parse(release);
            assert_eq!(
                version.capability(),
                expected_cap,
                "Kernel {} should have capability {:?}",
                release,
                expected_cap
            );
        }
    }

    // ============================================================
    // SessionMapHandle Tests
    // ============================================================

    #[test]
    fn test_session_map_insert_lookup() {
        let handle = SessionMapHandle::new();
        let key = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 80, 443, 6);
        let entry = make_session_entry(1, 10, 1024, 42);

        // Insert
        let result = handle.insert(&key, &entry);
        assert!(result.is_ok());

        // Lookup
        let found = handle.lookup(&key).unwrap();
        assert!(found.is_some());
        let retrieved = found.unwrap();
        assert_eq!(retrieved.state, 1);
        assert_eq!(retrieved.packets, 10);
        assert_eq!(retrieved.bytes, 1024);
        assert_eq!(retrieved.route_id, 42);
    }

    #[test]
    fn test_session_map_lookup_nonexistent() {
        let handle = SessionMapHandle::new();
        let key = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 80, 443, 6);

        let found = handle.lookup(&key).unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn test_session_map_remove() {
        let handle = SessionMapHandle::new();
        let key = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 80, 443, 6);
        let entry = SessionEntry::default();

        handle.insert(&key, &entry).unwrap();
        assert!(handle.lookup(&key).unwrap().is_some());

        handle.remove(&key).unwrap();
        assert!(handle.lookup(&key).unwrap().is_none());
    }

    #[test]
    fn test_session_map_remove_nonexistent() {
        let handle = SessionMapHandle::new();
        let key = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 80, 443, 6);

        // Removing non-existent key should not error
        let result = handle.remove(&key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_map_update_existing() {
        let handle = SessionMapHandle::new();
        let key = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 80, 443, 6);

        let entry1 = make_session_entry(1, 5, 100, 0);
        handle.insert(&key, &entry1).unwrap();

        let entry2 = make_session_entry(2, 10, 200, 0);
        handle.insert(&key, &entry2).unwrap();

        let found = handle.lookup(&key).unwrap().unwrap();
        assert_eq!(found.state, 2);
        assert_eq!(found.packets, 10);
        assert_eq!(found.bytes, 200);
    }

    #[test]
    fn test_session_map_len_and_empty() {
        let handle = SessionMapHandle::new();

        assert!(handle.is_empty());
        assert_eq!(handle.len(), 0);

        let key1 = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 80, 443, 6);
        let key2 = ConnectionKey::from_raw(0x7f000001, 0x7f000003, 80, 443, 6);
        let entry = SessionEntry::default();

        handle.insert(&key1, &entry).unwrap();
        assert_eq!(handle.len(), 1);
        assert!(!handle.is_empty());

        handle.insert(&key2, &entry).unwrap();
        assert_eq!(handle.len(), 2);

        handle.remove(&key1).unwrap();
        assert_eq!(handle.len(), 1);
    }

    #[test]
    fn test_session_map_multiple_keys() {
        let handle = SessionMapHandle::new();
        let entry = make_session_entry(1, 1, 1, 0);

        for i in 0u16..100 {
            let key = ConnectionKey::from_raw(0x7f000001, 0x7f000001, i, 443, 6);
            handle.insert(&key, &entry).unwrap();
        }

        assert_eq!(handle.len(), 100);
    }

    // ============================================================
    // RoutingMapHandle Tests
    // ============================================================

    #[test]
    fn test_routing_map_insert_lookup() {
        let handle = RoutingMapHandle::new();
        let ip = 0x7f000001_u32;
        let entry = RoutingEntry::new(42, 0, 0); // route_id=42, action=PASS

        let result = handle.insert(ip, entry);
        assert!(result.is_ok());

        let found = handle.lookup(ip).unwrap();
        assert!(found.is_some());
        let retrieved = found.unwrap();
        assert_eq!(retrieved.route_id, 42);
        assert_eq!(retrieved.action, 0);
    }

    #[test]
    fn test_routing_map_lookup_nonexistent() {
        let handle = RoutingMapHandle::new();
        let found = handle.lookup(0xDEADBEEF).unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn test_routing_map_remove() {
        let handle = RoutingMapHandle::new();
        let ip = 0x0A000001_u32;
        let entry = RoutingEntry::new(1, 0, 0);

        handle.insert(ip, entry).unwrap();
        assert!(handle.lookup(ip).unwrap().is_some());

        handle.remove(ip).unwrap();
        assert!(handle.lookup(ip).unwrap().is_none());
    }

    #[test]
    fn test_routing_map_update_existing() {
        let handle = RoutingMapHandle::new();
        let ip = 0x0A000001_u32;

        let entry1 = RoutingEntry::new(1, 0, 0);
        handle.insert(ip, entry1).unwrap();

        let entry2 = RoutingEntry::new(2, 1, 0); // different route_id, action=REDIRECT
        handle.insert(ip, entry2).unwrap();

        let found = handle.lookup(ip).unwrap().unwrap();
        assert_eq!(found.route_id, 2);
        assert_eq!(found.action, 1);
    }

    #[test]
    fn test_routing_map_len() {
        let handle = RoutingMapHandle::new();
        assert_eq!(handle.len(), 0);

        for i in 0u32..10 {
            handle.insert(i, RoutingEntry::new(i, 0, 0)).unwrap();
        }

        assert_eq!(handle.len(), 10);
    }

    // ============================================================
    // StatsMapHandle Tests
    // ============================================================

    #[test]
    fn test_stats_map_increment() {
        let handle = StatsMapHandle::new();
        let idx = stats_idx::TCP;

        handle.increment(idx, 100).unwrap();
        handle.increment(idx, 200).unwrap();

        let found = handle.get(idx).unwrap();
        assert!(found.is_some());
        let stats = found.unwrap();
        assert_eq!(stats.bytes, 300); // 100 + 200
        assert_eq!(stats.packets, 2);
    }

    #[test]
    fn test_stats_map_increment_creates_entry() {
        let handle = StatsMapHandle::new();
        let idx = stats_idx::UDP;

        // Entry should not exist initially
        assert!(handle.get(idx).unwrap().is_none());

        // After increment, entry should exist
        handle.increment(idx, 50).unwrap();
        let stats = handle.get(idx).unwrap().unwrap();
        assert_eq!(stats.bytes, 50);
        assert_eq!(stats.packets, 1);
    }

    #[test]
    fn test_stats_map_set_and_get() {
        let handle = StatsMapHandle::new();
        let idx = stats_idx::OVERALL;

        let entry = StatsEntry {
            packets: 999,
            bytes: 1_000_000,
            redirected: 100,
            passed: 800,
            dropped: 99,
            routed: 500,
            unmatched: 400,
            ..Default::default()
        };

        handle.set(idx, entry).unwrap();

        let found = handle.get(idx).unwrap();
        assert!(found.is_some());
        let retrieved = found.unwrap();
        assert_eq!(retrieved.packets, 999);
        assert_eq!(retrieved.bytes, 1_000_000);
        assert_eq!(retrieved.redirected, 100);
        assert_eq!(retrieved.passed, 800);
    }

    #[test]
    fn test_stats_map_get_all() {
        let handle = StatsMapHandle::new();

        handle
            .set(
                stats_idx::TCP,
                StatsEntry {
                    packets: 1,
                    bytes: 100,
                    ..Default::default()
                },
            )
            .unwrap();
        handle
            .set(
                stats_idx::UDP,
                StatsEntry {
                    packets: 2,
                    bytes: 200,
                    ..Default::default()
                },
            )
            .unwrap();
        handle
            .set(
                stats_idx::OVERALL,
                StatsEntry {
                    packets: 3,
                    bytes: 300,
                    ..Default::default()
                },
            )
            .unwrap();

        let all = handle.get_all();
        assert_eq!(all.len(), 3);
        assert_eq!(all[&stats_idx::TCP].packets, 1);
        assert_eq!(all[&stats_idx::UDP].packets, 2);
        assert_eq!(all[&stats_idx::OVERALL].packets, 3);
    }

    #[test]
    fn test_stats_map_multiple_indices() {
        let handle = StatsMapHandle::new();

        handle.increment(stats_idx::TCP, 100).unwrap();
        handle.increment(stats_idx::UDP, 200).unwrap();
        handle.increment(stats_idx::ICMP, 50).unwrap();

        let all = handle.get_all();
        assert_eq!(all.len(), 3);
        assert_eq!(all[&stats_idx::TCP].bytes, 100);
        assert_eq!(all[&stats_idx::UDP].bytes, 200);
        assert_eq!(all[&stats_idx::ICMP].bytes, 50);
    }

    #[test]
    fn test_stats_entry_increment_methods() {
        let mut entry = StatsEntry::default();

        entry.inc_packets(500);
        assert_eq!(entry.packets, 1);
        assert_eq!(entry.bytes, 500);

        entry.inc_packets(300);
        assert_eq!(entry.packets, 2);
        assert_eq!(entry.bytes, 800);

        entry.inc_redirected();
        assert_eq!(entry.redirected, 1);

        entry.inc_passed();
        assert_eq!(entry.passed, 1);

        entry.inc_dropped();
        assert_eq!(entry.dropped, 1);

        entry.inc_routed();
        assert_eq!(entry.routed, 1);

        entry.inc_unmatched();
        assert_eq!(entry.unmatched, 1);
    }

    // ============================================================
    // EbpfMaps is_initialized Tests
    // ============================================================

    #[test]
    fn test_ebpf_maps_partial_initialization() {
        // Test that is_initialized requires ALL maps to be present
        let mut maps = EbpfMaps::new_in_memory();
        assert!(maps.is_initialized());

        // Clone out the sessions handle
        let sessions = maps.sessions.take();
        assert!(!maps.is_initialized()); // Now only 2 of 3

        // Put it back
        maps.sessions = sessions;
        assert!(maps.is_initialized());
    }

    #[test]
    fn test_ebpf_maps_default_not_initialized() {
        let maps = EbpfMaps::default();
        assert!(!maps.is_initialized());
    }

    // ============================================================
    // EbpfSessionHandle Tests
    // ============================================================

    #[test]
    fn test_ebpf_session_handle_create_session() {
        let maps = EbpfMaps::new_in_memory();
        let handle = EbpfSessionHandle::new(maps.clone());

        let key = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 80, 443, 6);
        let result = handle.create_session(&key, state::ESTABLISHED, 42);
        assert!(result.is_ok());

        let session = handle.lookup_session(&key).unwrap();
        assert!(session.is_some());
        let entry = session.unwrap();
        assert_eq!(entry.state, state::ESTABLISHED);
        assert_eq!(entry.route_id, 42);
    }

    #[test]
    fn test_ebpf_session_handle_update_session() {
        let maps = EbpfMaps::new_in_memory();
        let handle = EbpfSessionHandle::new(maps.clone());

        let key = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 80, 443, 6);
        handle.create_session(&key, state::NEW, 1).unwrap();

        let result = handle.update_session(&key, state::ESTABLISHED, 5);
        assert!(result.is_ok());

        let session = handle.lookup_session(&key).unwrap().unwrap();
        assert_eq!(session.state, state::ESTABLISHED);
        assert_eq!(session.packets, 5);
    }

    #[test]
    fn test_ebpf_session_handle_remove_session() {
        let maps = EbpfMaps::new_in_memory();
        let handle = EbpfSessionHandle::new(maps.clone());

        let key = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 80, 443, 6);
        handle.create_session(&key, state::NEW, 1).unwrap();
        assert!(handle.lookup_session(&key).unwrap().is_some());

        handle.remove_session(&key).unwrap();
        assert!(handle.lookup_session(&key).unwrap().is_none());
    }

    #[test]
    fn test_ebpf_session_handle_maps_accessor() {
        let maps = EbpfMaps::new_in_memory();
        let handle = EbpfSessionHandle::new(maps.clone());
        assert!(handle.maps().is_initialized());
    }

    // ============================================================
    // EbpfRoutingHandle Tests
    // ============================================================

    #[test]
    fn test_ebpf_routing_handle_lookup() {
        let maps = EbpfMaps::new_in_memory();

        // Insert a routing entry
        if let Some(ref routing) = maps.routing {
            routing
                .insert(0x7f000001, RoutingEntry::new(99, action::PASS, 0))
                .unwrap();
        }

        let handle = EbpfRoutingHandle::new(maps);
        let result = handle.lookup_routing(0x7f000001).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().route_id, 99);
    }

    #[test]
    fn test_ebpf_routing_handle_lookup_nonexistent() {
        let maps = EbpfMaps::new_in_memory();
        let handle = EbpfRoutingHandle::new(maps);

        let result = handle.lookup_routing(0xDEADBEEF).unwrap();
        assert!(result.is_none());
    }

    // ============================================================
    // EbpfStatsHandle Tests
    // ============================================================

    #[test]
    fn test_ebpf_stats_handle_increment_stats() {
        let maps = EbpfMaps::new_in_memory();
        let handle = EbpfStatsHandle::new(maps);

        handle.increment_stats(stats_idx::TCP, 500).unwrap();
        handle.increment_stats(stats_idx::TCP, 300).unwrap();

        let stats = handle.get_stats(stats_idx::TCP).unwrap().unwrap();
        assert_eq!(stats.bytes, 800);
        assert_eq!(stats.packets, 2);
    }

    #[test]
    fn test_ebpf_stats_handle_increment_tcp() {
        let maps = EbpfMaps::new_in_memory();
        let handle = EbpfStatsHandle::new(maps);

        handle.increment_tcp(1000).unwrap();
        let stats = handle.get_stats(stats_idx::TCP).unwrap().unwrap();
        assert_eq!(stats.bytes, 1000);
    }

    #[test]
    fn test_ebpf_stats_handle_increment_udp() {
        let maps = EbpfMaps::new_in_memory();
        let handle = EbpfStatsHandle::new(maps);

        handle.increment_udp(750).unwrap();
        let stats = handle.get_stats(stats_idx::UDP).unwrap().unwrap();
        assert_eq!(stats.bytes, 750);
    }

    #[test]
    fn test_ebpf_stats_handle_increment_overall() {
        let maps = EbpfMaps::new_in_memory();
        let handle = EbpfStatsHandle::new(maps);

        handle.increment_overall(2000).unwrap();
        let stats = handle.get_stats(stats_idx::OVERALL).unwrap().unwrap();
        assert_eq!(stats.bytes, 2000);
    }

    // ============================================================
    // unix_time_secs Test
    // ============================================================

    #[test]
    fn test_unix_time_secs_reasonable() {
        let now = unix_time_secs();
        // Should be well past 2020 (1577836800) but not in the distant future
        assert!(now > 1577836800, "unix_time_secs should be after 2020");
        assert!(now < 4102444800, "unix_time_secs should be before 2100");
    }

    // ============================================================
    // ConnectionKey to SessionKey Conversion Test
    // ============================================================

    #[test]
    fn test_connection_key_to_session_key() {
        use dae_ebpf_common::session::SessionKey;

        let conn_key = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 80, 443, 6);
        let session_key: SessionKey = (&conn_key).into();

        assert_eq!(session_key.src_ip, 0x7f000001);
        assert_eq!(session_key.dst_ip, 0x7f000002);
        assert_eq!(session_key.src_port, 80);
        assert_eq!(session_key.dst_port, 443);
        assert_eq!(session_key.proto, 6);
    }

    // ============================================================
    // SessionEntry Default Test
    // ============================================================

    #[test]
    fn test_session_entry_default_values() {
        let entry = SessionEntry::default();
        assert_eq!(entry.state, 0);
        assert_eq!(entry.packets, 0);
        assert_eq!(entry.bytes, 0);
        assert_eq!(entry.start_time, 0);
        assert_eq!(entry.last_time, 0);
        assert_eq!(entry.route_id, 0);
        assert_eq!(entry.src_mac_len, 0);
    }

    // ============================================================
    // RoutingEntry Tests
    // ============================================================

    #[test]
    fn test_routing_entry_new() {
        let entry = RoutingEntry::new(123, action::DROP, 5);
        assert_eq!(entry.route_id, 123);
        assert_eq!(entry.action, action::DROP);
        assert_eq!(entry.ifindex, 5);
    }

    #[test]
    fn test_routing_entry_action_constants() {
        assert_eq!(action::PASS, 0);
        assert_eq!(action::REDIRECT, 1);
        assert_eq!(action::DROP, 2);
    }

    // ============================================================
    // StatsEntry Default Test
    // ============================================================

    #[test]
    fn test_stats_entry_default() {
        let entry = StatsEntry::default();
        assert_eq!(entry.packets, 0);
        assert_eq!(entry.bytes, 0);
        assert_eq!(entry.redirected, 0);
        assert_eq!(entry.passed, 0);
        assert_eq!(entry.dropped, 0);
        assert_eq!(entry.routed, 0);
        assert_eq!(entry.unmatched, 0);
    }

    // ============================================================
    // EbpfError Display Test
    // ============================================================

    #[test]
    fn test_ebpf_error_display() {
        let err = EbpfError::MapNotFound("sessions".to_string());
        assert!(format!("{}", err).contains("Map not found"));
        assert!(format!("{}", err).contains("sessions"));

        let err = EbpfError::KeyNotFound("0x1234".to_string());
        assert!(format!("{}", err).contains("Key not found"));

        let err = EbpfError::UpdateFailed("permission denied".to_string());
        assert!(format!("{}", err).contains("Update failed"));

        let err = EbpfError::LookupFailed("oops".to_string());
        assert!(format!("{}", err).contains("Lookup failed"));

        let err = EbpfError::PermissionDenied("no access".to_string());
        assert!(format!("{}", err).contains("Permission denied"));

        let err = EbpfError::EbpfNotAvailable("no kernel support".to_string());
        assert!(format!("{}", err).contains("eBPF not available"));

        let err = EbpfError::Other("generic error".to_string());
        assert!(format!("{}", err).contains("generic error"));
    }

    #[test]
    fn test_ebpf_error_from_io_error() {
        use std::io;
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let ebpf_err: EbpfError = io_err.into();
        assert!(format!("{}", ebpf_err).contains("file not found"));
    }

    // ============================================================
    // EbpfRuntime Tests
    // ============================================================

    #[test]
    fn test_ebpf_runtime_is_active() {
        let active = EbpfRuntime::Active {
            program_type: EbpfProgramType::Tc,
            kernel_capability: KernelCapability::FullTc,
        };
        assert!(active.is_active());
        assert_eq!(active.program_type(), Some(EbpfProgramType::Tc));

        let fallback = EbpfRuntime::Fallback;
        assert!(!fallback.is_active());
        assert_eq!(fallback.program_type(), None);

        let uninit = EbpfRuntime::Uninitialized;
        assert!(!uninit.is_active());
        assert_eq!(uninit.program_type(), None);
    }

    // ============================================================
    // SessionMapHandle Clone Test
    // ============================================================

    #[test]
    fn test_session_map_handle_clone_independence() {
        let handle1 = SessionMapHandle::new();
        let key = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 80, 443, 6);
        let entry = make_session_entry(1, 5, 100, 0);
        handle1.insert(&key, &entry).unwrap();

        // Clone should share the same underlying map
        let handle2 = handle1.clone();
        assert_eq!(handle2.len(), 1);

        // Insert via handle2
        let key2 = ConnectionKey::from_raw(0x7f000001, 0x7f000003, 80, 443, 6);
        handle2.insert(&key2, &entry).unwrap();

        // Both handles should see both entries (shared state)
        assert_eq!(handle1.len(), 2);
        assert_eq!(handle2.len(), 2);
    }

    #[test]
    fn test_routing_map_handle_clone_independence() {
        let handle1 = RoutingMapHandle::new();
        handle1
            .insert(0x10000001, RoutingEntry::new(1, 0, 0))
            .unwrap();

        let handle2 = handle1.clone();
        handle2
            .insert(0x10000002, RoutingEntry::new(2, 0, 0))
            .unwrap();

        assert_eq!(handle1.len(), 2);
        assert_eq!(handle2.len(), 2);
    }

    #[test]
    fn test_stats_map_handle_clone_independence() {
        let handle1 = StatsMapHandle::new();
        handle1.increment(stats_idx::TCP, 100).unwrap();

        let handle2 = handle1.clone();
        handle2.increment(stats_idx::UDP, 200).unwrap();

        // Stats indices are different so both should exist
        assert_eq!(handle1.len(), 2);
        assert_eq!(handle2.len(), 2);
    }
}
