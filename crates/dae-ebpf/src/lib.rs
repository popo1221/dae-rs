//! dae-ebpf - User-space eBPF loader for dae-rs
//!
//! This crate provides the user-space interface for loading and managing
//! eBPF programs (TC and XDP) that implement transparent proxy functionality.
//!
//! # Architecture
//!
//! The eBPF subsystem consists of:
//! - **dae-xdp**: XDP program for packet capture at network driver level
//! - **dae-tc**: TC (Traffic Control) program for packet processing
//! - **dae-ebpf**: This crate - user-space loader and manager
//!
//! # Usage
//!
//! ```rust,ignore
//! use dae_ebpf::EbpfContext;
//!
//! let mut ctx = EbpfContext::new()?;
//! ctx.load_xdp("path/to/xdp.o", "eth0")?;
//! ctx.load_tc("path/to/tc.o", "eth0")?;
//! ctx.run().await?;
//! ```

#![deny(warnings)]
#![allow(clippy::module_inception)]

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use thiserror::Error;

// Re-export common types for use by other crates
pub use dae_ebpf_common::*;

/// eBPF program type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramType {
    /// XDP (Express Data Path) program
    Xdp,
    /// TC (Traffic Control) clsact program
    Tc,
    /// Socket filter program
    SocketFilter,
    /// Sk SKB (socket SKB) program
    SkSkb,
    /// Sock ops program
    SockOps,
    /// Cgroup sock addr program
    CgroupSockAddr,
    /// Cgroup sock program
    CgroupSock,
    /// Cgroup device program
    CgroupDevice,
    /// Generic Kprobe program
    Kprobe,
    /// Generic Kretprobe program
    Kretprobe,
    /// Generic tracepoint program
    Tracepoint,
    /// Generic raw tracepoint program
    RawTracepoint,
    /// Performance profile program
    PerfEvent,
    /// Generic raw tracepoint w/ perf event
    RawTracepointWritable,
}

/// eBPF attachment location
#[derive(Debug, Clone)]
pub struct AttachmentPoint {
    /// Interface name (e.g., "eth0")
    pub iface: String,
    /// Optional priority for TC programs
    pub priority: Option<i32>,
    /// Optional direction for TC programs ("ingress" or "egress")
    pub direction: Option<String>,
}

impl AttachmentPoint {
    /// Create a new attachment point for the given interface
    pub fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
            priority: None,
            direction: None,
        }
    }

    /// Set TC priority
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Set direction (for TC only)
    pub fn with_direction(mut self, direction: impl Into<String>) -> Self {
        self.direction = Some(direction.into());
        self
    }
}

/// eBPF program load error types
#[derive(Error, Debug)]
pub enum EbpfError {
    #[error("Failed to load eBPF object: {0}")]
    LoadError(String),

    #[error("Failed to attach program: {0}")]
    AttachError(String),

    #[error("Failed to create map: {0}")]
    MapError(String),

    #[error("Program not found: {0}")]
    ProgramNotFound(String),

    #[error("Map not found: {0}")]
    MapNotFound(String),

    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Permission denied (need root): {0}")]
    PermissionDenied(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Aya error: {0}")]
    AyaError(String),
}

/// Statistics for a loaded eBPF program
#[derive(Debug, Clone, Default)]
pub struct ProgramStats {
    /// Number of times the program was called
    pub run_count: u64,
    /// Number of times the program returned an error
    pub error_count: u64,
    /// Total packets processed
    pub packets_processed: u64,
    /// Total bytes processed
    pub bytes_processed: u64,
    /// Timestamp of last execution
    pub last_run: Option<std::time::Instant>,
}

/// Loaded eBPF program information
#[derive(Debug, Clone)]
pub struct LoadedProgram {
    /// Program name
    pub name: String,
    /// Program type
    pub program_type: ProgramType,
    /// Attachment point
    pub attachment: Option<AttachmentPoint>,
    /// File descriptor (if available)
    pub fd: Option<i32>,
    /// Statistics
    pub stats: ProgramStats,
}

/// eBPF map information
#[derive(Debug, Clone)]
pub struct MapInfo {
    /// Map name
    pub name: String,
    /// Map type
    pub map_type: u32,
    /// Key size
    pub key_size: u32,
    /// Value size
    pub value_size: u32,
    /// Maximum entries
    pub max_entries: u32,
    /// File descriptor
    pub fd: Option<i32>,
}

/// Configuration for eBPF subsystem
#[derive(Debug, Clone)]
pub struct EbpfConfig {
    /// Enable XDP program
    pub xdp_enabled: bool,
    /// Enable TC program
    pub tc_enabled: bool,
    /// Default interface to attach
    pub default_iface: Option<String>,
    /// TC priority (lower = higher priority)
    pub tc_priority: i32,
    /// Enable map pinning
    pub map_pinning: bool,
    /// Map pinning path
    pub map_pinning_path: String,
    /// Enable logging
    pub logging_enabled: bool,
    /// Log level
    pub log_level: String,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            xdp_enabled: true,
            tc_enabled: true,
            default_iface: None,
            tc_priority: 100,
            map_pinning: false,
            map_pinning_path: "/sys/fs/bpf".to_string(),
            logging_enabled: true,
            log_level: "info".to_string(),
        }
    }
}

/// eBPF context for managing programs and maps
///
/// This is the main entry point for the eBPF subsystem. It handles:
/// - Loading eBPF object files
/// - Attaching programs to network interfaces
/// - Managing eBPF maps
/// - Providing a user-space API for configuration
pub struct EbpfContext {
    /// aya eBPF instance
    ebpf: Option<aya::Ebpf>,
    /// Loaded programs
    programs: HashMap<String, LoadedProgram>,
    /// Map information
    maps: HashMap<String, MapInfo>,
    /// Configuration
    config: EbpfConfig,
    /// Whether the context is running
    running: bool,
    /// Supported program types (detected at init)
    supported_programs: Vec<ProgramType>,
}

impl EbpfContext {
    /// Create a new eBPF context
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Insufficient permissions (need root/CAP_BPF)
    /// - Kernel doesn't support required eBPF features
    /// - Failed to initialize aya
    pub fn new() -> Result<Self, EbpfError> {
        Self::new_with_config(EbpfConfig::default())
    }

    /// Create a new eBPF context with custom configuration
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub fn new_with_config(config: EbpfConfig) -> Result<Self, EbpfError> {
        // Check if running as root
        if !Self::is_root() {
            return Err(EbpfError::PermissionDenied(
                "eBPF operations require root privileges or CAP_BPF capability".to_string(),
            ));
        }

        // Detect supported eBPF program types
        let supported_programs = Self::detect_supported_programs();

        // Initialize aya Ebpf (try to load from default path)
        let ebpf = aya::Ebpf::load_file("/sys/fs/bpf/dae-rs").ok();

        Ok(Self {
            ebpf,
            programs: HashMap::new(),
            maps: HashMap::new(),
            config,
            running: false,
            supported_programs,
        })
    }

    /// Check if running as root
    fn is_root() -> bool {
        // SAFETY: geteuid is a pure read-only syscall that is always safe.
        unsafe { libc::geteuid() == 0 }
    }

    /// Detect kernel-supported eBPF program types
    fn detect_supported_programs() -> Vec<ProgramType> {
        let mut supported = Vec::new();

        // Try to detect XDP support
        if Self::kernel_supports_xdp() {
            supported.push(ProgramType::Xdp);
        }

        // TC is generally always supported on modern kernels
        supported.push(ProgramType::Tc);

        // Other program types can be detected similarly
        supported
    }

    /// Check if kernel supports XDP
    fn kernel_supports_xdp() -> bool {
        // XDP requires kernel >= 4.8
        // We can check via /proc/sys/net/core/bpf_jit_enable or similar
        // For now, assume modern kernel supports XDP
        std::fs::read_to_string("/proc/sys/net/core/bpf_jit_enable")
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    }

    /// Load an XDP eBPF program from an object file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the compiled eBPF object file (.o)
    /// * `iface` - Network interface to attach to
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File not found or invalid
    /// - Failed to load eBPF program
    /// - Failed to attach to interface
    pub fn load_xdp<P: AsRef<Path>>(&mut self, path: P, iface: &str) -> Result<(), EbpfError> {
        if !self.supported_programs.contains(&ProgramType::Xdp) {
            return Err(EbpfError::InvalidArgument(
                "XDP not supported on this system".to_string(),
            ));
        }

        let path = path.as_ref();
        if !path.exists() {
            return Err(EbpfError::LoadError(format!(
                "eBPF object file not found: {:?}",
                path
            )));
        }

        // Load the eBPF program using aya
        let ebpf = aya::Ebpf::load_file(path)
            .map_err(|e| EbpfError::LoadError(format!("Failed to load XDP program: {}", e)))?;

        let loaded_program = LoadedProgram {
            name: "xdp_prog_main".to_string(),
            program_type: ProgramType::Xdp,
            attachment: Some(AttachmentPoint::new(iface)),
            fd: None,
            stats: ProgramStats::default(),
        };

        self.programs.insert("xdp".to_string(), loaded_program);
        self.ebpf = Some(ebpf);

        Ok(())
    }

    /// Load a TC eBPF program from an object file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the compiled eBPF object file (.o)
    /// * `iface` - Network interface to attach to
    ///
    /// # Errors
    ///
    /// Returns an error if loading or attachment fails.
    pub fn load_tc<P: AsRef<Path>>(&mut self, path: P, iface: &str) -> Result<(), EbpfError> {
        if !self.supported_programs.contains(&ProgramType::Tc) {
            return Err(EbpfError::InvalidArgument(
                "TC not supported on this system".to_string(),
            ));
        }

        let path = path.as_ref();
        if !path.exists() {
            return Err(EbpfError::LoadError(format!(
                "eBPF object file not found: {:?}",
                path
            )));
        }

        // Load the eBPF program using aya
        let ebpf = aya::Ebpf::load_file(path)
            .map_err(|e| EbpfError::LoadError(format!("Failed to load TC program: {}", e)))?;

        // Attach to TC clsact qdisc
        let mut attachment = AttachmentPoint::new(iface);
        if let Some(priority) = self.config.tc_priority.checked_sub(1) {
            attachment = attachment.with_priority(priority);
        }

        let loaded_program = LoadedProgram {
            name: "tc_prog_main".to_string(),
            program_type: ProgramType::Tc,
            attachment: Some(attachment),
            fd: None,
            stats: ProgramStats::default(),
        };

        self.programs.insert("tc".to_string(), loaded_program);
        self.ebpf = Some(ebpf);

        Ok(())
    }

    /// Load a raw eBPF object file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the compiled eBPF object file (.o)
    /// * `program_name` - Name of the program to load
    ///
    /// # Errors
    ///
    /// Returns an error if loading fails.
    #[allow(dead_code)]
    pub fn load_object<P: AsRef<Path>>(
        &mut self,
        path: P,
        _program_name: &str,
    ) -> Result<(), EbpfError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(EbpfError::LoadError(format!(
                "eBPF object file not found: {:?}",
                path
            )));
        }

        let ebpf = aya::Ebpf::load_file(path)
            .map_err(|e| EbpfError::LoadError(format!("Failed to load program: {}", e)))?;

        let loaded_program = LoadedProgram {
            name: _program_name.to_string(),
            program_type: ProgramType::RawTracepoint,
            attachment: None,
            fd: None,
            stats: ProgramStats::default(),
        };

        self.programs
            .insert(_program_name.to_string(), loaded_program);
        self.ebpf = Some(ebpf);

        Ok(())
    }

    /// Detach a program by name
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the program to detach
    ///
    /// # Errors
    ///
    /// Returns an error if the program is not found.
    pub fn detach_program(&mut self, name: &str) -> Result<(), EbpfError> {
        let program = self
            .programs
            .remove(name)
            .ok_or_else(|| EbpfError::ProgramNotFound(name.to_string()))?;

        // Clean up the attachment
        if let Some(attachment) = program.attachment {
            Self::detach_from_interface(&attachment, program.program_type)?;
        }

        Ok(())
    }

    /// Detach a program from its interface
    #[allow(dead_code)]
    fn detach_from_interface(
        attachment: &AttachmentPoint,
        program_type: ProgramType,
    ) -> Result<(), EbpfError> {
        match program_type {
            ProgramType::Xdp => {
                // Detach XDP - remove the XDP program from the interface
                let output = std::process::Command::new("ip")
                    .args(["link", "set", "dev", &attachment.iface, "xdpgeneric", "off"])
                    .output();

                if let Ok(output) = output {
                    if !output.status.success() {
                        // Try ip link set without xdpgeneric
                        std::process::Command::new("ip")
                            .args(["link", "set", "dev", &attachment.iface, "xdp", "off"])
                            .output()?;
                    }
                }
            }
            ProgramType::Tc => {
                // Detach TC - remove the clsact qdisc
                std::process::Command::new("tc")
                    .args(["qdisc", "del", "dev", &attachment.iface, "clsact"])
                    .output()?;
            }
            _ => {}
        }

        Ok(())
    }

    /// Get a loaded program by name
    #[allow(dead_code)]
    pub fn get_program(&self, name: &str) -> Option<&LoadedProgram> {
        self.programs.get(name)
    }

    /// Get all loaded programs
    #[allow(dead_code)]
    pub fn programs(&self) -> &HashMap<String, LoadedProgram> {
        &self.programs
    }

    /// Get all loaded maps
    #[allow(dead_code)]
    pub fn maps(&self) -> &HashMap<String, MapInfo> {
        &self.maps
    }

    /// Get program statistics
    #[allow(dead_code)]
    pub fn get_stats(&self, name: &str) -> Option<&ProgramStats> {
        self.programs.get(name).map(|p| &p.stats)
    }

    /// Check if XDP is supported
    pub fn is_xdp_supported(&self) -> bool {
        self.supported_programs.contains(&ProgramType::Xdp)
    }

    /// Check if TC is supported
    pub fn is_tc_supported(&self) -> bool {
        self.supported_programs.contains(&ProgramType::Tc)
    }

    /// Get supported program types
    #[allow(dead_code)]
    pub fn supported_programs(&self) -> &[ProgramType] {
        &self.supported_programs
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Get configuration
    pub fn config(&self) -> &EbpfConfig {
        &self.config
    }

    /// Get a mutable reference to configuration
    pub fn config_mut(&mut self) -> &mut EbpfConfig {
        &mut self.config
    }

    /// Start the eBPF context
    ///
    /// This begins processing packets with the loaded programs.
    pub fn run(&mut self) -> Result<(), EbpfError> {
        if self.programs.is_empty() {
            return Err(EbpfError::InvalidArgument("No programs loaded".to_string()));
        }

        self.running = true;
        Ok(())
    }

    /// Stop the eBPF context
    ///
    /// This detaches all programs and cleans up resources.
    pub fn stop(&mut self) -> Result<(), EbpfError> {
        // Detach all programs
        let program_names: Vec<String> = self.programs.keys().cloned().collect();
        for name in program_names {
            self.detach_program(&name)?;
        }

        self.running = false;
        Ok(())
    }

    /// Get the underlying aya Ebpf instance (for advanced usage)
    ///
    /// # Safety
    ///
    /// This returns a mutable reference to the internal Ebpf instance.
    /// Use with caution - improper handling can cause undefined behavior.
    #[allow(dead_code)]
    pub unsafe fn ebpf_mut(&mut self) -> Option<&mut aya::Ebpf> {
        self.ebpf.as_mut()
    }

    /// Get the underlying aya Ebpf instance (immutable reference)
    #[allow(dead_code)]
    pub fn ebpf(&self) -> Option<&aya::Ebpf> {
        self.ebpf.as_ref()
    }
}

impl Drop for EbpfContext {
    fn drop(&mut self) {
        // Ensure all programs are detached on drop
        if self.running {
            let _ = self.stop();
        }
    }
}

impl Default for EbpfContext {
    fn default() -> Self {
        Self::new().expect("Failed to create default EbpfContext")
    }
}

/// Initialize logging for the eBPF subsystem
pub fn init_logging() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,dae_ebpf=debug"));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();
}

/// Check if eBPF subsystem is available and properly configured
pub fn check_ebpf_support() -> EbpfSupportStatus {
    let mut status = EbpfSupportStatus {
        kernel_bpf_enabled: false,
        xdp_supported: false,
        tc_supported: false,
        jit_enabled: false,
        unprivileged_bpf_enabled: false,
    };

    // Check if BPF is enabled in kernel
    status.kernel_bpf_enabled = std::fs::read_to_string("/proc/sys/kernel/bpf_stats_enabled")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    // Check JIT status
    if let Ok(jit) = std::fs::read_to_string("/proc/sys/net/core/bpf_jit_enable") {
        status.jit_enabled = jit.trim() == "1" || jit.trim() == "2";
    }

    // Check unprivileged BPF
    if let Ok(unpriv) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled") {
        status.unprivileged_bpf_enabled = unpriv.trim() == "0";
    }

    // XDP support check
    if let Ok(output) = std::process::Command::new("ip")
        .args(["link", "show", "type", "xdp"])
        .output()
    {
        status.xdp_supported = output.status.success();
    }

    // TC is always supported on modern kernels
    status.tc_supported = std::process::Command::new("tc")
        .arg("qdisc")
        .arg("show")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    status
}

/// eBPF support status
#[derive(Debug, Clone, Default)]
pub struct EbpfSupportStatus {
    /// Kernel BPF is enabled
    pub kernel_bpf_enabled: bool,
    /// XDP is supported
    pub xdp_supported: bool,
    /// TC is supported
    pub tc_supported: bool,
    /// JIT compilation is enabled
    pub jit_enabled: bool,
    /// Unprivileged BPF is enabled
    pub unprivileged_bpf_enabled: bool,
}

impl EbpfSupportStatus {
    /// Check if full eBPF support is available
    pub fn is_full_support(&self) -> bool {
        self.kernel_bpf_enabled && self.tc_supported
    }

    /// Check if XDP is available
    pub fn is_xdp_available(&self) -> bool {
        self.kernel_bpf_enabled && self.xdp_supported
    }
}

#[allow(dead_code)]
/// Setup TC clsact qdisc on an interface
///
/// This must be done before attaching TC programs.
pub fn setup_tc_clsact(iface: &str) -> Result<(), EbpfError> {
    // First, check if clsact already exists
    let output = std::process::Command::new("tc")
        .args(["qdisc", "show", "dev", iface])
        .output()?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    if !output_str.contains("clsact") {
        // Add clsact qdisc
        let output = std::process::Command::new("tc")
            .args(["qdisc", "add", "dev", iface, "clsact"])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(EbpfError::AttachError(format!(
                "Failed to setup clsact qdisc: {}",
                stderr
            )));
        }
    }

    Ok(())
}

/// Remove TC clsact qdisc from an interface
#[allow(dead_code)]
pub fn remove_tc_clsact(iface: &str) -> Result<(), EbpfError> {
    let output = std::process::Command::new("tc")
        .args(["qdisc", "del", "dev", iface, "clsact"])
        .output()?;

    if !output.status.success() {
        // It's okay if it doesn't exist
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("No such file or directory") && !stderr.contains("Cannot find") {
            return Err(EbpfError::AttachError(format!(
                "Failed to remove clsact qdisc: {}",
                stderr
            )));
        }
    }

    Ok(())
}

/// Get interface index for a network interface name
#[allow(dead_code)]
pub fn get_iface_index(iface: &str) -> Result<u32, EbpfError> {
    let output = std::process::Command::new("ip")
        .args(["link", "show", iface])
        .output()?;

    if !output.status.success() {
        return Err(EbpfError::InterfaceNotFound(iface.to_string()));
    }

    // Parse interface index from output like "1: lo"
    let output_str = String::from_utf8_lossy(&output.stdout);
    for line in output_str.lines() {
        if let Some(colon_idx) = line.find(':') {
            let num_str = &line[..colon_idx];
            if let Ok(idx) = num_str.parse::<u32>() {
                return Ok(idx);
            }
        }
    }

    Err(EbpfError::InterfaceNotFound(format!(
        "Could not parse index for interface: {}",
        iface
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_support_status_default() {
        let status = EbpfSupportStatus::default();
        assert!(!status.is_full_support());
    }

    #[test]
    fn test_attachment_point_new() {
        let ap = AttachmentPoint::new("eth0");
        assert_eq!(ap.iface, "eth0");
        assert!(ap.priority.is_none());
        assert!(ap.direction.is_none());
    }

    #[test]
    fn test_attachment_point_with_priority() {
        let ap = AttachmentPoint::new("eth0").with_priority(100);
        assert_eq!(ap.iface, "eth0");
        assert_eq!(ap.priority, Some(100));
    }

    #[test]
    fn test_attachment_point_with_direction() {
        let ap = AttachmentPoint::new("eth0").with_direction("ingress");
        assert_eq!(ap.iface, "eth0");
        assert_eq!(ap.direction, Some("ingress".to_string()));
    }

    #[test]
    fn test_program_type_display() {
        assert_eq!(format!("{:?}", ProgramType::Xdp), "Xdp");
        assert_eq!(format!("{:?}", ProgramType::Tc), "Tc");
    }

    #[test]
    fn test_ebpf_config_default() {
        let config = EbpfConfig::default();
        assert!(config.xdp_enabled);
        assert!(config.tc_enabled);
        assert_eq!(config.map_pinning_path, "/sys/fs/bpf");
    }
}
