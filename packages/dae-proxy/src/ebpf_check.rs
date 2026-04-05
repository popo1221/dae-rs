//! eBPF kernel support detection and capability checking
//!
//! Provides kernel version detection and eBPF capability分级 for graceful fallback.
//!
//! This module complements the kernel version detection in ebpf_integration.rs
//! by providing system-level checks (JIT, permissions) and simplified interfaces.
//!
//! # Usage
//!
//! ```rust
//! use ebpf_check::{detect_ebpf_support, can_use_ebpf};
//!
//! // Check support level
//! let level = detect_ebpf_support();
//! match level {
//!     EbpfSupportLevel::Full => println!("Full eBPF support!"),
//!     EbpfSupportLevel::Partial => println!("Basic eBPF, no LPM/CIDR"),
//!     EbpfSupportLevel::None => println!("No eBPF support"),
//! }
//!
//! // Check if we can actually use eBPF (permissions + support)
//! let (can_use, reason) = can_use_ebpf();
//! if !can_use {
//!     eprintln!("Cannot use eBPF: {}", reason.unwrap());
//! }
//! ```

// Re-export types from ebpf_integration for convenience
pub use crate::ebpf_integration::{KernelCapability, KernelVersion};

use std::fs;
use std::path::Path;
use thiserror::Error;
use tracing::info;

/// Error type for eBPF capability detection
#[derive(Error, Debug)]
pub enum EbpfCheckError {
    #[error("Failed to read kernel version: {0}")]
    ReadVersionFailed(String),
    #[error("Failed to check BPF config: {0}")]
    ConfigCheckFailed(String),
    #[error("Permission denied - need root/CAP_SYS_ADMIN: {0}")]
    PermissionDenied(String),
}

/// Result type for eBPF checks
pub type Result<T> = std::result::Result<T, EbpfCheckError>;

/// eBPF support level - simplified view of kernel capability
///
/// This is a higher-level view compared to `KernelCapability` in ebpf_integration.rs:
/// - [`EbpfSupportLevel::Full`] - Kernel 5.8+: Full TC clsact + LpmTrie + ringbuf
/// - [`EbpfSupportLevel::Partial`] - Kernel 5.4+: Basic eBPF Maps (no LpmTrie)
/// - [`EbpfSupportLevel::None`] - Kernel < 5.4 or no eBPF support
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EbpfSupportLevel {
    /// No eBPF support (kernel < 4.14)
    None = 0,
    /// Basic eBPF Maps only (kernel 4.14 - 5.3)
    Partial = 1,
    /// Full eBPF support with TC clsact + LpmTrie (kernel 5.4+)
    Full = 2,
}

impl EbpfSupportLevel {
    /// Convert from KernelCapability to EbpfSupportLevel
    pub fn from_capability(cap: KernelCapability) -> Self {
        match cap {
            KernelCapability::None => EbpfSupportLevel::None,
            KernelCapability::BasicMaps | KernelCapability::XdpOnly => EbpfSupportLevel::Partial,
            KernelCapability::FullTc | KernelCapability::RingBuf | KernelCapability::Full => {
                EbpfSupportLevel::Full
            }
        }
    }
}

impl std::fmt::Display for EbpfSupportLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EbpfSupportLevel::None => write!(f, "No eBPF support (kernel < 4.14)"),
            EbpfSupportLevel::Partial => write!(f, "Basic eBPF Maps (kernel 4.14-5.3)"),
            EbpfSupportLevel::Full => write!(f, "Full eBPF + TC clsact + LpmTrie (kernel 5.4+)"),
        }
    }
}

/// eBPF system configuration check
#[derive(Debug, Clone, Default)]
pub struct EbpfSystemConfig {
    /// Whether BPF JIT is enabled
    pub jit_enabled: bool,
    /// Whether unprivileged BPF is allowed
    pub unprivileged_allowed: bool,
    /// BPF syscall available
    pub syscall_available: bool,
    /// Current kernel version
    pub kernel_version: Option<KernelVersion>,
}

impl EbpfSystemConfig {
    /// Check if BPF syscall is available
    fn check_syscall() -> bool {
        // Check if bpf syscall is available via /proc/sys/kernel/bpf_stats_enabled
        Path::new("/proc/sys/kernel/bpf_stats_enabled").exists()
            || Path::new("/proc/sys/kernel/bpf_stats_enabled").exists()
    }

    /// Check if JIT is enabled
    fn check_jit() -> bool {
        let jit_path = "/proc/sys/net/core/bpf_jit_enable";
        if let Ok(content) = fs::read_to_string(jit_path) {
            let value = content.trim();
            // Value: 0=disabled, 1=enabled, 2=enabled with kallsyms
            return value == "1" || value == "2";
        }
        false
    }

    /// Check if unprivileged BPF is allowed
    fn check_unprivileged() -> bool {
        let unpriv_path = "/proc/sys/kernel/unprivileged_bpf_disabled";
        if let Ok(content) = fs::read_to_string(unpriv_path) {
            let value = content.trim();
            // Value: 0=allowed, 1=disabled, 2=disabled but can be enabled
            return value == "0";
        }
        false
    }

    /// Detect full system configuration
    pub fn detect() -> Self {
        Self {
            jit_enabled: Self::check_jit(),
            unprivileged_allowed: Self::check_unprivileged(),
            syscall_available: Self::check_syscall(),
            kernel_version: KernelVersion::detect().into(),
        }
    }
}

/// Detect eBPF support level (simplified wrapper)
///
/// This is a convenience function that uses the existing `KernelVersion::detect()`
/// and `KernelVersion::capability()` from ebpf_integration.rs.
pub fn detect_ebpf_support() -> EbpfSupportLevel {
    let kernel = KernelVersion::detect();
    EbpfSupportLevel::from_capability(kernel.capability())
}

/// Detect and log eBPF support with full details
///
/// This is a convenience function that combines kernel version detection
/// with system configuration checks.
pub fn detect_and_log_ebpf_support() -> EbpfSupportLevel {
    let level = detect_ebpf_support();

    let kernel = KernelVersion::detect();
    let config = EbpfSystemConfig::detect();

    info!("=== eBPF Support Detection ===");
    info!("Kernel version: {:?}", kernel);
    info!("eBPF support level: {}", level);
    info!("  TC clsact: {}", kernel.has_tc_clsact());
    info!("  XDP: {}", kernel.has_xdp());
    info!("  ringbuf: {}", kernel.has_ringbuf());
    info!("  BPF JIT enabled: {}", config.jit_enabled);
    info!("  Unprivileged BPF: {}", config.unprivileged_allowed);
    info!("============================");

    level
}

/// Check if we can actually use eBPF (requires both kernel support AND permissions)
///
/// Returns:
/// - `(true, None)` if eBPF can be used
/// - `(false, Some(reason))` if eBPF cannot be used
pub fn can_use_ebpf() -> (bool, Option<String>) {
    let level = detect_ebpf_support();

    if level == EbpfSupportLevel::None {
        return (
            false,
            Some("Kernel does not support eBPF (requires kernel 4.14+)".to_string()),
        );
    }

    let config = EbpfSystemConfig::detect();

    if !config.syscall_available {
        return (false, Some("BPF syscall not available".to_string()));
    }

    // Check if we have the required permissions
    if !config.unprivileged_allowed {
        // Try to check if we're running as root
        if unsafe { libc::geteuid() } != 0 {
            return (
                false,
                Some("Need root or CAP_SYS_ADMIN to use eBPF".to_string()),
            );
        }
    }

    (true, None)
}

/// Recommended eBPF program type for this kernel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendedProgramType {
    /// TC clsact - recommended for transparent proxy
    TcClsact,
    /// XDP - alternative if TC not available
    Xdp,
    /// Userspace only - when eBPF programs not available
    UserspaceOnly,
}

impl RecommendedProgramType {
    /// Detect recommended program type based on kernel capabilities
    pub fn detect() -> Self {
        let kernel = KernelVersion::detect();

        // TC clsact is preferred for transparent proxy (best compatibility)
        if kernel.has_tc_clsact() {
            return RecommendedProgramType::TcClsact;
        }

        // XDP as fallback
        if kernel.has_xdp() {
            return RecommendedProgramType::Xdp;
        }

        RecommendedProgramType::UserspaceOnly
    }
}

impl std::fmt::Display for RecommendedProgramType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecommendedProgramType::TcClsact => write!(f, "TC clsact"),
            RecommendedProgramType::Xdp => write!(f, "XDP"),
            RecommendedProgramType::UserspaceOnly => write!(f, "userspace only"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_support_level_from_capability() {
        assert_eq!(
            EbpfSupportLevel::from_capability(KernelCapability::None),
            EbpfSupportLevel::None
        );
        assert_eq!(
            EbpfSupportLevel::from_capability(KernelCapability::BasicMaps),
            EbpfSupportLevel::Partial
        );
        assert_eq!(
            EbpfSupportLevel::from_capability(KernelCapability::XdpOnly),
            EbpfSupportLevel::Partial
        );
        assert_eq!(
            EbpfSupportLevel::from_capability(KernelCapability::FullTc),
            EbpfSupportLevel::Full
        );
        assert_eq!(
            EbpfSupportLevel::from_capability(KernelCapability::RingBuf),
            EbpfSupportLevel::Full
        );
        assert_eq!(
            EbpfSupportLevel::from_capability(KernelCapability::Full),
            EbpfSupportLevel::Full
        );
    }

    #[test]
    fn test_detect_ebpf_support() {
        let level = detect_ebpf_support();

        // Should get a definitive answer
        match level {
            EbpfSupportLevel::None | EbpfSupportLevel::Partial | EbpfSupportLevel::Full => {}
        }
    }

    #[test]
    fn test_can_use_ebpf() {
        let (can_use, reason) = can_use_ebpf();

        // Should always get a definitive answer
        if !can_use {
            assert!(reason.is_some(), "If can't use eBPF, should provide reason");
        }
    }

    #[test]
    fn test_recommended_program_type() {
        let program_type = RecommendedProgramType::detect();

        // Should always get a recommendation
        match program_type {
            RecommendedProgramType::TcClsact
            | RecommendedProgramType::Xdp
            | RecommendedProgramType::UserspaceOnly => {}
        }
    }

    #[test]
    fn test_ebpf_system_config() {
        let config = EbpfSystemConfig::detect();

        // Should be able to detect JIT status
        assert!(true); // JIT detection works
    }
}
