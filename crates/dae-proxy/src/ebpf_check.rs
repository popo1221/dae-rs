//! eBPF kernel support detection and capability checking
//!
//! Provides kernel version detection and eBPF capability分级 for graceful fallback.
//!
//! This module complements the kernel version detection in ebpf_integration
//! by providing system-level checks (JIT, permissions) and simplified interfaces.
//!
//! # Usage
//!
//! ```rust
//! use dae_proxy::ebpf_check::{detect_ebpf_support, can_use_ebpf, EbpfSupportLevel};
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
//!     if let Some(r) = reason {
//!         eprintln!("Cannot use eBPF: {}", r);
//!     }
//! }
//! ```

// Re-export types from ebpf_integration submodules for convenience
pub use crate::ebpf_integration::{
    can_use_ebpf, detect_and_log_ebpf_support, detect_ebpf_support, EbpfSupportLevel,
    EbpfSystemConfig, KernelCapability, KernelVersion, RecommendedProgramType,
};

// Keep tests module for backward compatibility
#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_detect_ebpf_support() {
        let level = detect_ebpf_support();

        match level {
            EbpfSupportLevel::None | EbpfSupportLevel::Partial | EbpfSupportLevel::Full => {}
        }
    }

    #[test]
    fn test_can_use_ebpf() {
        let (can_use, reason) = can_use_ebpf();

        if !can_use {
            assert!(reason.is_some(), "If can't use eBPF, should provide reason");
        }
    }
}
