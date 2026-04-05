//! Kernel Version Detection and eBPF Capability Checking
//!
//! Provides [`KernelVersion`] detection and [`KernelCapability`] levels,
//! plus the simplified [`EbpfSupportLevel`] enum.

use tracing::warn;

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
    /// Major version number
    pub major: u8,
    /// Minor version number
    pub minor: u8,
    /// Patch version number
    pub patch: u8,
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
    pub fn parse(release: &str) -> Self {
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

/// eBPF support level - simplified view of kernel capability
///
/// This is a higher-level view compared to `KernelCapability`:
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
