//! eBPF System Diagnostics
//!
//! Provides system-level eBPF diagnostics including [`EbpfSystemConfig`] detection,
//! [`can_use_ebpf()`] permission checking, and [`detect_and_log_ebpf_support()`].

use crate::ebpf_integration::checks::{EbpfSupportLevel, KernelVersion};
use std::fs;
use std::path::Path;
use tracing::{debug, info};

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
    /// Current RLIMIT_MEMLOCK in bytes (-1 if unable to determine)
    pub memlock_limit: i64,
    /// Number of CPUs available
    pub num_cpus: u32,
    /// Total memory in bytes
    pub total_memory: u64,
    /// Whether we have root/CAP_SYS_ADMIN
    pub has_admin_cap: bool,
    /// Current eBPF program count (if accessible)
    pub bpf_prog_count: Option<u32>,
    /// Current eBPF map count (if accessible)
    pub bpf_map_count: Option<u32>,
}

impl EbpfSystemConfig {
    /// Check if BPF syscall is available
    fn check_syscall() -> bool {
        Path::new("/proc/sys/kernel/bpf_stats_enabled").exists()
            || Path::new("/proc/sys/net/core/bpf_jit_enable").exists()
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

    /// Check if we have admin capabilities
    fn check_admin_cap() -> bool {
        // SAFETY: geteuid is a pure read-only syscall that is always safe.
        let uid = unsafe { libc::geteuid() };
        uid == 0
    }

    /// Get current RLIMIT_MEMLOCK
    fn get_memlock_limit() -> i64 {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        // SAFETY: getrlimit is a safe syscall; we pass a valid pointer to a zeroed rlimit.
        if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim) } == 0 {
            rlim.rlim_cur as i64
        } else {
            -1
        }
    }

    /// Get number of CPUs
    fn get_num_cpus() -> u32 {
        std::thread::available_parallelism()
            .map(|p| p.get() as u32)
            .unwrap_or(1)
    }

    /// Get total system memory
    fn get_total_memory() -> u64 {
        if let Ok(content) = fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(value_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = value_str.parse::<u64>() {
                            return kb * 1024;
                        }
                    }
                }
            }
        }
        0
    }

    /// Get BPF program count (requires reading /sys/kernel/debug/bpf/ or similar)
    fn get_bpf_counts() -> (Option<u32>, Option<u32>) {
        if let Ok(output) = std::process::Command::new("bpftool")
            .arg("prog")
            .arg("show")
            .arg("--json")
            .output()
        {
            if output.status.success() {
                let count = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .filter(|l| !l.is_empty())
                    .count() as u32;
                return (Some(count), None);
            }
        }
        (None, None)
    }

    /// Detect full system configuration with comprehensive diagnostics
    pub fn detect() -> Self {
        let (bpf_prog_count, bpf_map_count) = Self::get_bpf_counts();

        Self {
            jit_enabled: Self::check_jit(),
            unprivileged_allowed: Self::check_unprivileged(),
            syscall_available: Self::check_syscall(),
            kernel_version: KernelVersion::detect().into(),
            memlock_limit: Self::get_memlock_limit(),
            num_cpus: Self::get_num_cpus(),
            total_memory: Self::get_total_memory(),
            has_admin_cap: Self::check_admin_cap(),
            bpf_prog_count,
            bpf_map_count,
        }
    }

    /// Generate a diagnostic report
    pub fn diagnostic_report(&self) -> String {
        let mut report = String::new();
        report.push_str("=== eBPF System Diagnostics ===\n");

        if let Some(ref kv) = self.kernel_version {
            report.push_str(&format!(
                "Kernel: {}.{}.{} (capability: {})\n",
                kv.major,
                kv.minor,
                kv.patch,
                kv.capability()
            ));
        } else {
            report.push_str("Kernel: Unknown\n");
        }

        report.push_str(&format!(
            "CPUs: {}, Total Memory: {:.2} GB\n",
            self.num_cpus,
            self.total_memory as f64 / (1024.0 * 1024.0 * 1024.0)
        ));

        report.push_str("\n--- eBPF Configuration ---\n");
        report.push_str(&format!(
            "BPF syscall: {}\n",
            if self.syscall_available {
                "available"
            } else {
                "unavailable"
            }
        ));
        report.push_str(&format!(
            "BPF JIT: {}\n",
            if self.jit_enabled {
                "enabled (recommended)"
            } else {
                "disabled"
            }
        ));
        report.push_str(&format!(
            "Unprivileged BPF: {}\n",
            if self.unprivileged_allowed {
                "allowed"
            } else if self.has_admin_cap {
                "disabled (root available)"
            } else {
                "disabled (root required)"
            }
        ));

        report.push_str(&format!(
            "RLIMIT_MEMLOCK: {} KB\n",
            self.memlock_limit / 1024
        ));

        if self.memlock_limit > 0 && self.memlock_limit < 64 * 1024 * 1024 {
            report.push_str("  ⚠️ Warning: RLIMIT_MEMLOCK may be too low for many eBPF maps\n");
            report.push_str("  Consider: ulimit -l 262144 (or higher)\n");
        }

        if let Some(count) = self.bpf_prog_count {
            report.push_str(&format!("Current BPF programs: {}\n", count));
        }

        if let Some(count) = self.bpf_map_count {
            report.push_str(&format!("Current BPF maps: {}\n", count));
        }

        report.push_str("\n--- Recommendations ---\n");
        if !self.syscall_available {
            report.push_str("❌ BPF syscall not available - eBPF not supported\n");
        } else if !self.jit_enabled {
            report.push_str("⚠️ BPF JIT disabled - performance may be reduced\n");
            report.push_str("  Enable: echo 1 > /proc/sys/net/core/bpf_jit_enable\n");
        }

        if !self.unprivileged_allowed && !self.has_admin_cap {
            report.push_str("❌ eBPF requires root or CAP_SYS_ADMIN\n");
        } else if self.unprivileged_allowed {
            report.push_str("✓ Unprivileged eBPF allowed (security consideration)\n");
        }

        if self.memlock_limit > 0 && self.memlock_limit < 32 * 1024 * 1024 {
            report.push_str("⚠️ Consider increasing RLIMIT_MEMLOCK for more eBPF maps\n");
        }

        report.push_str("=============================\n");
        report
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

    let report = config.diagnostic_report();

    info!("=== eBPF Support Detection ===");
    info!("Kernel version: {:?}", kernel);
    info!("eBPF support level: {}", level);
    info!("  TC clsact: {}", kernel.has_tc_clsact());
    info!("  XDP: {}", kernel.has_xdp());
    info!("  ringbuf: {}", kernel.has_ringbuf());
    info!("  BPF JIT enabled: {}", config.jit_enabled);
    info!("  Unprivileged BPF: {}", config.unprivileged_allowed);

    if std::cfg!(debug_assertions) {
        debug!("\n{}", report);
    } else if !config.jit_enabled || config.memlock_limit < 32 * 1024 * 1024 {
        info!("\n{}", report);
    }

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
        let kernel = KernelVersion::detect();
        return (
            false,
            Some(format!(
                "Kernel does not support eBPF (requires kernel 4.14+, got {}.{}.{})",
                kernel.major, kernel.minor, kernel.patch
            )),
        );
    }

    let config = EbpfSystemConfig::detect();

    if !config.syscall_available {
        return (
            false,
            Some("BPF syscall not available on this system".to_string()),
        );
    }

    // Check if we have the required permissions
    if !config.unprivileged_allowed && !config.has_admin_cap {
        return (
            false,
            Some(format!(
                "Need root or CAP_SYS_ADMIN to use eBPF (current RLIMIT_MEMLOCK: {} KB)",
                config.memlock_limit / 1024
            )),
        );
    }

    // Check memory limit
    if config.memlock_limit > 0 && config.memlock_limit < 16 * 1024 * 1024 {
        return (
            false,
            Some(format!(
                "RLIMIT_MEMLOCK too low ({} KB). Need at least 16 MB for eBPF maps.\n\n\
                Run: ulimit -l 262144\n\
                Or add to /etc/security/limits.conf:\n\
                * - memlock 262144",
                config.memlock_limit / 1024
            )),
        );
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
