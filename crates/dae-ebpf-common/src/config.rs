//! Configuration map entry for eBPF
//!
//! This defines the structure for passing configuration from user-space
//! to the kernel eBPF programs.

/// Global configuration structure shared between user-space and kernel
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ConfigEntry {
    /// Enable/disable the proxy globally
    pub enabled: u8,
    /// Reserved for future use
    pub reserved: [u8; 7],
}

impl Default for ConfigEntry {
    fn default() -> Self {
        Self {
            enabled: 1,
            reserved: [0; 7],
        }
    }
}

/// Index for the global config in CONFIG_MAP
pub const GLOBAL_CONFIG_KEY: u32 = 0;
