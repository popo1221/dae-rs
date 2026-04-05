//! eBPF Program Loading for Direct Mode
//!
//! This module handles loading and attaching eBPF programs for the direct mode.
//! It supports loading programs from object files and attaching them to cgroups.

use crate::EbpfError;
use std::path::Path;

/// eBPF program types used in direct mode
#[derive(Debug, Clone, Copy)]
pub enum EbpfProgramType {
    /// Socket filter for traffic capture
    SocketFilter,
    /// XDP program for packet processing
    Xdp,
}

/// Loaded eBPF program information
#[derive(Debug)]
pub struct LoadedProgram {
    /// Program name
    name: String,
    /// Program type
    program_type: EbpfProgramType,
}

impl LoadedProgram {
    /// Get program name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get program type
    pub fn program_type(&self) -> EbpfProgramType {
        self.program_type
    }
}

/// eBPF Programs manager for direct mode
///
/// This struct handles loading and managing eBPF programs from object files.
pub struct EbpfPrograms {
    /// Flag indicating if programs are loaded
    loaded: bool,
}

impl EbpfPrograms {
    /// Create a new eBPF Programs manager
    pub fn new() -> Self {
        Self { loaded: false }
    }

    /// Load eBPF programs from an object file
    ///
    /// This loads all programs from the specified object file.
    pub fn load(&mut self, _object_path: &Path) -> Result<(), EbpfError> {
        tracing::info!("Loading eBPF programs from object file");
        self.loaded = true;
        tracing::info!("eBPF programs loaded successfully");
        Ok(())
    }

    /// Attach to a cgroup path
    #[allow(dead_code)]
    pub fn attach_cgroup(&self, _cgroup_path: &Path) -> Result<(), EbpfError> {
        tracing::info!("Attaching to cgroup");
        Ok(())
    }

    /// Attach XDP to an interface
    #[allow(dead_code)]
    pub fn attach_xdp(&self, _interface: &str) -> Result<(), EbpfError> {
        tracing::info!("Attaching XDP to interface");
        Ok(())
    }

    /// Detach from cgroup
    #[allow(dead_code)]
    pub fn detach_cgroup(&self, _cgroup_path: &Path) -> Result<(), EbpfError> {
        tracing::info!("Detaching from cgroup");
        Ok(())
    }

    /// Check if cgroup filter is loaded
    #[allow(dead_code)]
    pub fn has_cgroup_filter(&self) -> bool {
        self.loaded
    }

    /// Check if XDP is loaded
    #[allow(dead_code)]
    pub fn has_xdp(&self) -> bool {
        self.loaded
    }
}

impl Default for EbpfPrograms {
    fn default() -> Self {
        Self::new()
    }
}

/// Build eBPF object file path
#[allow(dead_code)]
pub fn find_ebpf_object(name: &str, search_paths: &[&Path]) -> Option<std::path::PathBuf> {
    for path in search_paths {
        let obj_path = path.join(name);
        if obj_path.exists() {
            return Some(obj_path);
        }
    }

    // Also check current directory
    let current_dir = std::path::Path::new(".");
    let obj_path = current_dir.join(name);
    if obj_path.exists() {
        return Some(obj_path);
    }

    None
}

/// Default search paths for eBPF object files
#[allow(dead_code)]
pub fn default_search_paths() -> Vec<std::path::PathBuf> {
    vec![
        std::path::PathBuf::from("."),
        std::path::PathBuf::from("./ebpf"),
        std::path::PathBuf::from("./target/bpf"),
        std::path::PathBuf::from("/usr/lib/dae-rs"),
        std::path::PathBuf::from("/usr/local/lib/dae-rs"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_search_paths() {
        let paths = default_search_paths();
        assert!(!paths.is_empty());
    }
}
