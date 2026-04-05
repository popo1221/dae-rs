//! Process resolver for Linux
//!
//! This module provides utilities to resolve process information from the Linux
//! /proc filesystem. It can get process names, paths, and find processes by
//! network connections.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

/// Maximum process name length (TASK_COMM_LEN in kernel)
pub const TASK_COMM_LEN: usize = 16;

/// Process resolver for Linux
///
/// Provides methods to get process information from /proc filesystem.
pub struct ProcessResolver;

impl ProcessResolver {
    /// Create a new ProcessResolver
    pub fn new() -> Self {
        Self
    }

    /// Get process name from /proc/[pid]/comm
    ///
    /// Returns the process name (up to TASK_COMM_LEN characters).
    pub fn get_process_name(pid: u32) -> Option<String> {
        let path = format!("/proc/{pid}/comm");
        read_file_first_line(&path)
    }

    /// Get process executable path from /proc/[pid]/exe
    ///
    /// Returns the symlink target of the executable.
    pub fn get_process_path(pid: u32) -> Option<PathBuf> {
        let path = format!("/proc/{pid}/exe");
        std::fs::read_link(&path).ok()
    }

    /// Get process command line from /proc/[pid]/cmdline
    ///
    /// Returns the command line arguments as a vector of strings.
    pub fn get_process_cmdline(pid: u32) -> Option<Vec<String>> {
        let path = format!("/proc/{pid}/cmdline");
        let file = File::open(&path).ok()?;
        let reader = BufReader::new(file);
        let mut args = Vec::new();

        for bytes in reader.split(0u8).flatten() {
            if bytes.is_empty() {
                break;
            }
            // cmdline uses null bytes as separators
            let arg = String::from_utf8_lossy(&bytes)
                .trim_end_matches('\0')
                .to_string();
            args.push(arg);
        }

        if args.is_empty() {
            None
        } else {
            Some(args)
        }
    }

    /// Get full process info for a given PID
    pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
        let name = Self::get_process_name(pid)?;
        let mut info = ProcessInfo::new(pid, name);

        if let Some(path) = Self::get_process_path(pid) {
            info = info.with_path(path);
        }

        if let Some(cmdline) = Self::get_process_cmdline(pid) {
            info = info.with_cmdline(cmdline);
        }

        Some(info)
    }

    /// List all processes with their names
    ///
    /// Returns an iterator of (pid, process_name) tuples.
    /// This is useful for debugging and testing.
    pub fn list_processes() -> impl Iterator<Item = (u32, String)> {
        (1u32..)
            .map(|pid| {
                let name = Self::get_process_name(pid);
                (pid, name)
            })
            .take_while(|(pid, _)| *pid < 65536) // Cap at reasonable PID max
            .filter_map(|(pid, name): (u32, Option<String>)| name.map(|n| (pid, n)))
    }

    /// Check if a PID exists
    pub fn pid_exists(pid: u32) -> bool {
        let path = format!("/proc/{pid}/comm");
        std::path::Path::new(&path).exists()
    }
}

impl Default for ProcessResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Read first line from a file
fn read_file_first_line(path: &str) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    Some(line.trim().to_string())
}

use crate::process::matcher::ProcessInfo;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_resolver_creation() {
        let resolver = ProcessResolver::new();
        drop(resolver);
    }

    #[test]
    fn test_get_current_process_name() {
        // Get current process name
        let pid = std::process::id();
        let name = ProcessResolver::get_process_name(pid);
        assert!(name.is_some());
    }

    #[test]
    fn test_get_current_process_path() {
        let pid = std::process::id();
        let path = ProcessResolver::get_process_path(pid);
        // Path might be None if the executable was deleted
        // or if we don't have permission
        println!("Current process path: {path:?}");
    }

    #[test]
    fn test_pid_exists() {
        // Current process exists
        let pid = std::process::id();
        assert!(ProcessResolver::pid_exists(pid));

        // Non-existent PID
        assert!(!ProcessResolver::pid_exists(0));
        assert!(!ProcessResolver::pid_exists(u32::MAX));
    }

    #[test]
    fn test_get_current_process_info() {
        let pid = std::process::id();
        let info = ProcessResolver::get_process_info(pid);
        assert!(info.is_some());

        if let Some(info) = info {
            assert_eq!(info.pid, pid);
            assert!(!info.name.is_empty());
            println!("Process info: {info:?}");
        }
    }

    #[test]
    fn test_list_processes() {
        // Take a larger sample of processes
        let processes: Vec<_> = ProcessResolver::list_processes().take(100).collect();
        println!("Found {} processes (sample)", processes.len());

        // We should have found some processes (at least PID 1 which is usually init/systemd)
        assert!(!processes.is_empty(), "Should find at least some processes");

        // Current process name should be resolvable
        let current_pid = std::process::id();
        let current_name = ProcessResolver::get_process_name(current_pid);
        assert!(
            current_name.is_some(),
            "Should be able to get current process name"
        );
        println!(
            "Current process (PID {}): {}",
            current_pid,
            current_name.unwrap()
        );
    }
}
