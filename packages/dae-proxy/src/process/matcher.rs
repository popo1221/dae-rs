//! Process matching utilities
//!
//! This module provides process information structures and pattern matching
//! for routing traffic based on process names.

use std::path::PathBuf;

/// Process information
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Process name (from /proc/[pid]/comm)
    pub name: String,
    /// Process executable path (from /proc/[pid]/exe)
    pub path: Option<PathBuf>,
    /// Command line arguments (from /proc/[pid]/cmdline)
    pub cmdline: Option<Vec<String>>,
}

impl ProcessInfo {
    /// Create a new ProcessInfo
    pub fn new(pid: u32, name: String) -> Self {
        Self {
            pid,
            name,
            path: None,
            cmdline: None,
        }
    }

    /// With path
    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    /// With cmdline
    pub fn with_cmdline(mut self, cmdline: Vec<String>) -> Self {
        self.cmdline = Some(cmdline);
        self
    }
}

/// Match a process name against a glob pattern
///
/// Supports:
/// - Exact match: "chrome"
/// - Prefix match: "chrome*" (starts with chrome)
/// - Suffix match: "*chrome" (ends with chrome)
/// - Wildcard match: "chrome*" or "*chrome*" or "chr*me"
///
/// # Arguments
/// * `pattern` - Glob pattern (e.g., "chrome*", "firefox", "*fox")
/// * `name` - Process name to match against
///
/// # Returns
/// * `true` if the name matches the pattern
pub fn match_process_name(pattern: &str, name: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }

    // Try using glob pattern for complex matching
    if let Ok(glob_pattern) = glob::Pattern::new(pattern) {
        // First try exact glob match on the full name
        if glob_pattern.matches(name) {
            return true;
        }

        // For patterns with only trailing asterisk (e.g., "chrome*"),
        // also try the simple prefix match for better performance
        if pattern.ends_with('*') && !pattern[..pattern.len() - 1].contains('*') {
            let prefix = &pattern[..pattern.len() - 1];
            if name.starts_with(prefix) {
                return true;
            }
        }

        // For patterns with only leading asterisk (e.g., "*chrome"),
        // try suffix match
        if pattern.starts_with('*') && !pattern[1..].contains('*') {
            let suffix = &pattern[1..];
            if name.ends_with(suffix) {
                return true;
            }
        }
    } else {
        // Fallback: if glob pattern fails to parse, try simple exact match
        if pattern == name {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(match_process_name("chrome", "chrome"));
        assert!(match_process_name("firefox", "firefox"));
        assert!(!match_process_name("chrome", "chromed"));
        assert!(!match_process_name("chrome", "firefox"));
    }

    #[test]
    fn test_prefix_match() {
        assert!(match_process_name("chrome*", "chrome"));
        assert!(match_process_name("chrome*", "chromed"));
        assert!(match_process_name("chrome*", "chrome-stable"));
        assert!(!match_process_name("chrome*", "chromedriver"));
        assert!(!match_process_name("chrome*", "firefox"));
    }

    #[test]
    fn test_suffix_match() {
        assert!(match_process_name("*chrome", "chrome"));
        assert!(match_process_name("*chrome", "chromium"));
        assert!(!match_process_name("*chrome", "chromeplus"));
    }

    #[test]
    fn test_wildcard_match() {
        assert!(match_process_name("*chrome*", "chrome"));
        assert!(match_process_name("*chrome*", "chromium-browser"));
        assert!(match_process_name("*chrome*", "google-chrome"));
        assert!(match_process_name("chr*me", "chrome"));
        assert!(match_process_name("chr*me", "chr123ome"));
    }

    #[test]
    fn test_case_sensitivity() {
        // Process names on Linux are case-sensitive, so we match as-is
        assert!(match_process_name("Chrome", "Chrome"));
        assert!(!match_process_name("Chrome", "chrome"));
    }

    #[test]
    fn test_empty_pattern() {
        assert!(!match_process_name("", "chrome"));
        assert!(!match_process_name("", ""));
    }

    #[test]
    fn test_process_info() {
        let info = ProcessInfo::new(1234, "chrome".to_string());
        assert_eq!(info.pid, 1234);
        assert_eq!(info.name, "chrome");
        assert!(info.path.is_none());

        let info = info.with_path(PathBuf::from("/usr/bin/chrome"));
        assert_eq!(info.path, Some(PathBuf::from("/usr/bin/chrome")));
    }
}
