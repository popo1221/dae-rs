//! 进程规则模块
//!
//! 包含进程名规则类型及匹配逻辑。

use crate::rule_engine::PacketInfo;

/// 进程名规则（仅 Linux）
///
/// 根据进程名匹配数据包的规则。
#[derive(Debug, Clone)]
pub struct ProcessRule {
    /// Process name to match
    pub process_name: String,
    /// Whether to match or exclude
    pub is_exclude: bool,
}

impl ProcessRule {
    /// Create a new process rule
    pub fn new(process_name: &str) -> Self {
        let (name, is_exclude) = if let Some(stripped) = process_name.strip_prefix('!') {
            (stripped, true)
        } else {
            (process_name, false)
        };
        Self {
            process_name: name.to_lowercase(),
            is_exclude,
        }
    }

    /// Check if this rule matches the given process name
    pub fn matches_process(&self, process_name: &str) -> bool {
        let name_lower = process_name.to_lowercase();
        let matches = name_lower == self.process_name;
        if self.is_exclude {
            !matches
        } else {
            matches
        }
    }

    /// Check if this rule matches the given packet info
    pub fn matches_packet(&self, info: &PacketInfo) -> bool {
        if let Some(ref process) = info.process_name {
            self.matches_process(process)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_rule() {
        let rule = ProcessRule::new("chrome");
        assert!(rule.matches_process("chrome"));
        assert!(rule.matches_process("CHROME"));
        assert!(!rule.matches_process("firefox"));
    }

    #[test]
    fn test_process_rule_case_insensitive() {
        let rule = ProcessRule::new("chrome");
        assert!(rule.matches_process("chrome"));
        assert!(rule.matches_process("CHROME"));
        assert!(!rule.matches_process("firefox"));
    }
}
