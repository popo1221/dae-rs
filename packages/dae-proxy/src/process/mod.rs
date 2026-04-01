//! Process rule engine module
//!
//! This module provides process-based traffic routing based on process names.
//! It integrates with the Linux /proc filesystem to resolve process information
//! and supports glob patterns for flexible rule matching.
//!
//! # Features
//!
//! - Process name resolution from /proc filesystem
//! - Glob pattern matching for flexible rules
//! - Connection-based process lookup
//! - Process rule sets with default actions
//!
//! # Example
//!
//! ```rust
//! use dae_proxy::process::{ProcessRuleSet, ProcessResolver};
//! use dae_proxy::process::ProcessMatchRule;
//! use dae_proxy::rule_engine::RuleAction;
//!
//! // Create a rule set
//! let mut rules = ProcessRuleSet::new();
//! rules.add("chrome*", RuleAction::Proxy);
//! rules.add("ssh", RuleAction::Direct);
//! rules.add("torrent*", RuleAction::Drop);
//!
//! // Match a process
//! let action = rules.match_process("chrome");
//! assert_eq!(action, RuleAction::Proxy);
//! ```

pub mod matcher;
pub mod resolver;
pub mod rule;

pub use matcher::{ProcessInfo, match_process_name};
pub use resolver::{ProcessResolver, TASK_COMM_LEN};
pub use rule::{ProcessMatchRule, ProcessRuleSet, ProcessRuleSetBuilder};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all exports are accessible
        let _ = ProcessInfo::new(1, "test".to_string());
        let _ = ProcessRuleSet::new();
        let _ = ProcessResolver::new();
        let _ = ProcessMatchRule::new("test", RuleAction::Pass);
    }
}
