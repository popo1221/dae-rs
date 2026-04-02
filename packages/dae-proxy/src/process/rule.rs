//! Process-based routing rules
//!
//! This module provides rule types for matching traffic based on process names.
//! Rules support glob patterns for flexible matching.

use super::matcher::{match_process_name, ProcessInfo};
use crate::rule_engine::RuleAction;

/// A single process match rule
///
/// Each rule has a process name pattern (supporting glob) and an action to take
/// when traffic matches.
#[derive(Debug, Clone)]
pub struct ProcessMatchRule {
    /// Process name pattern (supports glob: "chrome*", "*fox", etc.)
    pub process_name: String,
    /// Action to take when this rule matches
    pub action: RuleAction,
    /// Whether this is an exclusion rule (!pattern)
    pub is_exclude: bool,
}

impl ProcessMatchRule {
    /// Create a new process match rule
    ///
    /// Supports exclusion patterns starting with '!':
    /// - "chrome" -> match chrome, action
    /// - "!chrome" -> match anything except chrome, action
    pub fn new(process_name: &str, action: RuleAction) -> Self {
        let (name, is_exclude) = if process_name.starts_with('!') {
            (&process_name[1..], true)
        } else {
            (process_name, false)
        };

        Self {
            process_name: name.to_string(),
            action,
            is_exclude,
        }
    }

    /// Check if this rule matches the given process name
    pub fn matches(&self, process_name: &str) -> bool {
        let matches = match_process_name(&self.process_name, process_name);

        if self.is_exclude {
            !matches
        } else {
            matches
        }
    }

    /// Check if this rule matches a ProcessInfo
    pub fn matches_process_info(&self, info: &ProcessInfo) -> bool {
        self.matches(&info.name)
    }
}

/// A set of process match rules with a default action
///
/// Rules are evaluated in order, and the first matching rule's action is returned.
/// If no rule matches, the default_action is returned.
#[derive(Debug, Clone)]
pub struct ProcessRuleSet {
    /// List of rules in order (first match wins)
    rules: Vec<ProcessMatchRule>,
    /// Default action when no rule matches
    default_action: RuleAction,
}

impl ProcessRuleSet {
    /// Create a new empty ProcessRuleSet with default action Pass
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_action: RuleAction::Pass,
        }
    }

    /// Create with a default action
    pub fn with_default_action(default_action: RuleAction) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
        }
    }

    /// Add a rule to the set
    pub fn add_rule(&mut self, rule: ProcessMatchRule) {
        self.rules.push(rule);
    }

    /// Add a rule from pattern and action
    pub fn add(&mut self, pattern: &str, action: RuleAction) {
        self.rules.push(ProcessMatchRule::new(pattern, action));
    }

    /// Match a process name against this rule set
    ///
    /// Returns the action of the first matching rule, or default_action if none match.
    pub fn match_process(&self, process_name: &str) -> RuleAction {
        for rule in &self.rules {
            if rule.matches(process_name) {
                return rule.action;
            }
        }
        self.default_action
    }

    /// Match a ProcessInfo against this rule set
    pub fn match_process_info(&self, info: &ProcessInfo) -> RuleAction {
        self.match_process(&info.name)
    }

    /// Get the number of rules
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if the rule set is empty
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Get the default action
    pub fn default_action(&self) -> RuleAction {
        self.default_action
    }

    /// Set the default action
    pub fn set_default_action(&mut self, action: RuleAction) {
        self.default_action = action;
    }

    /// Get an iterator over the rules
    pub fn rules(&self) -> &[ProcessMatchRule] {
        &self.rules
    }
}

impl Default for ProcessRuleSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for ProcessRuleSet
#[derive(Debug, Clone)]
pub struct ProcessRuleSetBuilder {
    rules: Vec<ProcessMatchRule>,
    default_action: RuleAction,
}

impl ProcessRuleSetBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_action: RuleAction::Pass,
        }
    }

    /// Add a rule
    pub fn add_rule(mut self, pattern: &str, action: RuleAction) -> Self {
        self.rules.push(ProcessMatchRule::new(pattern, action));
        self
    }

    /// Add a pass rule
    pub fn pass(mut self, pattern: &str) -> Self {
        self.rules
            .push(ProcessMatchRule::new(pattern, RuleAction::Pass));
        self
    }

    /// Add a direct rule
    pub fn direct(mut self, pattern: &str) -> Self {
        self.rules
            .push(ProcessMatchRule::new(pattern, RuleAction::Direct));
        self
    }

    /// Add a proxy rule
    pub fn proxy(mut self, pattern: &str) -> Self {
        self.rules
            .push(ProcessMatchRule::new(pattern, RuleAction::Proxy));
        self
    }

    /// Add a drop rule
    pub fn drop(mut self, pattern: &str) -> Self {
        self.rules
            .push(ProcessMatchRule::new(pattern, RuleAction::Drop));
        self
    }

    /// Set default action
    pub fn default_action(mut self, action: RuleAction) -> Self {
        self.default_action = action;
        self
    }

    /// Build the ProcessRuleSet
    pub fn build(self) -> ProcessRuleSet {
        ProcessRuleSet {
            rules: self.rules,
            default_action: self.default_action,
        }
    }
}

impl Default for ProcessRuleSetBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_engine::RuleAction;

    #[test]
    fn test_process_rule_exact_match() {
        let rule = ProcessMatchRule::new("chrome", RuleAction::Proxy);

        assert!(rule.matches("chrome"));
        assert!(!rule.matches("chromium"));
        assert!(!rule.matches("firefox"));
    }

    #[test]
    fn test_process_rule_prefix_match() {
        let rule = ProcessMatchRule::new("chrome*", RuleAction::Proxy);

        assert!(rule.matches("chrome")); // exact match
        assert!(rule.matches("chromedriver")); // starts with chrome
        assert!(rule.matches("chrome-stable")); // starts with chrome
        assert!(!rule.matches("chromium")); // chromium != chrome* (has 'i' not 'e' after 'chrom')
        assert!(!rule.matches("firefox"));
    }

    #[test]
    fn test_process_rule_exclude() {
        let rule = ProcessMatchRule::new("!chrome", RuleAction::Proxy);

        assert!(!rule.matches("chrome"));
        assert!(rule.matches("firefox"));
        assert!(rule.matches("anything"));
    }

    #[test]
    fn test_process_rule_set_basic() {
        let mut set = ProcessRuleSet::new();
        set.add("chrome", RuleAction::Proxy);
        set.add("firefox", RuleAction::Pass);

        assert_eq!(set.match_process("chrome"), RuleAction::Proxy);
        assert_eq!(set.match_process("firefox"), RuleAction::Pass);
        assert_eq!(set.match_process("unknown"), RuleAction::Pass); // default
    }

    #[test]
    fn test_process_rule_set_builder() {
        let set = ProcessRuleSetBuilder::new()
            .proxy("chrome")
            .direct("ssh")
            .drop("torrent*")
            .default_action(RuleAction::Pass)
            .build();

        assert_eq!(set.match_process("chrome"), RuleAction::Proxy);
        assert_eq!(set.match_process("ssh"), RuleAction::Direct);
        assert_eq!(set.match_process("torrent"), RuleAction::Drop);
        assert_eq!(set.match_process("torrent-x"), RuleAction::Drop);
        assert_eq!(set.match_process("unknown"), RuleAction::Pass);
    }

    #[test]
    fn test_process_rule_set_first_match() {
        let mut set = ProcessRuleSet::new();
        set.add("chrome*", RuleAction::Proxy);
        set.add("chrome", RuleAction::Drop);

        // First rule matches first
        assert_eq!(set.match_process("chrome"), RuleAction::Proxy);
        assert_eq!(set.match_process("chrome-stable"), RuleAction::Proxy);
    }

    #[test]
    fn test_process_rule_set_default() {
        let mut set = ProcessRuleSet::with_default_action(RuleAction::Drop);
        set.add("chrome", RuleAction::Proxy);

        assert_eq!(set.match_process("chrome"), RuleAction::Proxy);
        assert_eq!(set.match_process("unknown"), RuleAction::Drop);
    }

    #[test]
    fn test_process_rule_with_process_info() {
        let rule = ProcessMatchRule::new("chrome", RuleAction::Proxy);
        let info = ProcessInfo::new(1234, "chrome".to_string());

        assert!(rule.matches_process_info(&info));
    }
}
