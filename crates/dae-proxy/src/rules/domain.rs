//! Domain rule module
//!
//! Contains domain-based rule types and matching logic.

use super::types::DomainRuleType;
use crate::rule_engine::PacketInfo;

/// A domain-based rule
#[derive(Debug, Clone)]
pub struct DomainRule {
    pub rule_type: DomainRuleType,
}

impl DomainRule {
    /// Create a new domain rule from string
    pub fn new(value: &str) -> Self {
        Self {
            rule_type: DomainRuleType::parse(value),
        }
    }

    /// Check if this rule matches the given packet info
    pub fn matches_packet(&self, info: &PacketInfo, domain_lower: Option<&str>) -> bool {
        if let Some(ref domain) = info.destination_domain {
            self.rule_type.matches(domain, domain_lower)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_rule_exact() {
        let rule = DomainRule::new("example.com");
        assert!(rule.rule_type.matches("example.com", None));
        assert!(rule.rule_type.matches("EXAMPLE.COM", None));
        assert!(!rule.rule_type.matches("sub.example.com", None));
        assert!(!rule.rule_type.matches("notexample.com", None));
    }

    #[test]
    fn test_domain_rule_suffix() {
        let rule = DomainRule::new(".example.com");
        assert!(rule.rule_type.matches("example.com", None));
        assert!(rule.rule_type.matches("sub.example.com", None));
        assert!(rule.rule_type.matches("deep.sub.example.com", None));
        assert!(!rule.rule_type.matches("notexample.com", None));
        assert!(!rule.rule_type.matches("example.com.cn", None));
    }

    #[test]
    fn test_domain_rule_keyword() {
        let rule = DomainRule::new("keyword:google");
        assert!(rule.rule_type.matches("google.com", None));
        assert!(rule.rule_type.matches("igoogle.com", None));
        assert!(rule.rule_type.matches("notgoogle.com", None));
        assert!(!rule.rule_type.matches("example.com", None));
    }

    #[test]
    fn test_domain_rule_root_domain() {
        let rule = DomainRule::new("example.com");
        assert!(rule.rule_type.matches("example.com", None));
        assert!(!rule.rule_type.matches("sub.example.com", None));
    }

    #[test]
    fn test_domain_rule_full_match() {
        // Domain rules match the exact domain
        let rule = DomainRule::new("mail.google.com");
        assert!(rule.rule_type.matches("mail.google.com", None));
        assert!(!rule.rule_type.matches("google.com", None));
    }
}
