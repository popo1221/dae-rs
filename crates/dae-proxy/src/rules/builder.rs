//! 规则构建器模块
//!
//! 包含 RuleGroup，用于将规则分组。

use super::{
    CapabilityRule, DnsTypeRule, DomainRule, GeoIpRule, IpCidrRule, NodeTagRule, ProcessRule,
};
use crate::rule_engine::PacketInfo;

/// Rule action for configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleMatchAction {
    /// Pass/direct the connection
    Pass,
    /// Proxy the connection
    Proxy,
    /// Drop the connection
    Drop,
}

impl RuleMatchAction {
    /// Convert to RuleAction
    pub fn to_action(&self) -> crate::rule_engine::RuleAction {
        use crate::rule_engine::RuleAction;
        match self {
            RuleMatchAction::Pass => RuleAction::Pass,
            RuleMatchAction::Proxy => RuleAction::Proxy,
            RuleMatchAction::Drop => RuleAction::Drop,
        }
    }
}

/// Rule enum holding different rule types (for matching)
#[derive(Debug, Clone)]
pub enum Rule {
    /// Domain rule
    Domain(DomainRule),
    /// IP CIDR rule
    IpCidr(IpCidrRule),
    /// GeoIP rule
    GeoIp(GeoIpRule),
    /// Process rule
    Process(ProcessRule),
    /// DNS type rule
    DnsType(DnsTypeRule),
    /// Node capability rule
    Capability(CapabilityRule),
    /// Node tag rule (matches against selected node's tag)
    NodeTag(NodeTagRule),
}

impl Rule {
    /// Create a rule from type string and value
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        rule_type_str: &str,
        value: &str,
        action: RuleMatchAction,
        priority: u32,
    ) -> Result<RuleWithAction, String> {
        let rule = match rule_type_str.to_lowercase().as_str() {
            "domain" => Rule::Domain(DomainRule::new(value)),
            "domain-suffix" => {
                let mut val = value.to_string();
                if !val.starts_with('.') {
                    val.insert(0, '.');
                }
                Rule::Domain(DomainRule::new(&val))
            }
            "domain-keyword" => Rule::Domain(DomainRule::new(&format!("keyword:{value}"))),
            "ipcidr" | "ip-cidr" | "cidr" => Rule::IpCidr(IpCidrRule::new(value)?),
            "geoip" | "geo-ip" => Rule::GeoIp(GeoIpRule::new(value)),
            "process" | "process-name" => Rule::Process(ProcessRule::new(value)),
            "dnstype" | "dns-type" | "dns" => {
                let types: Vec<&str> = value.split(',').map(|s| s.trim()).collect();
                Rule::DnsType(DnsTypeRule::new(&types)?)
            }
            // Node capability rules
            "fullcone" | "full-cone" | "fullcone(enabled)" => {
                Rule::Capability(CapabilityRule::new("fullcone", value)?)
            }
            "udp" | "udp(enabled)" => Rule::Capability(CapabilityRule::new("udp", value)?),
            "v2ray" | "v2ray(compatible)" => Rule::Capability(CapabilityRule::new("v2ray", value)?),
            // Node tag rules
            "node-tag" | "nodetag" | "tag" => Rule::NodeTag(NodeTagRule::new(value)),
            _ => return Err(format!("Unknown rule type: {rule_type_str}")),
        };

        Ok(RuleWithAction {
            rule,
            action,
            priority,
        })
    }

    /// Check if this rule matches the given packet info
    pub fn matches(&self, info: &PacketInfo, domain_lower: Option<&str>) -> bool {
        match self {
            Rule::Domain(r) => r.matches_packet(info, domain_lower),
            Rule::IpCidr(r) => r.matches_packet(info),
            Rule::GeoIp(r) => {
                if let Some(ref country) = info.geoip_country {
                    r.matches_country(country)
                } else {
                    false
                }
            }
            Rule::Process(r) => r.matches_packet(info),
            Rule::DnsType(r) => r.matches_packet(info),
            Rule::Capability(r) => r.matches_packet(info),
            Rule::NodeTag(r) => r.matches_packet(info),
        }
    }
}

/// A rule with its action and priority
#[derive(Debug, Clone)]
pub struct RuleWithAction {
    /// The rule
    pub rule: Rule,
    /// Action to take when rule matches
    pub action: RuleMatchAction,
    /// Rule priority (lower = higher priority)
    pub priority: u32,
}

impl RuleWithAction {
    /// Check if this rule matches the given packet info
    pub fn matches(&self, info: &PacketInfo, domain_lower: Option<&str>) -> bool {
        self.rule.matches(info, domain_lower)
    }
}

/// A collection of rules with a default action
#[derive(Debug, Clone)]
pub struct RuleGroup {
    /// Group name
    pub name: String,
    /// Rules in this group
    pub rules: Vec<RuleWithAction>,
    /// Default action if no rule matches
    pub default_action: RuleMatchAction,
    /// Whether to stop matching after first match
    pub first_match: bool,
}

impl RuleGroup {
    /// Create a new rule group
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            rules: Vec::new(),
            default_action: RuleMatchAction::Proxy,
            first_match: true,
        }
    }

    /// Add a rule to this group
    pub fn add_rule(&mut self, rule: RuleWithAction) {
        self.rules.push(rule);
    }

    /// Set the default action
    pub fn set_default_action(&mut self, action: RuleMatchAction) {
        self.default_action = action;
    }

    /// Match a packet against this rule group
    ///
    /// Optimizes domain matching by lowercasing ONCE before the rule loop,
    /// then passing the pre-lowercased domain to each rule's matches().
    /// This avoids N × to_lowercase() allocations when there are N domain rules.
    pub fn match_packet(&self, info: &PacketInfo) -> Option<RuleMatchAction> {
        let domain_lower = info.destination_domain.as_ref().map(|s| s.to_lowercase());
        for rule in &self.rules {
            if rule.matches(info, domain_lower.as_deref()) {
                return Some(rule.action);
            }
        }
        None
    }

    /// Get the default action
    pub fn default_action(&self) -> RuleMatchAction {
        self.default_action
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_rule_from_type_string() {
        let rule = Rule::new("domain-suffix", ".cn", RuleMatchAction::Pass, 100).unwrap();
        assert!(matches!(rule.rule, Rule::Domain(_)));

        let rule = Rule::new("ipcidr", "10.0.0.0/8", RuleMatchAction::Pass, 100).unwrap();
        assert!(matches!(rule.rule, Rule::IpCidr(_)));

        let rule = Rule::new("geoip", "cn", RuleMatchAction::Pass, 100).unwrap();
        assert!(matches!(rule.rule, Rule::GeoIp(_)));

        let rule = Rule::new("process", "chrome", RuleMatchAction::Drop, 100).unwrap();
        assert!(matches!(rule.rule, Rule::Process(_)));

        let rule = Rule::new("dnstype", "A,AAAA", RuleMatchAction::Pass, 100).unwrap();
        assert!(matches!(rule.rule, Rule::DnsType(_)));
    }

    #[test]
    fn test_rule_group() {
        let mut group = RuleGroup::new("test");
        group.add_rule(Rule::new("domain-suffix", ".cn", RuleMatchAction::Pass, 100).unwrap());
        group.add_rule(Rule::new("ipcidr", "10.0.0.0/8", RuleMatchAction::Pass, 90).unwrap());
        group.set_default_action(RuleMatchAction::Proxy);

        let mut info = PacketInfo::default();
        info.destination_domain = Some("example.cn".to_string());
        assert_eq!(group.match_packet(&info), Some(RuleMatchAction::Pass));

        let mut info = PacketInfo::default();
        info.destination_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(group.match_packet(&info), Some(RuleMatchAction::Pass));

        let mut info = PacketInfo::default();
        info.destination_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(group.match_packet(&info), None);
        assert_eq!(group.default_action(), RuleMatchAction::Proxy);
    }

    #[test]
    fn test_rule_group_default_action() {
        let mut group = RuleGroup::new("test");
        assert_eq!(group.default_action(), RuleMatchAction::Proxy); // Default

        group.set_default_action(RuleMatchAction::Drop);
        assert_eq!(group.default_action(), RuleMatchAction::Drop);
    }

    #[test]
    fn test_rule_group_empty() {
        let group = RuleGroup::new("empty");
        let mut info = PacketInfo::default();
        info.destination_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        // Empty group should use default action
        assert_eq!(group.match_packet(&info), None);
    }

    #[test]
    fn test_rule_group_order() {
        let mut group = RuleGroup::new("ordered");
        group.add_rule(Rule::new("domain-suffix", ".org", RuleMatchAction::Pass, 100).unwrap());
        group.add_rule(Rule::new("domain-suffix", ".com", RuleMatchAction::Pass, 90).unwrap());

        let mut info = PacketInfo::default();
        info.destination_domain = Some("example.org".to_string());
        assert_eq!(group.match_packet(&info), Some(RuleMatchAction::Pass));
    }

    #[test]
    fn test_rule_type_variant() {
        let rule = Rule::new("domain-suffix", ".net", RuleMatchAction::Pass, 100).unwrap();
        assert!(matches!(rule.rule, Rule::Domain(_)));

        let rule = Rule::new("domain-keyword", "test", RuleMatchAction::Pass, 100).unwrap();
        assert!(matches!(rule.rule, Rule::Domain(_)));
    }

    #[test]
    fn test_rule_with_wrong_type() {
        // Unknown rule type should fail
        let rule = Rule::new("unknown-type", "value", RuleMatchAction::Pass, 100);
        assert!(rule.is_err());
    }

    #[test]
    fn test_rule_action_debug() {
        let debug_pass = format!("{:?}", RuleMatchAction::Pass);
        let debug_drop = format!("{:?}", RuleMatchAction::Drop);
        let debug_proxy = format!("{:?}", RuleMatchAction::Proxy);
        assert!(!debug_pass.is_empty());
        assert!(!debug_drop.is_empty());
        assert!(!debug_proxy.is_empty());
    }
}
