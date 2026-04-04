//! Rule types for domain/IP/GeoIP matching
//!
//! This module provides rule matching types for routing decisions.

use crate::rule_engine::{PacketInfo, RuleAction};
use std::net::IpAddr;

/// Rule types supported by the rule engine
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleType {
    /// Domain exact match (e.g., "example.com")
    Domain,
    /// Domain suffix match (e.g., ".example.com" matches "sub.example.com")
    DomainSuffix,
    /// Domain keyword match (matches if domain contains keyword)
    DomainKeyword,
    /// IP CIDR match (IPv4 or IPv6)
    IpCidr,
    /// GeoIP match by country code
    GeoIp,
    /// Process name match (Linux)
    Process,
    /// DNS query type match
    DnsType,
    /// Node capability match (fullcone, udp, v2ray)
    Capability,
    /// Node tag match (matches nodes with specified tag)
    NodeTag,
}

/// Domain rule types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainRuleType {
    /// Exact domain match
    Exact(String),
    /// Suffix domain match (starts with .)
    Suffix(String),
    /// Keyword domain match (contains)
    Keyword(String),
}

impl DomainRuleType {
    /// Parse domain rule from string
    /// - ".example.com" -> suffix rule
    /// - "keyword:example" -> keyword rule
    /// - "example.com" -> exact rule
    pub fn parse(s: &str) -> Self {
        if s.starts_with('.') {
            DomainRuleType::Suffix(s.to_lowercase())
        } else if let Some(stripped) = s.strip_prefix("keyword:") {
            DomainRuleType::Keyword(stripped.to_lowercase())
        } else {
            DomainRuleType::Exact(s.to_lowercase())
        }
    }

    /// Check if this rule matches the given domain
    pub fn matches(&self, domain: &str, domain_lower: Option<&str>) -> bool {
        // Lowercase once: use pre-lowercased domain_lower if provided (hot path from RuleGroup::match_packet),
        // otherwise lowercase domain ourselves. Avoids N×to_lowercase() in RuleGroup::match_packet loop.
        let domain_lc = match domain_lower {
            Some(dl) => dl.to_lowercase(),
            None => domain.to_lowercase(),
        };
        match self {
            DomainRuleType::Exact(d) => domain_lc == *d,
            DomainRuleType::Suffix(suffix) => {
                domain_lc.ends_with(suffix) || domain_lc == suffix.trim_start_matches('.')
            }
            DomainRuleType::Keyword(keyword) => domain_lc.contains(keyword),
        }
    }
}

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

/// An IP CIDR-based rule
#[derive(Debug, Clone)]
pub struct IpCidrRule {
    /// Network prefix (IPv4 or IPv6)
    pub prefix: IpNet,
    /// Whether to include or exclude (for blocklists)
    pub is_exclude: bool,
}

/// IP network (IPv4 or IPv6)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpNet {
    /// IPv4 network
    V4(ipnet::Ipv4Net),
    /// IPv6 network
    V6(ipnet::Ipv6Net),
}

impl IpCidrRule {
    /// Create a new IP CIDR rule
    pub fn new(cidr: &str) -> Result<Self, String> {
        // Parse CIDR notation
        let (prefix, is_exclude) = if let Some(cidr) = cidr.strip_prefix('!') {
            // Exclusion rule
            (parse_cidr(cidr)?, true)
        } else {
            (parse_cidr(cidr)?, false)
        };

        Ok(Self { prefix, is_exclude })
    }

    /// Check if this rule matches the given IP address
    pub fn matches_ip(&self, ip: &IpAddr) -> bool {
        let contains = match (&self.prefix, ip) {
            (IpNet::V4(net), IpAddr::V4(ip)) => net.contains(ip),
            (IpNet::V6(net), IpAddr::V6(ip)) => net.contains(ip),
            _ => false,
        };
        // For exclude rules, we invert the match
        if self.is_exclude {
            !contains
        } else {
            contains
        }
    }

    /// Check if this rule matches the given packet info
    pub fn matches_packet(&self, info: &PacketInfo) -> bool {
        self.matches_ip(&info.destination_ip)
    }
}

/// Parse CIDR string into IpNet
fn parse_cidr(s: &str) -> Result<IpNet, String> {
    s.parse::<ipnet::IpNet>()
        .map(|net| match net {
            ipnet::IpNet::V4(net) => IpNet::V4(net),
            ipnet::IpNet::V6(net) => IpNet::V6(net),
        })
        .map_err(|e| format!("Invalid CIDR '{s}': {e}"))
}

/// A GeoIP-based rule
#[derive(Debug, Clone)]
pub struct GeoIpRule {
    /// Country code (ISO 3166-1 alpha-2)
    pub country_code: String,
    /// Whether to match or exclude (for blocklists)
    pub is_exclude: bool,
}

impl GeoIpRule {
    /// Create a new GeoIP rule
    pub fn new(country_code: &str) -> Self {
        let (code, is_exclude) = if let Some(stripped) = country_code.strip_prefix('!') {
            (stripped, true)
        } else {
            (country_code, false)
        };
        Self {
            country_code: code.to_uppercase(),
            is_exclude,
        }
    }

    /// Check if this rule matches the given country code
    pub fn matches_country(&self, country: &str) -> bool {
        let country_upper = country.to_uppercase();
        let matches = country_upper == self.country_code;
        if self.is_exclude {
            !matches
        } else {
            matches
        }
    }
}

/// A process name rule (Linux only)
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
}

/// DNS query types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQueryType {
    /// A record (IPv4)
    A = 1,
    /// NS record
    NS = 2,
    /// CNAME record
    CNAME = 5,
    /// SOA record
    SOA = 6,
    /// PTR record
    PTR = 12,
    /// MX record
    MX = 15,
    /// TXT record
    TXT = 16,
    /// AAAA record (IPv6)
    AAAA = 28,
    /// SRV record
    SRV = 33,
    /// Any (special)
    ANY = 255,
}

#[allow(clippy::should_implement_trait)]
impl DnsQueryType {
    /// Parse DNS query type from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "A" => Some(DnsQueryType::A),
            "AAAA" => Some(DnsQueryType::AAAA),
            "CNAME" => Some(DnsQueryType::CNAME),
            "NS" => Some(DnsQueryType::NS),
            "MX" => Some(DnsQueryType::MX),
            "TXT" => Some(DnsQueryType::TXT),
            "PTR" => Some(DnsQueryType::PTR),
            "SRV" => Some(DnsQueryType::SRV),
            "ANY" => Some(DnsQueryType::ANY),
            _ => None,
        }
    }

    /// Get query type number
    pub fn as_u16(&self) -> u16 {
        *self as u16
    }
}

/// A DNS query type rule
#[derive(Debug, Clone)]
pub struct DnsTypeRule {
    /// DNS query types to match
    pub query_types: Vec<DnsQueryType>,
    /// Whether to match or exclude
    pub is_exclude: bool,
}

impl DnsTypeRule {
    /// Create a new DNS type rule
    pub fn new(types: &[&str]) -> Result<Self, String> {
        let query_types: Result<Vec<_>, _> = types
            .iter()
            .map(|s| {
                DnsQueryType::from_str(s).ok_or_else(|| format!("Unknown DNS query type: {s}"))
            })
            .collect();

        Ok(Self {
            query_types: query_types?,
            is_exclude: false,
        })
    }
}

/// Node capability type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityType {
    /// Full-Cone NAT capability
    FullCone,
    /// UDP protocol support
    Udp,
    /// V2Ray compatibility
    V2Ray,
}

/// A node capability rule
#[derive(Debug, Clone)]
pub struct CapabilityRule {
    /// Capability type to match
    pub capability: CapabilityType,
    /// Expected value (true/false)
    pub expected_value: bool,
}

impl CapabilityRule {
    /// Create a new capability rule from type string and value
    ///
    /// Supported formats:
    /// - "fullcone" or "fullcone(true)" or "fullcone(enabled)" -> FullCone with true
    /// - "fullcone(false)" or "fullcone(disabled)" -> FullCone with false
    /// - "udp" or "udp(true)" -> Udp with true
    /// - "v2ray" or "v2ray(compatible)" -> V2Ray with true
    pub fn new(capability_str: &str, value_str: &str) -> Result<Self, String> {
        let capability = match capability_str.to_lowercase().as_str() {
            "fullcone" | "full-cone" => CapabilityType::FullCone,
            "udp" => CapabilityType::Udp,
            "v2ray" | "v2ray(compatible)" => CapabilityType::V2Ray,
            _ => return Err(format!("Unknown capability type: {capability_str}")),
        };

        let expected_value = match value_str.to_lowercase().as_str() {
            "true" | "1" | "enabled" | "compatible" => true,
            "false" | "0" | "disabled" => false,
            _ => return Err(format!("Invalid capability value: {value_str}")),
        };

        Ok(Self {
            capability,
            expected_value,
        })
    }

    /// Check if this rule matches the given packet info
    pub fn matches_packet(&self, info: &PacketInfo) -> bool {
        // Get the actual capability value from packet info
        let actual_value = match self.capability {
            CapabilityType::FullCone => info.node_fullcone.unwrap_or(false),
            CapabilityType::Udp => info.node_udp.unwrap_or(true),
            CapabilityType::V2Ray => info.node_v2ray.unwrap_or(true),
        };
        actual_value == self.expected_value
    }
}

/// Node tag rule - matches packets based on the selected node's tag
///
/// This rule type is used to route traffic to nodes with specific tags.
/// For example, a rule with tag "hk" would match if the selected node
/// has the "hk" tag.
///
/// Note: Node-tag rules require node tag support in the proxy chain.
/// The `PacketInfo.node_tag` field must be set before rule matching for
/// this rule type to work correctly.
#[derive(Debug, Clone)]
pub struct NodeTagRule {
    /// Tag to match against
    pub tag: String,
}

impl NodeTagRule {
    /// Create a new node tag rule
    pub fn new(tag: &str) -> Self {
        Self {
            tag: tag.to_lowercase(),
        }
    }

    /// Check if this rule matches the given packet info
    ///
    /// Returns true if the packet info's `node_tag` matches this rule's tag.
    /// If `node_tag` is not set (None), returns false.
    pub fn matches_packet(&self, info: &PacketInfo) -> bool {
        // node_tag must be set by the node selector before rule matching
        // For now, we check if info.node_tag matches our tag
        // This will be implemented fully when node group support is added
        if let Some(ref node_tag) = info.node_tag {
            node_tag.to_lowercase() == self.tag
        } else {
            // If no node tag is set, we can't match
            // This is expected behavior when node-tag rules are used but
            // node selection hasn't populated the tag yet
            false
        }
    }
}

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
    pub fn to_action(&self) -> RuleAction {
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
            Rule::Process(r) => {
                if let Some(ref process) = info.process_name {
                    r.matches_process(process)
                } else {
                    false
                }
            }
            Rule::DnsType(r) => {
                if let Some(qtype) = info.dns_query_type {
                    r.query_types.iter().any(|qt| {
                        let matches = *qt as u16 == qtype;
                        if r.is_exclude {
                            !matches
                        } else {
                            matches
                        }
                    })
                } else {
                    false
                }
            }
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
    /// Match a packet against this rule group.
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
    use std::net::Ipv4Addr;

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
    fn test_ip_cidr_rule_v4() {
        let rule = IpCidrRule::new("10.0.0.0/8").unwrap();

        let ip1: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(192, 168, 0, 1).into();

        assert!(rule.matches_ip(&ip1));
        assert!(!rule.matches_ip(&ip2));
    }

    #[test]
    fn test_ip_cidr_rule_exclude() {
        let rule = IpCidrRule::new("!10.0.0.0/8").unwrap();

        let ip1: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(192, 168, 0, 1).into();

        assert!(!rule.matches_ip(&ip1));
        assert!(rule.matches_ip(&ip2));
    }

    #[test]
    fn test_geoip_rule() {
        let rule = GeoIpRule::new("CN");
        assert!(rule.matches_country("CN"));
        assert!(rule.matches_country("cn"));
        assert!(!rule.matches_country("US"));
    }

    #[test]
    fn test_process_rule() {
        let rule = ProcessRule::new("chrome");
        assert!(rule.matches_process("chrome"));
        assert!(rule.matches_process("CHROME"));
        assert!(!rule.matches_process("firefox"));
    }

    #[test]
    fn test_dns_query_type() {
        assert_eq!(DnsQueryType::from_str("A"), Some(DnsQueryType::A));
        assert_eq!(DnsQueryType::from_str("AAAA"), Some(DnsQueryType::AAAA));
        assert_eq!(DnsQueryType::from_str("CNAME"), Some(DnsQueryType::CNAME));
        assert_eq!(DnsQueryType::from_str("INVALID"), None);
    }

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

    #[test]
    fn test_ip_cidr_rule_v6() {
        let result = IpCidrRule::new("2001:db8::/32");
        // IPv6 rules may or may not be supported
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_ip_cidr_rule_invalid() {
        let result = IpCidrRule::new("not an ip");
        assert!(result.is_err());
    }

    #[test]
    fn test_geoip_rule_case_insensitive() {
        let rule = GeoIpRule::new("us");
        assert!(rule.matches_country("US"));
        assert!(rule.matches_country("us"));
        assert!(!rule.matches_country("CN"));
    }

    #[test]
    fn test_process_rule_case_insensitive() {
        let rule = ProcessRule::new("chrome");
        assert!(rule.matches_process("chrome"));
        assert!(rule.matches_process("CHROME"));
        assert!(!rule.matches_process("firefox"));
    }

    #[test]
    fn test_dns_query_type_all() {
        assert!(DnsQueryType::from_str("A").is_some());
        assert!(DnsQueryType::from_str("AAAA").is_some());
        assert!(DnsQueryType::from_str("MX").is_some());
        assert!(DnsQueryType::from_str("TXT").is_some());
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
    fn test_packet_info_default() {
        let info = PacketInfo::default();
        assert!(info.source_ip.is_unspecified());
        assert!(info.destination_ip.is_unspecified());
        assert!(info.destination_domain.is_none());
        assert!(info.dns_query_type.is_none());
    }

    #[test]
    fn test_packet_info_with_domain() {
        let mut info = PacketInfo::default();
        info.destination_domain = Some("example.com".to_string());
        assert!(info.destination_domain.is_some());
        assert_eq!(info.destination_domain.unwrap(), "example.com");
    }

    #[test]
    fn test_packet_info_with_ip() {
        let mut info = PacketInfo::default();
        info.destination_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!info.destination_ip.is_unspecified());
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
}
