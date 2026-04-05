//! Rule types module
//!
//! Contains basic rule type enums and domain rule types.

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
    ///
    /// The `domain_lower` parameter is pre-lowercased by `RuleGroup::match_packet`
    /// to avoid N×to_lowercase() allocations when there are N domain rules.
    /// When provided, it should be used directly without calling to_lowercase() again.
    pub fn matches(&self, domain: &str, domain_lower: Option<&str>) -> bool {
        // Use pre-lowercased domain_lower if provided, otherwise lowercase ourselves.
        // Note: domain_lower is already lowercase from RuleGroup::match_packet,
        // so we use it directly via &dl[..] to get &str without allocation.
        let domain_lc: &str = match domain_lower {
            Some(dl) => dl, // Already lowercase, use directly (no to_lowercase call)
            None => &domain.to_lowercase(),
        };
        match self {
            DomainRuleType::Exact(d) => domain_lc == d,
            DomainRuleType::Suffix(suffix) => {
                domain_lc.ends_with(suffix) || domain_lc == suffix.trim_start_matches('.')
            }
            DomainRuleType::Keyword(keyword) => domain_lc.contains(keyword),
        }
    }
}
