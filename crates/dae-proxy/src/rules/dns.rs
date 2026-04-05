//! DNS rule module
//!
//! Contains DNS query type rule types and matching logic.

use crate::rule_engine::PacketInfo;

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

    /// Check if this rule matches the given packet info
    pub fn matches_packet(&self, info: &PacketInfo) -> bool {
        if let Some(qtype) = info.dns_query_type {
            self.query_types.iter().any(|qt| {
                let matches = *qt as u16 == qtype;
                if self.is_exclude {
                    !matches
                } else {
                    matches
                }
            })
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_query_type() {
        assert_eq!(DnsQueryType::from_str("A"), Some(DnsQueryType::A));
        assert_eq!(DnsQueryType::from_str("AAAA"), Some(DnsQueryType::AAAA));
        assert_eq!(DnsQueryType::from_str("CNAME"), Some(DnsQueryType::CNAME));
        assert_eq!(DnsQueryType::from_str("INVALID"), None);
    }

    #[test]
    fn test_dns_query_type_all() {
        assert!(DnsQueryType::from_str("A").is_some());
        assert!(DnsQueryType::from_str("AAAA").is_some());
        assert!(DnsQueryType::from_str("MX").is_some());
        assert!(DnsQueryType::from_str("TXT").is_some());
    }
}
