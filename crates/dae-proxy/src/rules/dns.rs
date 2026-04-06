//! DNS 规则模块
//!
//! 包含 DNS 查询类型规则类型及匹配逻辑。

use crate::rule_engine::PacketInfo;

/// DNS 查询类型枚举
///
/// 定义常见的 DNS 查询类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQueryType {
    /// A 记录（IPv4 地址）
    A = 1,
    /// NS 记录（域名服务器）
    NS = 2,
    /// CNAME 记录（规范名称）
    CNAME = 5,
    /// SOA 记录（授权起始）
    SOA = 6,
    /// PTR 记录（指针）
    PTR = 12,
    /// MX 记录（邮件交换）
    MX = 15,
    /// TXT 记录（文本）
    TXT = 16,
    /// AAAA 记录（IPv6 地址）
    AAAA = 28,
    /// SRV 记录（服务定位）
    SRV = 33,
    /// ANY（任意类型，特殊值）
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
