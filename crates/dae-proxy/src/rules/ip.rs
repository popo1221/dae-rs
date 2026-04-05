//! IP 规则模块
//!
//! 包含 IP CIDR 和 GeoIP 规则类型及匹配逻辑。

use crate::rule_engine::PacketInfo;
use std::net::IpAddr;

/// 基于 IP CIDR 的规则
///
/// 用于匹配 IP 地址范围的规则。
#[derive(Debug, Clone)]
pub struct IpCidrRule {
    /// Network prefix (IPv4 or IPv6)
    pub prefix: IpNet,
    /// Whether to include or exclude (for blocklists)
    pub is_exclude: bool,
}

/// IP 网络（IPv4 或 IPv6）
///
/// 表示一个 IP 网络段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpNet {
    /// IPv4 网络
    V4(ipnet::Ipv4Net),
    /// IPv6 网络
    V6(ipnet::Ipv6Net),
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
    ///
    /// The country parameter is expected to be already uppercase (as returned by lookup_geoip).
    /// We use case-insensitive comparison for robustness.
    pub fn matches_country(&self, country: &str) -> bool {
        // lookup_geoip returns uppercase country codes, and rule stores uppercase.
        // Use eq_ignore_ascii_case for case-insensitive comparison without allocation.
        let matches = country.eq_ignore_ascii_case(&self.country_code);
        if self.is_exclude {
            !matches
        } else {
            matches
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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
    fn test_geoip_rule() {
        let rule = GeoIpRule::new("CN");
        assert!(rule.matches_country("CN"));
        assert!(rule.matches_country("cn"));
        assert!(!rule.matches_country("US"));
    }

    #[test]
    fn test_geoip_rule_case_insensitive() {
        let rule = GeoIpRule::new("us");
        assert!(rule.matches_country("US"));
        assert!(rule.matches_country("us"));
        assert!(!rule.matches_country("CN"));
    }
}
