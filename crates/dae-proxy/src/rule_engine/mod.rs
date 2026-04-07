//! 规则引擎模块
//!
//! 本模块提供运行在用户空间的规则匹配引擎，基于域名/IP/GeoIP 规则做出最终路由决策。
//!
//! # 模块结构
//!
//! - `engine`: RuleEngine 实现
//! - PacketInfo、RuleAction、RuleEngineConfig、RuleEngineStats 类型

mod engine;

pub use engine::RuleEngine;

use std::net::IpAddr;
use std::sync::Arc;

/// 数据包信息 - 用于规则匹配
///
/// 包含数据包的完整信息，用于规则引擎判断如何路由该数据包。
#[derive(Debug, Clone)]
pub struct PacketInfo {
    /// Source IP address
    pub source_ip: IpAddr,
    /// Destination IP address
    pub destination_ip: IpAddr,
    /// Source port (for TCP/UDP)
    pub src_port: u16,
    /// Destination port (for TCP/UDP)
    pub dst_port: u16,
    /// IP protocol (6=TCP, 17=UDP)
    pub protocol: u8,
    /// Destination domain (if known from DNS or SNI)
    pub destination_domain: Option<String>,
    /// GeoIP country code (ISO 3166-1 alpha-2)
    pub geoip_country: Option<String>,
    /// Process name (Linux only)
    pub process_name: Option<String>,
    /// DNS query type
    pub dns_query_type: Option<u16>,
    /// Connection direction (true = outbound, false = inbound)
    pub is_outbound: bool,
    /// Packet size in bytes
    pub packet_size: usize,
    /// Connection key hash (for session matching)
    pub connection_hash: Option<u64>,
    /// Node capability: fullcone NAT support
    pub node_fullcone: Option<bool>,
    /// Node capability: UDP support
    pub node_udp: Option<bool>,
    /// Node capability: V2Ray compatibility
    pub node_v2ray: Option<bool>,
    /// Selected node's tag (for node-tag rule matching)
    /// This is set by the node selector when a node is chosen for routing
    pub node_tag: Option<String>,
}

impl Default for PacketInfo {
    fn default() -> Self {
        Self {
            source_ip: "0.0.0.0".parse().unwrap(),
            destination_ip: "0.0.0.0".parse().unwrap(),
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            destination_domain: None,
            geoip_country: None,
            process_name: None,
            dns_query_type: None,
            is_outbound: true,
            packet_size: 0,
            connection_hash: None,
            node_fullcone: None,
            node_udp: None,
            node_v2ray: None,
            node_tag: None,
        }
    }
}

impl PacketInfo {
    /// Create a new packet info
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, proto: u8) -> Self {
        Self {
            source_ip: src_ip,
            destination_ip: dst_ip,
            src_port,
            dst_port,
            protocol: proto,
            ..Default::default()
        }
    }

    /// Create from 4-tuple
    pub fn from_tuple(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8) -> Self {
        use std::net::Ipv4Addr;

        let source_ip: IpAddr = Ipv4Addr::from(src_ip).into();
        let destination_ip: IpAddr = Ipv4Addr::from(dst_ip).into();

        Self::new(source_ip, destination_ip, src_port, dst_port, proto)
    }

    /// Set destination domain
    ///
    /// Note: caller should normalize the domain before passing (lowercase once, not per-call).
    pub fn with_domain(mut self, domain: &str) -> Self {
        // Normalize to lowercase once at entry point — avoid repeated conversion in hot paths
        self.destination_domain = Some(domain.to_lowercase());
        self
    }

    /// Set GeoIP country
    pub fn with_geoip(mut self, country: &str) -> Self {
        self.geoip_country = Some(country.to_uppercase());
        self
    }

    /// Set process name
    pub fn with_process(mut self, process: &str) -> Self {
        self.process_name = Some(process.to_lowercase());
        self
    }

    /// Set DNS query type
    pub fn with_dns_type(mut self, qtype: u16) -> Self {
        self.dns_query_type = Some(qtype);
        self
    }

    /// Set node fullcone capability
    pub fn with_node_fullcone(mut self, fullcone: bool) -> Self {
        self.node_fullcone = Some(fullcone);
        self
    }

    /// Set node UDP capability
    pub fn with_node_udp(mut self, udp: bool) -> Self {
        self.node_udp = Some(udp);
        self
    }

    /// Set node V2Ray compatibility
    pub fn with_node_v2ray(mut self, v2ray: bool) -> Self {
        self.node_v2ray = Some(v2ray);
        self
    }

    /// Set all node capabilities at once
    pub fn with_node_capabilities(
        mut self,
        fullcone: Option<bool>,
        udp: Option<bool>,
        v2ray: Option<bool>,
    ) -> Self {
        self.node_fullcone = fullcone;
        self.node_udp = udp;
        self.node_v2ray = v2ray;
        self
    }
}

/// 路由决策的规则动作
///
/// 定义规则匹配后对数据包采取的动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// 放行数据包（直连）
    Pass,
    /// 代理数据包
    Proxy,
    /// 丢弃数据包
    Drop,
    /// 无匹配规则，使用默认动作
    Default,
    /// 直连（显式直连，不经过路由规则）
    Direct,
    /// 强制直连（绕过代理，最高优先级直连）
    MustDirect,
}

impl RuleAction {
    /// Convert to eBPF routing action
    pub fn to_ebpf_action(&self) -> u8 {
        match self {
            RuleAction::Pass | RuleAction::Direct | RuleAction::MustDirect => 0, // dae_ebpf_common::routing::action::PASS
            RuleAction::Drop => 2, // dae_ebpf_common::routing::action::DROP
            RuleAction::Proxy | RuleAction::Default => 0, // Default to pass for now
        }
    }

    /// Convert to u8 for tracking
    ///
    /// Maps to tracking::types::RuleAction values:
    /// - Pass = 0
    /// - Proxy = 1
    /// - Drop = 2
    /// - Default = 3
    /// - Direct = 4
    /// - MustDirect = 5
    pub fn to_u8(&self) -> u8 {
        match self {
            RuleAction::Pass => 0,
            RuleAction::Proxy => 1,
            RuleAction::Drop => 2,
            RuleAction::Default => 3,
            RuleAction::Direct => 4,
            RuleAction::MustDirect => 5,
        }
    }
}

/// Rule match information for tracking
///
/// Contains details about a rule match event for statistics tracking.
#[derive(Debug, Clone)]
pub struct RuleMatchInfo {
    /// The matched rule's action
    pub action: RuleAction,
    /// Unique rule identifier
    pub rule_id: u32,
    /// Rule type (0=Domain, 1=DomainSuffix, 2=DomainKeyword, 3=IpCidr, 4=GeoIp, 5=Process)
    pub rule_type: u8,
    /// Whether a rule matched (false means default action was used)
    pub matched: bool,
}

/// 规则引擎配置
///
/// 配置规则引擎的各项参数。
#[derive(Debug, Clone)]
pub struct RuleEngineConfig {
    /// Enable GeoIP lookup
    pub geoip_enabled: bool,
    /// GeoIP database path
    pub geoip_db_path: Option<String>,
    /// Enable process matching (Linux only)
    pub process_matching_enabled: bool,
    /// Default action when no rule matches
    pub default_action: RuleAction,
    /// Enable rule hot-reload
    pub hot_reload_enabled: bool,
    /// Rule reload interval in seconds
    pub reload_interval_secs: u64,
}

impl Default for RuleEngineConfig {
    fn default() -> Self {
        Self {
            geoip_enabled: true,
            geoip_db_path: None,
            process_matching_enabled: false,
            default_action: RuleAction::Proxy,
            hot_reload_enabled: false,
            reload_interval_secs: 60,
        }
    }
}

/// 规则引擎统计信息
///
/// 记录规则引擎的运行时统计。
#[derive(Debug, Clone)]
pub struct RuleEngineStats {
    /// Whether rules have been loaded
    pub loaded: bool,
    /// Number of rule groups
    pub rule_group_count: usize,
    /// Total number of rules
    pub total_rule_count: usize,
}

/// Shared rule engine type
pub type SharedRuleEngine = Arc<RuleEngine>;

/// Create a new shared rule engine
pub fn new_rule_engine(config: RuleEngineConfig) -> SharedRuleEngine {
    Arc::new(RuleEngine::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_packet_info_creation() {
        // Note: IP addresses in network byte order (big-endian)
        let info = PacketInfo::from_tuple(
            u32::from_be_bytes([127, 0, 0, 1]), // 127.0.0.1
            u32::from_be_bytes([8, 8, 8, 8]),   // 8.8.8.8
            12345,
            80,
            6,
        );

        assert_eq!(info.source_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(info.destination_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(info.src_port, 12345);
        assert_eq!(info.dst_port, 80);
        assert_eq!(info.protocol, 6);
    }

    #[test]
    fn test_rule_action_to_ebpf() {
        assert_eq!(RuleAction::Pass.to_ebpf_action(), 0);
        assert_eq!(RuleAction::Direct.to_ebpf_action(), 0);
        assert_eq!(RuleAction::MustDirect.to_ebpf_action(), 0);
        assert_eq!(RuleAction::Drop.to_ebpf_action(), 2);
        assert_eq!(RuleAction::Proxy.to_ebpf_action(), 0);
        assert_eq!(RuleAction::Default.to_ebpf_action(), 0);
    }
}
