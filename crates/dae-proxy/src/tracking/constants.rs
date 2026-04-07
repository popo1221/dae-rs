//! Tracking constants and enumerations
//!
//! Shared constants, enums, and event type definitions for tracking.

use std::time::SystemTime;

/// Connection state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectionState {
    /// New connection, not yet established
    New = 0,
    /// Connection is active and transferring data
    Established = 1,
    /// Connection is being closed gracefully
    Closing = 2,
    /// Connection has been closed
    Closed = 3,
}

/// Node status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NodeStatus {
    /// Node is healthy and accepting traffic
    Up = 0,
    /// Node is not responding
    Down = 1,
    /// Node is responding but high latency or error rate
    Degraded = 2,
}

/// Rule action enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuleAction {
    /// Pass the packet (direct)
    Pass = 0,
    /// Proxy the packet
    Proxy = 1,
    /// Drop the packet
    Drop = 2,
    /// No matching rule, use default
    Default = 3,
    /// Direct connection (explicit direct)
    Direct = 4,
    /// Must direct (force bypass proxy)
    MustDirect = 5,
}

impl From<u8> for RuleAction {
    fn from(value: u8) -> Self {
        match value {
            0 => RuleAction::Pass,
            1 => RuleAction::Proxy,
            2 => RuleAction::Drop,
            3 => RuleAction::Default,
            4 => RuleAction::Direct,
            5 => RuleAction::MustDirect,
            _ => RuleAction::Pass, // Default to Pass for unknown values
        }
    }
}

/// Rule type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuleType {
    /// Domain exact match
    Domain = 0,
    /// Domain suffix match
    DomainSuffix = 1,
    /// Domain keyword match
    DomainKeyword = 2,
    /// IP CIDR match
    IpCidr = 3,
    /// GeoIP country match
    GeoIp = 4,
    /// Process name match
    Process = 5,
}

/// Protocol type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    /// TCP protocol
    Tcp = 6,
    /// UDP protocol
    Udp = 17,
    /// ICMP protocol
    Icmp = 1,
    /// SOCKS5 protocol
    Socks5 = 0x50,
    /// HTTP protocol
    Http = 0x51,
    /// VLESS protocol
    Vless = 0x52,
    /// VMess protocol
    Vmess = 0x53,
    /// Trojan protocol
    Trojan = 0x54,
    /// Shadowsocks protocol
    Shadowsocks = 0x55,
}

/// Event type constants for TrackingEvent
pub mod event_type {
    /// Connection event type
    pub const CONNECTION: u8 = 0;
    /// Rule event type
    pub const RULE: u8 = 1;
    /// Node event type
    pub const NODE: u8 = 2;
    /// Stats event type
    pub const STATS: u8 = 3;
}

/// Latency sample for histogram calculation
#[derive(Clone, Debug)]
pub struct LatencySample {
    /// Timestamp
    pub timestamp: u64,
    /// Latency in milliseconds
    pub latency_ms: u32,
    /// Node ID (if applicable)
    pub node_id: Option<u32>,
}

/// Helper function to get current epoch in milliseconds
pub fn current_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
