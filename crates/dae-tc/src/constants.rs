//! Protocol constants for packet parsing
//!
//! Consolidates EtherType, IP protocol, TCP flags, and ICMP type constants.

/// 以太网协议类型（EtherType 值）
///
/// EtherType 是以太网帧中用于标识上层协议的两个字节字段。
/// 常见值：
/// - 0x0800 = IPv4
/// - 0x86DD = IPv6
/// - 0x8100 = IEEE 802.1Q VLAN 标签
pub mod ethertype {
    /// IPv4
    pub const IPV4: u16 = 0x0800;
    /// IPv6
    pub const IPV6: u16 = 0x86DD;
    /// IEEE 802.1Q VLAN tagging
    pub const VLAN: u16 = 0x8100;
}

/// IP 协议号常量
///
/// 标识 IP 头中 `protocol` 字段的协议类型.
/// - ICMP (1): 用于 ping、traceroute 等诊断
/// - TCP (6): 可靠传输协议
/// - UDP (17): 无连接传输协议,常用于 DNS、QUIC
pub mod ip_proto {
    /// Internet Control Message Protocol
    pub const ICMP: u8 = 1;
    /// Transmission Control Protocol
    pub const TCP: u8 = 6;
    /// User Datagram Protocol
    pub const UDP: u8 = 17;
    /// ICMP for IPv6
    pub const ICMPV6: u8 = 58;
}

/// TCP 标志位常量
///
/// TCP 控制标志用于管理连接状态和数据传输.
pub mod tcp_flags {
    /// FIN: 结束数据传输,双方均可发送 FIN
    pub const FIN: u8 = 0x01;
    /// SYN: 同步序列号,建立连接时使用
    pub const SYN: u8 = 0x02;
    /// RST: 重置连接
    pub const RST: u8 = 0x04;
    /// PSH: 推送,通知接收方立即将数据交付给应用
    pub const PSH: u8 = 0x08;
    /// ACK: 确认标志,确认已收到的数据
    pub const ACK: u8 = 0x10;
    /// URG: 紧急指针有效
    pub const URG: u8 = 0x20;
    /// ECE: ECN 回显(拥塞通知)
    pub const ECE: u8 = 0x40;
    /// CWR: 拥塞窗口减少(与 ECE 配合)
    pub const CWR: u8 = 0x80;
}

/// ICMP types
pub mod icmp_type {
    pub const ECHO_REPLY: u8 = 0;
    pub const ECHO_REQUEST: u8 = 8;
    pub const DEST_UNREACHABLE: u8 = 3;
    pub const TIME_EXCEEDED: u8 = 11;
}
