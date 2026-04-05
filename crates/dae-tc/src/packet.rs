//! Packet parsing helpers for TC eBPF program
//!
//! Provides utilities for parsing Ethernet, IP, TCP, UDP, and VLAN headers
//! from the sk_buff context used in tc programs.
//!
//! # Packet Structure
//!
//! ```text
//! +-------------------+
////! |   Ethernet Hdr    |  (14 bytes, + 4 if VLAN)
//! +-------------------+
//! |   VLAN Tag         |  (4 bytes, optional)
//! +-------------------+
////! |   IP Header       |  (20-60 bytes)
//! +-------------------+
//! |   TCP/UDP Header  |  (20-60 bytes)
//! +-------------------+
//! |   Payload         |
//! +-------------------+
//! ```
//!
//! All multi-byte values are in network byte order (big-endian).

#![allow(dead_code)]

use aya_ebpf::programs::TcContext;

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
/// 标识 IP 头中 `protocol` 字段的协议类型。
/// - ICMP (1)：用于 ping、traceroute 等诊断
/// - TCP (6)：可靠传输协议
/// - UDP (17)：无连接传输协议，常用于 DNS、QUIC
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

/// 以太网头（14 字节）
///
/// 位于数据包最前端，14 字节固定长度，包含目标 MAC、源 MAC 和 EtherType。
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++++++++++++++++++++++++++++
/// |         Destination MAC (目标 MAC, 6 字节)                  |
/// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
/// |         Source MAC (源 MAC, 6 字节)                          |
/// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
/// |         EtherType (2 字节)                                  |
/// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
/// ```
///
/// # EtherType 常见值
///
/// - `0x0800` = IPv4
/// - `0x86DD` = IPv6
/// - `0x8100` = IEEE 802.1Q VLAN 标签（此时后面有 4 字节 VLAN 头）
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EthHdr {
    /// 目标 MAC 地址（网络字节序）
    ///
    /// 网卡接收到数据包后，根据目标 MAC 决定是否交付给本机处理。
    dst: [u8; 6],
    /// 源 MAC 地址（网络字节序）
    ///
    /// 用于标识数据包的发送方，在 LAN 内路由和 ARP 解析中使用。
    src: [u8; 6],
    /// 上层协议类型（网络字节序）
    ///
    /// 0x0800=IPv4, 0x86DD=IPv6, 0x8100=VLAN
    ether_type: u16,
}

impl EthHdr {
    /// 从 TC 上下文解析以太网头
    ///
    /// 从 sk_buff 的 `data()` 起始位置解析以太网头。
    ///
    /// # 参数
    ///
    /// * `ctx` - TC 上下文（包含数据包指针和边界）
    ///
    /// # 返回值
    ///
    /// - `Some(ptr)`：数据包足够长（≥14 字节），返回以太网头指针
    /// - `None`：数据包长度不足（<14 字节），不能安全解析
    ///
    /// # Safety
    ///
    /// 返回的指针在 `ctx.data()` 到 `ctx.data_end()` 区间内，
    /// 调用方在解引用前应确保数据包长度足够（通过边界检查）。
    pub fn from_ctx(ctx: &TcContext) -> Option<*const EthHdr> {
        let data = ctx.data();
        let data_end = ctx.data_end();

        let ptr = data as *const EthHdr;
        if ptr as usize + core::mem::size_of::<EthHdr>() > data_end {
            return None;
        }
        Some(ptr)
    }

    /// 获取 EtherType（主机字节序）
    ///
    /// 将网络字节序（大端）的 16 位字段转换为宿主字节序。
    ///
    /// # 返回值
    ///
    /// 主机字节序的 EtherType 值，如 0x0800 表示 IPv4。
    pub fn ether_type(&self) -> u16 {
        u16::from_be(self.ether_type)
    }

    /// 判断是否为 IPv4 数据包
    ///
    /// EtherType == 0x0800 时返回 true。
    ///
    /// # 返回值
    ///
    /// - `true`：IPv4 数据包
    /// - `false`：其他协议（IPv6、VLAN 等）
    pub fn is_ipv4(&self) -> bool {
        self.ether_type() == ethertype::IPV4
    }

    /// 判断是否为 IPv6 数据包
    #[allow(dead_code)]
    pub fn is_ipv6(&self) -> bool {
        self.ether_type() == ethertype::IPV6
    }

    /// 判断是否存在 VLAN 标签
    ///
    /// EtherType == 0x8100 时返回 true，表示以太网头后有 4 字节 VLAN 标签。
    ///
    /// # 返回值
    ///
    /// - `true`：存在 VLAN 标签，需要额外解析 VlanHdr
    /// - `false`：无 VLAN 标签
    pub fn has_vlan(&self) -> bool {
        self.ether_type() == ethertype::VLAN
    }

    /// 获取源 MAC 地址
    ///
    /// # 返回值
    ///
    /// 6 字节源 MAC 地址数组（网络字节序）。
    pub fn src_mac(&self) -> [u8; 6] {
        self.src
    }

    /// 获取目标 MAC 地址
    #[allow(dead_code)]
    pub fn dst_mac(&self) -> [u8; 6] {
        self.dst
    }
}

/// IEEE 802.1Q VLAN 标签头（4 字节）
///
/// 当以太网头的 EtherType 为 0x8100 时，以太网头后会跟随一个 VLAN 标签。
/// VLAN 标签用于将二层网络划分为多个虚拟局域网。
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// ++++++++++++++++++++++++++++
/// | TPID (0x8100) |         TCI (VLAN ID, PCP, DEI)              |
/// ++++++++++++++++++++++++++++
/// ```
///
/// # TCI (Tag Control Information) 结构
///
/// | 位    | 含义            | 说明                              |
/// |------|-----------------|-----------------------------------|
/// | 15-13 | PCP (优先级)    | 3 位，QoS 优先级代码点            |
/// | 12    | DEI (丢弃标识)  | 1 位，是否可丢弃                  |
/// | 11-0  | VLAN ID        | 12 位，0-4095 的 VLAN 标识符      |
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct VlanHdr {
    /// 标签协议标识符（固定为 0x8100）
    ///
    /// 用于验证这确实是一个 VLAN 标签，而非其他协议。
    pub tpid: u16,
    /// 标签控制信息（低 12 位为 VLAN ID）
    ///
    /// 包含 PCP（优先级）、DEI（丢弃指示）和 VLAN ID。
    pub tci: u16,
}

impl VlanHdr {
    /// Parse VLAN header from context (after Ethernet header)
    pub fn from_ctx_after_eth(ctx: &TcContext, eth_offset: usize) -> Option<*const VlanHdr> {
        let data = ctx.data();
        let data_end = ctx.data_end();

        let ptr = unsafe { (data as *const u8).add(eth_offset) as *const VlanHdr };
        if ptr as usize + core::mem::size_of::<VlanHdr>() > data_end {
            return None;
        }
        Some(ptr)
    }

    /// Get VLAN ID from TCI (lower 12 bits)
    #[allow(dead_code)]
    pub fn vlan_id(&self) -> u16 {
        u16::from_be(self.tci) & 0x0FFF
    }

    /// Get Priority Code Point (PCP) from TCI (upper 3 bits)
    #[allow(dead_code)]
    pub fn pcp(&self) -> u8 {
        (u16::from_be(self.tci) >> 13) as u8
    }

    /// Get DEI (Drop Eligible Indicator) from TCI
    #[allow(dead_code)]
    pub fn dei(&self) -> bool {
        (u16::from_be(self.tci) & 0x1000) != 0
    }
}

/// IPv4 头（20-60 字节）
///
/// IP 数据包的第 2 层协议头，固定字段共 20 字节，可选 IP 选项最多扩展到 60 字节。
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// ++++++++++++++++++++++++++++
/// |Version|  IHL   |    DSCP      |           Total Length        |
/// ++++++++++++++++++++++++++++
/// |         Identification        |Flags|     Fragment Offset      |
/// ++++++++++++++++++++++++++++
/// |  Time to Live |    Protocol   |        Header Checksum         |
/// ++++++++++++++++++++++++++++
/// |                         Source Address                        |
/// ++++++++++++++++++++++++++++
/// |                      Destination Address                      |
/// ++++++++++++++++++++++++++++
/// ```
///
/// # 关键字段
///
/// - `version_ihl`：版本号（4）+ 头部长度（单位 4 字节，5-15）
/// - `tot_len`：数据包总长度（包含 IP 头+上层数据）
/// - `proto`：上层协议（6=TCP, 17=UDP, 1=ICMP）
/// - `saddr/daddr`：源/目标 IP 地址（网络字节序）
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct IpHdr {
    /// Version (4) and Internet Header Length (5-15, in 32-bit words)
    version_ihl: u8,
    /// Type of Service / DSCP
    tos: u8,
    /// Total packet length (including header and data)
    tot_len: u16,
    /// Fragment identification
    id: u16,
    /// Flags and fragment offset
    frag_off: u16,
    /// Time to Live
    ttl: u8,
    /// Protocol (TCP=6, UDP=17, ICMP=1)
    proto: u8,
    /// Header checksum
    check: u16,
    /// Source IP address (network byte order)
    saddr: u32,
    /// Destination IP address (network byte order)
    daddr: u32,
}

impl IpHdr {
    /// 从 TC 上下文解析 IPv4 头（在 Ethernet/VLAN 头之后）
    ///
    /// # 参数
    ///
    /// * `ctx` - TC 上下文
    /// * `eth_offset` - IP 头相对于数据包起始的偏移量
    ///   - 无 VLAN：`size_of::<EthHdr>()` = 14
    ///   - 有 VLAN：`size_of::<EthHdr>() + size_of::<VlanHdr>()` = 18
    ///
    /// # 返回值
    ///
    /// - `Some(ptr)`：数据包在 IP 头处足够长
    /// - `None`：数据包长度不足（IP 头被截断）
    ///
    /// # Safety
    ///
    /// 边界检查确保 `ptr + size_of::<IpHdr>() <= data_end`
    pub fn from_ctx_after_eth(ctx: &TcContext, eth_offset: usize) -> Option<*const IpHdr> {
        let data = ctx.data();
        let data_end = ctx.data_end();

        let ptr = unsafe { (data as *const u8).add(eth_offset) as *const IpHdr };
        if ptr as usize + core::mem::size_of::<IpHdr>() > data_end {
            return None;
        }
        Some(ptr)
    }

    /// Get IP version
    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    /// Get IP header length in bytes
    pub fn header_len(&self) -> u8 {
        (self.version_ihl & 0x0F) * 4
    }

    /// 获取源 IP 地址
    ///
    /// # 返回值
    ///
    /// 32 位源 IP（网络字节序），例如 `0xC0A80101` = `192.168.1.1`
    pub fn src_addr(&self) -> u32 {
        self.saddr
    }

    /// 获取目标 IP 地址
    ///
    /// # 返回值
    ///
    /// 32 位目标 IP（网络字节序）
    pub fn dst_addr(&self) -> u32 {
        self.daddr
    }

    /// Get protocol
    pub fn protocol(&self) -> u8 {
        self.proto
    }

    /// Get total length (host byte order)
    pub fn tot_len(&self) -> u16 {
        u16::from_be(self.tot_len)
    }

    /// Get TTL
    #[allow(dead_code)]
    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    /// Check if this is a fragment
    #[allow(dead_code)]
    pub fn is_fragment(&self) -> bool {
        let frag_off = u16::from_be(self.frag_off);
        frag_off & 0x1FFF != 0 || (frag_off & 0x2000) != 0
    }
}

/// TCP 头（20-60 字节）
///
/// TCP 协议的传输层头部，提供可靠连接、流量控制、拥塞控制等功能。
/// dae-tc 使用 TCP 头解析源/目标端口用于会话跟踪。
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// ++++++++++++++++++++++++++++
/// |         Source Port (源端口)      |       Destination Port (目标端口)        |
/// ++++++++++++++++++++++++++++
/// |                        Sequence Number (序列号)                        |
/// ++++++++++++++++++++++++++++
/// |                     Acknowledgment Number (确认号)                      |
/// ++++++++++++++++++++++++++++
/// | Offset|  Flags |               Window Size (窗口大小)                   |
/// ++++++++++++++++++++++++++++
/// |           Checksum (校验和)    |         Urgent Pointer (紧急指针)         |
/// ++++++++++++++++++++++++++++
/// ```
///
/// # dae-tc 中的使用场景
///
/// 提取 `source` 和 `dest` 字段构建 SessionKey 的 5 元组，
/// 结合 IP 层的 src_ip/dst_ip，实现精确的 TCP 连接跟踪。
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct TcpHdr {
    /// Source port (network byte order)
    source: u16,
    /// Destination port (network byte order)
    dest: u16,
    /// Sequence number
    seq: u32,
    /// Acknowledgment number
    ack_seq: u32,
    /// Data offset and flags (offset in upper 4 bits)
    data_offset: u8,
    /// TCP flags (in lower bits)
    flags: u8,
    /// Receive window size
    window: u16,
    /// Checksum
    check: u16,
    /// Urgent pointer
    urgent: u16,
}

/// TCP 标志位常量
///
/// TCP 控制标志用于管理连接状态和数据传输。
mod tcp_flags {
    /// FIN：结束数据传输，双方均可发送 FIN
    pub const FIN: u8 = 0x01;
    /// SYN：同步序列号，建立连接时使用
    pub const SYN: u8 = 0x02;
    /// RST：重置连接
    pub const RST: u8 = 0x04;
    /// PSH：推送，通知接收方立即将数据交付给应用
    pub const PSH: u8 = 0x08;
    /// ACK：确认标志，确认已收到的数据
    pub const ACK: u8 = 0x10;
    /// URG：紧急指针有效
    pub const URG: u8 = 0x20;
    /// ECE：ECN 回显（拥塞通知）
    pub const ECE: u8 = 0x40;
    /// CWR：拥塞窗口减少（与 ECE 配合）
    pub const CWR: u8 = 0x80;
}

impl TcpHdr {
    /// Parse TCP header from context (after IP header)
    pub fn from_ctx_after_ip(
        ctx: &TcContext,
        ip_offset: usize,
        ip_hdr_len: u8,
    ) -> Option<*const TcpHdr> {
        let data = ctx.data();
        let data_end = ctx.data_end();

        let offset = ip_offset + ip_hdr_len as usize;
        let ptr = unsafe { (data as *const u8).add(offset) as *const TcpHdr };
        if ptr as usize + core::mem::size_of::<TcpHdr>() > data_end {
            return None;
        }
        Some(ptr)
    }

    /// Get source port (host byte order)
    pub fn src_port(&self) -> u16 {
        u16::from_be(self.source)
    }

    /// Get destination port (host byte order)
    pub fn dst_port(&self) -> u16 {
        u16::from_be(self.dest)
    }

    /// Get TCP header length in bytes
    pub fn header_len(&self) -> u8 {
        (self.data_offset >> 4) * 4
    }

    /// Check if SYN flag is set
    pub fn is_syn(&self) -> bool {
        self.flags & tcp_flags::SYN != 0
    }

    /// Check if ACK flag is set
    pub fn is_ack(&self) -> bool {
        self.flags & tcp_flags::ACK != 0
    }

    /// Check if FIN flag is set
    pub fn is_fin(&self) -> bool {
        self.flags & tcp_flags::FIN != 0
    }

    /// Check if RST flag is set
    pub fn is_rst(&self) -> bool {
        self.flags & tcp_flags::RST != 0
    }

    /// Check if PSH flag is set
    #[allow(dead_code)]
    pub fn is_psh(&self) -> bool {
        self.flags & tcp_flags::PSH != 0
    }
}

/// UDP 头（固定 8 字节）
///
/// UDP 是一种无连接的传输协议，相比 TCP 更简单、开销更小。
/// 常用于 DNS 查询、QUIC、游戏等对延迟敏感的场景。
///
/// # 特点
///
/// - 固定 8 字节头，无可选字段
/// - 无连接状态，无拥塞控制
/// - `len` 字段包括 UDP 头（8字节）+ 数据部分
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Source Port          |       Destination Port        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Length            |           Checksum              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct UdpHdr {
    /// Source port (network byte order)
    source: u16,
    /// Destination port (network byte order)
    dest: u16,
    /// UDP length (header + data)
    len: u16,
    /// Checksum
    check: u16,
}

impl UdpHdr {
    /// Parse UDP header from context (after IP header)
    pub fn from_ctx_after_ip(
        ctx: &TcContext,
        ip_offset: usize,
        ip_hdr_len: u8,
    ) -> Option<*const UdpHdr> {
        let data = ctx.data();
        let data_end = ctx.data_end();

        let offset = ip_offset + ip_hdr_len as usize;
        let ptr = unsafe { (data as *const u8).add(offset) as *const UdpHdr };
        if ptr as usize + core::mem::size_of::<UdpHdr>() > data_end {
            return None;
        }
        Some(ptr)
    }

    /// Get source port (host byte order)
    pub fn src_port(&self) -> u16 {
        u16::from_be(self.source)
    }

    /// Get destination port (host byte order)
    pub fn dst_port(&self) -> u16 {
        u16::from_be(self.dest)
    }

    /// Get UDP data length (total length minus header)
    #[allow(dead_code)]
    pub fn data_len(&self) -> u16 {
        u16::from_be(self.len) - core::mem::size_of::<UdpHdr>() as u16
    }

    /// Get total length (host byte order)
    #[allow(dead_code)]
    pub fn len(&self) -> u16 {
        u16::from_be(self.len)
    }
}

/// ICMP header (8 bytes)
///
/// Used for diagnostic and error reporting (ping, traceroute, etc.)
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct IcmpHdr {
    /// ICMP type
    icmp_type: u8,
    /// ICMP code (subtype)
    code: u8,
    /// Checksum
    checksum: u16,
    /// Rest of header (varies by type)
    rest: u32,
}

/// ICMP types
pub mod icmp_type {
    pub const ECHO_REPLY: u8 = 0;
    pub const ECHO_REQUEST: u8 = 8;
    pub const DEST_UNREACHABLE: u8 = 3;
    pub const TIME_EXCEEDED: u8 = 11;
}

impl IcmpHdr {
    /// Parse ICMP header from context
    #[allow(dead_code)]
    pub fn from_ctx_after_ip(
        ctx: &TcContext,
        ip_offset: usize,
        ip_hdr_len: u8,
    ) -> Option<*const IcmpHdr> {
        let data = ctx.data();
        let data_end = ctx.data_end();

        let offset = ip_offset + ip_hdr_len as usize;
        let ptr = unsafe { (data as *const u8).add(offset) as *const IcmpHdr };
        if ptr as usize + core::mem::size_of::<IcmpHdr>() > data_end {
            return None;
        }
        Some(ptr)
    }

    /// Get ICMP type
    #[allow(dead_code)]
    pub fn icmp_type(&self) -> u8 {
        self.icmp_type
    }

    /// Get ICMP code
    #[allow(dead_code)]
    pub fn code(&self) -> u8 {
        self.code
    }
}
