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

/// Ethernet protocol types (EtherType values)
pub mod ethertype {
    /// IPv4
    pub const IPV4: u16 = 0x0800;
    /// IPv6
    pub const IPV6: u16 = 0x86DD;
    /// IEEE 802.1Q VLAN tagging
    pub const VLAN: u16 = 0x8100;
}

/// IP protocol numbers
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

/// Ethernet header (14 bytes)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Destination MAC                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Source MAC                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         EtherType            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EthHdr {
    /// Destination MAC address
    dst: [u8; 6],
    /// Source MAC address
    src: [u8; 6],
    /// EtherType (network byte order)
    ether_type: u16,
}

impl EthHdr {
    /// Parse Ethernet header from tc context
    ///
    /// Returns a pointer to the Ethernet header if the packet is large enough,
    /// or None if the packet is too small.
    pub fn from_ctx(ctx: &TcContext) -> Option<*const EthHdr> {
        let data = ctx.data();
        let data_end = ctx.data_end();

        let ptr = data as *const EthHdr;
        if ptr as usize + core::mem::size_of::<EthHdr>() > data_end {
            return None;
        }
        Some(ptr)
    }

    /// Get the EtherType in host byte order
    pub fn ether_type(&self) -> u16 {
        u16::from_be(self.ether_type)
    }

    /// Check if this is an IPv4 packet
    pub fn is_ipv4(&self) -> bool {
        self.ether_type() == ethertype::IPV4
    }

    /// Check if this is an IPv6 packet
    #[allow(dead_code)]
    pub fn is_ipv6(&self) -> bool {
        self.ether_type() == ethertype::IPV6
    }

    /// Check if this has a VLAN tag (EtherType is 0x8100)
    pub fn has_vlan(&self) -> bool {
        self.ether_type() == ethertype::VLAN
    }

    /// Get source MAC address
    pub fn src_mac(&self) -> [u8; 6] {
        self.src
    }

    /// Get destination MAC address
    #[allow(dead_code)]
    pub fn dst_mac(&self) -> [u8; 6] {
        self.dst
    }
}

/// IEEE 802.1Q VLAN tag header (4 bytes)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | TPID (0x8100) |         TCI (VLAN ID, PCP, DEI)              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct VlanHdr {
    /// Tag Protocol Identifier (should be 0x8100 for 802.1Q)
    pub tpid: u16,
    /// Tag Control Information (VLAN ID in lower 12 bits)
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

/// IPv4 header (20-60 bytes)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version|  IHL   |    DSCP      |           Total Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Identification        |Flags|     Fragment Offset      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Time to Live |    Protocol   |        Header Checksum         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Source Address                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Destination Address                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
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
    /// Parse IPv4 header from context (after Ethernet/VLAN header)
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

    /// Get source address (network byte order)
    pub fn src_addr(&self) -> u32 {
        self.saddr
    }

    /// Get destination address (network byte order)
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

/// TCP header (20-60 bytes)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Source Port          |       Destination Port        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Sequence Number                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Acknowledgment Number                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Offset|  Flags |               Window Size                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Checksum            |         Urgent Pointer         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
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

/// TCP flags
mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
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

/// UDP header (8 bytes)
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
