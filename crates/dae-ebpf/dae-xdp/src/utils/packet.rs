//! Packet parsing helpers for XDP
//!
//! Provides utilities for parsing Ethernet, IP, TCP, and UDP headers.

#![allow(dead_code)]

use aya_ebpf::programs::XdpContext;

/// Ethernet protocol types
pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const IPV6: u16 = 0x86DD;
    pub const VLAN: u16 = 0x8100;
}

/// IP protocol numbers
pub mod ip_proto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
}

/// Parse Ethernet header
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EthHdr {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ether_type: u16,
}

/// IEEE 802.1Q VLAN tag header (4 bytes)
/// Present when EtherType is 0x8100 (VLAN)
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct VlanHdr {
    pub tpid: u16, // Tag Protocol Identifier (0x8100)
    pub tci: u16,  // Tag Control Information (VLAN ID, PCP, DEI)
}

impl EthHdr {
    /// Parse Ethernet header from context
    pub fn from_ctx(ctx: &XdpContext) -> Option<*const EthHdr> {
        let data = ctx.data();
        let data_end = ctx.data_end();

        let ptr = data as *const EthHdr;
        // Safety: check that the header fits within bounds
        if ptr as usize + core::mem::size_of::<EthHdr>() > data_end {
            return None;
        }
        Some(ptr)
    }

    /// Get the EtherType in network byte order
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
    #[allow(dead_code)]
    pub fn has_vlan(&self) -> bool {
        self.ether_type() == ethertype::VLAN
    }

    /// Get source MAC address as byte array
    #[allow(dead_code)]
    pub fn src_mac(&self) -> [u8; 6] {
        self.src
    }
}

impl VlanHdr {
    /// Parse VLAN header from context (after Ethernet header)
    pub fn from_ctx_after_eth(ctx: &XdpContext, eth_offset: usize) -> Option<*const VlanHdr> {
        let data = ctx.data();
        let data_end = ctx.data_end();

        // SAFETY: ptr is guaranteed to be within packet buffer bounds.
        // Caller ensures eth_offset + size_of::<VlanHdr>() <= data.len().
        // The bounds check below verifies this before returning Some.
        let ptr = unsafe { (data as *const u8).add(eth_offset) as *const VlanHdr };
        if ptr as usize + core::mem::size_of::<VlanHdr>() > data_end {
            return None;
        }
        Some(ptr)
    }

    /// Get the actual EtherType after VLAN tag (network byte order)
    #[allow(dead_code)]
    pub fn inner_ether_type(&self) -> u16 {
        u16::from_be(self.tci)
    }

    /// Get VLAN ID from TCI
    #[allow(dead_code)]
    pub fn vlan_id(&self) -> u16 {
        u16::from_be(self.tci) & 0x0FFF
    }
}

/// Parse IPv4 header
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct IpHdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub proto: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

impl IpHdr {
    /// Parse IPv4 header from context (after Ethernet header)
    pub fn from_ctx_after_eth(ctx: &XdpContext, eth_offset: usize) -> Option<*const IpHdr> {
        let data = ctx.data();
        let data_end = ctx.data_end();

        // SAFETY: ptr is guaranteed to be within packet buffer bounds.
        // Caller ensures eth_offset + size_of::<IpHdr>() <= data.len().
        // The bounds check below verifies this before returning Some.
        let ptr = unsafe { (data as *const u8).add(eth_offset) as *const IpHdr };
        if ptr as usize + core::mem::size_of::<IpHdr>() > data_end {
            return None;
        }
        Some(ptr)
    }

    /// Get IP version (4 or 6)
    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    /// Get IP header length in bytes
    #[allow(dead_code)]
    pub fn header_len(&self) -> u8 {
        (self.version_ihl & 0x0F) * 4
    }

    /// Get source address (network byte order)
    #[allow(dead_code)]
    pub fn src_addr(&self) -> u32 {
        self.saddr
    }

    /// Get destination address (network byte order)
    pub fn dst_addr(&self) -> u32 {
        self.daddr
    }

    /// Get protocol
    #[allow(dead_code)]
    pub fn protocol(&self) -> u8 {
        self.proto
    }
}

/// Parse TCP header
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct TcpHdr {
    pub source: u16,
    pub dest: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window: u16,
    pub check: u16,
    pub urgent: u16,
}

impl TcpHdr {
    /// Parse TCP header from context (after IP header)
    #[allow(dead_code)]
    pub fn from_ctx_after_ip(
        ctx: &XdpContext,
        ip_offset: usize,
        ip_hdr_len: u8,
    ) -> Option<*const TcpHdr> {
        let data = ctx.data();
        let data_end = ctx.data_end();

        let offset = ip_offset + ip_hdr_len as usize;
        // SAFETY: ptr is guaranteed to be within packet buffer bounds.
        // Caller ensures offset + size_of::<TcpHdr>() <= data.len().
        // The bounds check below verifies this before returning Some.
        let ptr = unsafe { (data as *const u8).add(offset) as *const TcpHdr };
        if ptr as usize + core::mem::size_of::<TcpHdr>() > data_end {
            return None;
        }
        Some(ptr)
    }

    /// Get source port (network byte order)
    #[allow(dead_code)]
    pub fn src_port(&self) -> u16 {
        u16::from_be(self.source)
    }

    /// Get destination port (network byte order)
    #[allow(dead_code)]
    pub fn dst_port(&self) -> u16 {
        u16::from_be(self.dest)
    }

    /// Get TCP header length in bytes
    #[allow(dead_code)]
    pub fn header_len(&self) -> u8 {
        (self.data_offset >> 4) * 4
    }

    /// Check if SYN flag is set
    #[allow(dead_code)]
    pub fn is_syn(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// Check if ACK flag is set
    #[allow(dead_code)]
    pub fn is_ack(&self) -> bool {
        self.flags & 0x10 != 0
    }

    /// Check if FIN flag is set
    #[allow(dead_code)]
    pub fn is_fin(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Check if RST flag is set
    #[allow(dead_code)]
    pub fn is_rst(&self) -> bool {
        self.flags & 0x04 != 0
    }
}

/// Parse UDP header
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct UdpHdr {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}

impl UdpHdr {
    /// Parse UDP header from context (after IP header)
    #[allow(dead_code)]
    pub fn from_ctx_after_ip(
        ctx: &XdpContext,
        ip_offset: usize,
        ip_hdr_len: u8,
    ) -> Option<*const UdpHdr> {
        let data = ctx.data();
        let data_end = ctx.data_end();

        let offset = ip_offset + ip_hdr_len as usize;
        // SAFETY: ptr is guaranteed to be within packet buffer bounds.
        // Caller ensures offset + size_of::<UdpHdr>() <= data.len().
        // The bounds check below verifies this before returning Some.
        let ptr = unsafe { (data as *const u8).add(offset) as *const UdpHdr };
        if ptr as usize + core::mem::size_of::<UdpHdr>() > data_end {
            return None;
        }
        Some(ptr)
    }

    /// Get source port (network byte order)
    #[allow(dead_code)]
    pub fn src_port(&self) -> u16 {
        u16::from_be(self.source)
    }

    /// Get destination port (network byte order)
    #[allow(dead_code)]
    pub fn dst_port(&self) -> u16 {
        u16::from_be(self.dest)
    }
}
