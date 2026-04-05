//! Packet parsing - IP, TCP, UDP, DNS header parsing

use crate::connection_pool::ConnectionKey;
use crate::rule_engine::PacketInfo;
use std::net::{IpAddr, Ipv4Addr};

/// IP protocol numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpProtocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    IcmpV6 = 58,
}

impl From<u8> for IpProtocol {
    fn from(v: u8) -> Self {
        match v {
            1 => IpProtocol::Icmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            58 => IpProtocol::IcmpV6,
            _ => IpProtocol::Tcp,
        }
    }
}

/// Parsed IP packet header
#[derive(Debug, Clone)]
pub struct IpHeader {
    /// Version (4 or 6)
    pub version: U4,
    /// Header length in bytes
    pub header_length: u8,
    /// Total packet length
    pub total_length: u16,
    /// Protocol (TCP=6, UDP=17, ICMP=1)
    pub protocol: IpProtocol,
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
}

impl IpHeader {
    /// Parse IPv4 header from bytes
    pub fn parse_ipv4(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 {
            return None;
        }

        let version = (bytes[0] >> 4) & 0xF;
        if version != 4 {
            return None;
        }

        let header_length = (bytes[0] & 0xF) * 4;
        if header_length < 20 || bytes.len() < header_length as usize {
            return None;
        }

        let total_length = u16::from_be_bytes([bytes[2], bytes[3]]);
        let protocol_num = bytes[9];
        let protocol = IpProtocol::from(protocol_num);

        let src_ip = IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]));

        Some(IpHeader {
            version: U4::new(version),
            header_length,
            total_length,
            protocol,
            src_ip,
            dst_ip,
        })
    }

    /// Get payload slice
    pub fn payload<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let start = self.header_length as usize;
        let start = start.min(bytes.len());
        &bytes[start..]
    }
}

/// Version 4 marker type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U4;

impl U4 {
    pub fn new(_v: u8) -> Self {
        Self
    }
}

/// Parsed TCP header
#[derive(Debug, Clone)]
pub struct TcpHeader {
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Sequence number
    pub seq_num: u32,
    /// Acknowledgment number
    pub ack_num: u32,
    /// Data offset (header length)
    pub data_offset: u8,
    /// Flags
    pub flags: TcpFlags,
    /// Window size
    pub window_size: u16,
}

bitflags::bitflags! {
    /// TCP flags
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct TcpFlags: u8 {
        const FIN = 0x01;
        const SYN = 0x02;
        const RST = 0x04;
        const PSH = 0x08;
        const ACK = 0x10;
    }
}

impl TcpHeader {
    /// Parse TCP header from bytes
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 {
            return None;
        }

        let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
        let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
        let seq_num = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let ack_num = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let data_offset = (bytes[12] >> 4) * 4;
        let flags = TcpFlags::from_bits_truncate(bytes[13]);
        let window_size = u16::from_be_bytes([bytes[14], bytes[15]]);

        if data_offset < 20 || bytes.len() < data_offset as usize {
            return None;
        }

        Some(TcpHeader {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset,
            flags,
            window_size,
        })
    }

    /// Check if this is a SYN packet
    pub fn is_syn(&self) -> bool {
        self.flags.contains(TcpFlags::SYN) && !self.flags.contains(TcpFlags::ACK)
    }

    /// Check if this is a SYN-ACK packet
    pub fn is_syn_ack(&self) -> bool {
        self.flags.contains(TcpFlags::SYN) && self.flags.contains(TcpFlags::ACK)
    }

    /// Check if this is a FIN packet
    pub fn is_fin(&self) -> bool {
        self.flags.contains(TcpFlags::FIN)
    }

    /// Check if this is a RST packet
    pub fn is_rst(&self) -> bool {
        self.flags.contains(TcpFlags::RST)
    }

    /// Get payload offset
    pub fn payload_offset(&self) -> usize {
        self.data_offset as usize
    }
}

/// Parsed UDP header
#[derive(Debug, Clone)]
pub struct UdpHeader {
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// UDP payload length
    pub length: u16,
}

impl UdpHeader {
    /// Parse UDP header from bytes
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }

        let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
        let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
        let length = u16::from_be_bytes([bytes[4], bytes[5]]);

        Some(UdpHeader {
            src_port,
            dst_port,
            length,
        })
    }
}

/// DNS query parser
#[derive(Debug, Clone)]
pub struct DnsQuery {
    /// Transaction ID
    pub id: u16,
    /// Query type (A=1, AAAA=28, etc.)
    pub qtype: u16,
    /// Queried domain name
    pub domain: String,
}

impl DnsQuery {
    /// Parse DNS query from UDP payload
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }

        let id = u16::from_be_bytes([bytes[0], bytes[1]]);

        // Skip DNS header (12 bytes)
        let mut pos = 12;
        let mut domain = String::new();

        // Read domain name
        while pos < bytes.len() {
            let label_len = bytes[pos] as usize;
            if label_len == 0 {
                break;
            }

            // Check for compression pointer
            if label_len >= 0xC0 {
                // Compression not supported for simplicity
                break;
            }

            if !domain.is_empty() {
                domain.push('.');
            }

            pos += 1;
            if pos + label_len > bytes.len() {
                return None;
            }

            domain.push_str(&String::from_utf8_lossy(&bytes[pos..pos + label_len]));
            pos += label_len;
        }

        if domain.is_empty() {
            return None;
        }

        pos += 1; // Skip null terminator

        // Read query type
        if pos + 2 > bytes.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);

        Some(DnsQuery { id, qtype, domain })
    }
}

/// TUN packet direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    /// Outbound packet (from TUN to network)
    Outbound,
    /// Inbound packet (from network to TUN)
    Inbound,
}

/// TUN packet with parsed headers
#[derive(Debug, Clone)]
pub struct TunPacket {
    /// Raw packet bytes
    pub bytes: Vec<u8>,
    /// Parsed IP header
    pub ip_header: IpHeader,
    /// TCP header (if TCP)
    pub tcp_header: Option<TcpHeader>,
    /// UDP header (if UDP)
    pub udp_header: Option<UdpHeader>,
    /// DNS query (if DNS)
    pub dns_query: Option<DnsQuery>,
    /// Packet direction
    pub direction: PacketDirection,
    /// Connection key for this packet
    pub connection_key: Option<ConnectionKey>,
}

impl TunPacket {
    /// Create a new TUN packet from bytes
    pub fn parse(bytes: Vec<u8>, direction: PacketDirection) -> Option<Self> {
        let ip_header = IpHeader::parse_ipv4(&bytes)?;

        let tcp_header = match ip_header.protocol {
            IpProtocol::Tcp => TcpHeader::parse(ip_header.payload(&bytes)),
            _ => None,
        };

        let udp_header = match ip_header.protocol {
            IpProtocol::Udp => UdpHeader::parse(ip_header.payload(&bytes)),
            _ => None,
        };

        // Parse DNS query if UDP to port 53
        let dns_query = if let (Some(udp), IpProtocol::Udp) = (&udp_header, ip_header.protocol) {
            if udp.dst_port == 53 {
                // Skip UDP header (8 bytes) to get DNS payload
                let dns_payload = ip_header.payload(&bytes);
                if dns_payload.len() > 8 {
                    DnsQuery::parse(&dns_payload[8..])
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // Create connection key
        let connection_key = match (ip_header.protocol, &tcp_header, &udp_header) {
            (IpProtocol::Tcp, Some(tcp), _) => {
                let src_ip = match ip_header.src_ip {
                    IpAddr::V4(ip) => u32::from(ip),
                    _ => 0,
                };
                let dst_ip = match ip_header.dst_ip {
                    IpAddr::V4(ip) => u32::from(ip),
                    _ => 0,
                };
                Some(ConnectionKey::from_raw(
                    src_ip,
                    dst_ip,
                    tcp.src_port,
                    tcp.dst_port,
                    6,
                ))
            }
            (IpProtocol::Udp, _, Some(udp)) => {
                let src_ip = match ip_header.src_ip {
                    IpAddr::V4(ip) => u32::from(ip),
                    _ => 0,
                };
                let dst_ip = match ip_header.dst_ip {
                    IpAddr::V4(ip) => u32::from(ip),
                    _ => 0,
                };
                Some(ConnectionKey::from_raw(
                    src_ip,
                    dst_ip,
                    udp.src_port,
                    udp.dst_port,
                    17,
                ))
            }
            _ => None,
        };

        Some(TunPacket {
            bytes,
            ip_header,
            tcp_header,
            udp_header,
            dns_query,
            direction,
            connection_key,
        })
    }

    /// Get source port
    pub fn src_port(&self) -> u16 {
        self.tcp_header
            .as_ref()
            .map(|h| h.src_port)
            .or_else(|| self.udp_header.as_ref().map(|h| h.src_port))
            .unwrap_or(0)
    }

    /// Get destination port
    pub fn dst_port(&self) -> u16 {
        self.tcp_header
            .as_ref()
            .map(|h| h.dst_port)
            .or_else(|| self.udp_header.as_ref().map(|h| h.dst_port))
            .unwrap_or(0)
    }

    /// Create PacketInfo for rule matching
    pub fn to_packet_info(&self) -> PacketInfo {
        let proto = match self.ip_header.protocol {
            IpProtocol::Tcp => 6,
            IpProtocol::Udp => 17,
            IpProtocol::Icmp => 1,
            IpProtocol::IcmpV6 => 58,
        };

        let mut info = PacketInfo::new(
            self.ip_header.src_ip,
            self.ip_header.dst_ip,
            self.src_port(),
            self.dst_port(),
            proto,
        );

        // Set DNS query info if available
        if let Some(ref dns) = self.dns_query {
            info = info.with_domain(&dns.domain);
            info = info.with_dns_type(dns.qtype);
        }

        info
    }

    /// Check if this is a DNS packet
    pub fn is_dns(&self) -> bool {
        self.dns_query.is_some()
    }

    /// Check if this is a TCP packet
    pub fn is_tcp(&self) -> bool {
        matches!(self.ip_header.protocol, IpProtocol::Tcp)
    }

    /// Check if this is a UDP packet
    pub fn is_udp(&self) -> bool {
        matches!(self.ip_header.protocol, IpProtocol::Udp)
    }
}
