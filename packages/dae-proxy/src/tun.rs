//! TUN transparent proxy implementation
//!
//! Provides TUN device management and IP packet routing for transparent proxy.
//!
//! This module intercepts network traffic at the IP level and routes it based
//! on the rule engine decisions - either through the proxy or directly.
//!
//! # Architecture
//!
//! - `TunDevice`: TUN device wrapper using tokio-tun
//! - `TunPacketParser`: Parse IP/TCP/UDP headers from raw packets
//! - `DnsHijacker`: Handle DNS hijacking for domain-based routing
//! - `TunRouter`: Route packets based on rule engine decisions
//!
//! # Usage
//!
//! ```ignore
//! let config = TunConfig {
//!     enabled: true,
//!     interface: "dae0".to_string(),
//!     tun_ip: "10.0.0.1".to_string(),
//!     tun_netmask: "255.255.255.0".to_string(),
//!     dns_hijack: vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()],
//!     mtu: 1500,
//! };
//!
//! let tun = TunProxy::new(config, rule_engine, connection_pool);
//! tun.start().await?;
//! ```

use crate::connection_pool::{ConnectionKey, SharedConnectionPool};
use crate::rule_engine::{PacketInfo, RuleAction, SharedRuleEngine};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// DNS hijack entry - maps queried IP to domain for rule matching
#[derive(Debug, Clone)]
pub struct DnsHijackEntry {
    /// The IP address that was returned in the DNS response
    pub queried_ip: IpAddr,
    /// The domain name that was queried
    pub domain: String,
    /// When this entry was created
    pub timestamp: std::time::Instant,
}

impl DnsHijackEntry {
    /// Check if entry is expired (5 minutes TTL)
    pub fn is_expired(&self) -> bool {
        self.timestamp.elapsed() > Duration::from_secs(300)
    }
}

/// TUN device configuration
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Enable TUN transparent proxy
    pub enabled: bool,
    /// TUN interface name
    pub interface: String,
    /// TUN device IP address
    pub tun_ip: String,
    /// TUN netmask
    pub tun_netmask: String,
    /// DNS hijack server addresses ( IPs to intercept DNS queries to)
    pub dns_hijack: Vec<IpAddr>,
    /// MTU for TUN device
    pub mtu: u32,
    /// TCP connection timeout
    pub tcp_timeout: Duration,
    /// UDP session timeout
    pub udp_timeout: Duration,
    /// Maximum packet size
    pub max_packet_size: usize,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: "dae0".to_string(),
            tun_ip: "10.0.0.1".to_string(),
            tun_netmask: "255.255.255.0".to_string(),
            dns_hijack: vec![
                "8.8.8.8".parse().unwrap(),
                "8.8.4.4".parse().unwrap(),
            ],
            mtu: 1500,
            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(30),
            max_packet_size: 64 * 1024,
        }
    }
}

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
    pub version: u4,
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
            version: u4::new(version),
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
pub struct u4;

impl u4 {
    pub fn new(v: u8) -> Self {
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

        Some(DnsQuery {
            id,
            qtype,
            domain,
        })
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
            _ => 0,
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

/// DNS hijacker for intercepting and handling DNS queries
pub struct DnsHijacker {
    /// DNS cache: domain -> hijack entry
    cache: RwLock<HashMap<String, DnsHijackEntry>>,
    /// DNS upstream servers to forward queries to
    upstream_servers: Vec<SocketAddr>,
    /// DNS response timeout
    timeout: Duration,
}

impl DnsHijacker {
    /// Create a new DNS hijacker
    pub fn new(upstream_servers: Vec<SocketAddr>) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            upstream_servers,
            timeout: Duration::from_secs(5),
        }
    }

    /// Check if an IP is in the hijack list
    pub fn is_hijacked_ip(&self, ip: IpAddr) -> bool {
        self.upstream_servers
            .iter()
            .any(|server| server.ip() == ip)
    }

    /// Cache a DNS hijack entry
    pub async fn cache_entry(&self, domain: String, ip: IpAddr) {
        let entry = DnsHijackEntry {
            queried_ip: ip,
            domain: domain.clone(),
            timestamp: std::time::Instant::now(),
        };
        let mut cache = self.cache.write().await;
        cache.insert(domain.to_lowercase(), entry);
    }

    /// Lookup a cached domain
    pub async fn lookup(&self, domain: &str) -> Option<IpAddr> {
        let cache = self.cache.read().await;
        cache
            .get(&domain.to_lowercase())
            .filter(|e| !e.is_expired())
            .map(|e| e.queried_ip)
    }

    /// Handle a DNS query packet
    /// Returns the response bytes if we should respond, None if forwarding
    pub async fn handle_query(
        &self,
        query: &DnsQuery,
        src_ip: IpAddr,
        _src_port: u16,
    ) -> Option<Vec<u8>> {
        // Check cache first
        if let Some(cached_ip) = self.lookup(&query.domain).await {
            debug!("DNS cache hit for {} -> {}", query.domain, cached_ip);
            return Some(self.build_response(query, cached_ip));
        }

        // Forward to upstream
        debug!(
            "DNS forwarding query for {} to upstream",
            query.domain
        );
        self.forward_query(query).await
    }

    /// Forward DNS query to upstream and cache result
    async fn forward_query(&self, query: &DnsQuery) -> Option<Vec<u8>> {
        if self.upstream_servers.is_empty() {
            warn!("No upstream DNS servers configured");
            return None;
        }

        let upstream = self.upstream_servers[0];
        let socket = match UdpSocket::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
        ))
        .await
        {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to bind DNS socket: {}", e);
                return None;
            }
        };

        // Build DNS query packet
        let mut query_bytes = vec![0u8; 512];
        // DNS header
        query_bytes[0..2].copy_from_slice(&query.id.to_be_bytes()); // ID
        query_bytes[2..4].copy_from_slice(&[0x01, 0x00]); // Flags: recursion desired
        query_bytes[4..6].copy_from_slice(&1u16.to_be_bytes()); // 1 question
        // Question
        let domain_parts: Vec<&str> = query.domain.split('.').collect();
        let mut pos = 12;
        for part in &domain_parts {
            query_bytes[pos] = part.len() as u8;
            pos += 1;
            query_bytes[pos..pos + part.len()].copy_from_slice(part.as_bytes());
            pos += part.len();
        }
        query_bytes[pos] = 0; // End of domain
        pos += 1;
        query_bytes[pos..pos + 2].copy_from_slice(&query.qtype.to_be_bytes()); // Query type
        pos += 2;
        query_bytes[pos..pos + 2].copy_from_slice(&1u16.to_be_bytes()); // Class: IN
        let query_len = pos + 2;

        match timeout(
            self.timeout,
            socket.send_to(&query_bytes[..query_len], upstream),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                error!("DNS upstream send error: {}", e);
                return None;
            }
            Err(_) => {
                error!("DNS upstream timeout");
                return None;
            }
        }

        // Wait for response
        let mut response_buf = [0u8; 512];
        match timeout(self.timeout, socket.recv_from(&mut response_buf)).await {
            Ok(Ok((len, _))) => {
                let response = response_buf[..len].to_vec();
                // Try to extract IP from response and cache it
                if let Some(ip) = self.extract_ip_from_response(&response) {
                    self.cache_entry(query.domain.clone(), ip).await;
                }
                Some(response)
            }
            Ok(Err(e)) => {
                error!("DNS upstream recv error: {}", e);
                None
            }
            Err(_) => {
                error!("DNS upstream response timeout");
                None
            }
        }
    }

    /// Extract IP from DNS response
    fn extract_ip_from_response(&self, response: &[u8]) -> Option<IpAddr> {
        if response.len() < 12 {
            return None;
        }

        // Skip DNS header and question
        let mut pos = 12;
        loop {
            if pos >= response.len() {
                return None;
            }
            let len = response[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if len >= 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + len;
        }

        // Skip query type and class (4 bytes)
        pos += 4;

        // Skip answer sections until we find an A record
        while pos < response.len() {
            // Skip name
            loop {
                if pos >= response.len() {
                    return None;
                }
                let len = response[pos] as usize;
                if len >= 0xC0 {
                    pos += 2;
                    break;
                }
                if len == 0 {
                    pos += 1;
                    break;
                }
                pos += 1 + len;
            }

            if pos + 10 > response.len() {
                return None;
            }

            let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
            // Skip TTL (4 bytes) and RDLENGTH (2 bytes)
            pos += 8;
            let rdlength = u16::from_be_bytes([response[pos], response[pos + 1]]);
            pos += 2;

            if rtype == 1 && rdlength == 4 {
                // A record with IPv4
                return Some(IpAddr::V4(Ipv4Addr::new(
                    response[pos],
                    response[pos + 1],
                    response[pos + 2],
                    response[pos + 3],
                )));
            }

            pos += rdlength as usize;
        }

        None
    }

    /// Build a DNS response with a fake IP
    fn build_response(&self, query: &DnsQuery, ip: IpAddr) -> Vec<u8> {
        let mut response = vec![0u8; 40];

        // DNS Header
        response[0..2].copy_from_slice(&query.id.to_be_bytes()); // ID
        response[2..4].copy_from_slice(&[0x81, 0x80]); // Flags: recursion desired + recursion available
        response[4..6].copy_from_slice(&1u16.to_be_bytes()); // 1 question
        response[6..8].copy_from_slice(&1u16.to_be_bytes()); // 1 answer
        response[8..10].copy_from_slice(&0u16.to_be_bytes()); // Authority (0)
        response[10..12].copy_from_slice(&0u16.to_be_bytes()); // Additional (0)

        // Question (copy from request)
        let domain_parts: Vec<&str> = query.domain.split('.').collect();
        let mut pos = 12;
        for part in &domain_parts {
            response.push(part.len() as u8);
            response.extend_from_slice(part.as_bytes());
        }
        response.push(0); // End of domain
        response.extend_from_slice(&query.qtype.to_be_bytes()); // Query type
        response.extend_from_slice(&1u16.to_be_bytes()); // Class: IN

        // Answer
        response.push(0xC0); // Compression pointer to question name
        response.push(12); // Offset to question name

        // Answer section header
        response.extend_from_slice(&query.qtype.to_be_bytes()); // Type
        response.extend_from_slice(&1u16.to_be_bytes()); // Class: IN
        response.extend_from_slice(&300u32.to_be_bytes()); // TTL: 300 seconds
        response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH: 4 bytes

        // RDATA: IPv4 address
        if let IpAddr::V4(ipv4) = ip {
            response.extend_from_slice(&ipv4.octets());
        }

        response
    }
}

/// DNS hijacker shared type
pub type SharedDnsHijacker = Arc<DnsHijacker>;

/// Create a new shared DNS hijacker
pub fn new_dns_hijacker(upstream_servers: Vec<SocketAddr>) -> SharedDnsHijacker {
    Arc::new(DnsHijacker::new(upstream_servers))
}

/// TCP session state for TUN proxy
#[derive(Debug, Clone)]
pub enum TcpSessionState {
    /// Waiting for connection setup
    SynSent,
    /// Connection established
    Established,
    /// Fin sent
    FinWait,
    /// Session closed
    Closed,
}

/// TCP session for TUN transparent proxy
pub struct TcpTunSession {
    /// Session state
    pub state: TcpSessionState,
    /// Last activity time
    pub last_activity: std::time::Instant,
    /// Client-side TUN sequence
    pub client_seq: u32,
    /// Server-side TUN sequence
    pub server_seq: u32,
    /// Client-side acknowledgment
    pub client_ack: u32,
    /// Server-side acknowledgment
    pub server_ack: u32,
}

impl TcpTunSession {
    /// Create a new TCP session
    pub fn new() -> Self {
        Self {
            state: TcpSessionState::SynSent,
            last_activity: std::time::Instant::now(),
            client_seq: 0,
            server_seq: 0,
            client_ack: 0,
            server_ack: 0,
        }
    }

    /// Update last activity
    pub fn touch(&mut self) {
        self.last_activity = std::time::Instant::now();
    }

    /// Check if session is expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

impl Default for TcpTunSession {
    fn default() -> Self {
        Self::new()
    }
}

/// TUN proxy main handler
pub struct TunProxy {
    /// Configuration
    config: TunConfig,
    /// Rule engine
    rule_engine: SharedRuleEngine,
    /// Connection pool
    connection_pool: SharedConnectionPool,
    /// DNS hijacker
    dns_hijacker: SharedDnsHijacker,
    /// TCP sessions
    tcp_sessions: RwLock<HashMap<ConnectionKey, Arc<TcpTunSession>>>,
    /// UDP sessions
    udp_sessions: RwLock<HashMap<ConnectionKey, Arc<UdpSessionData>>>,
    /// Local TUN IP
    local_ip: Ipv4Addr,
}

impl TunProxy {
    /// Create a new TUN proxy
    pub fn new(
        config: TunConfig,
        rule_engine: SharedRuleEngine,
        connection_pool: SharedConnectionPool,
        dns_hijacker: SharedDnsHijacker,
    ) -> Self {
        let local_ip: Ipv4Addr = config.tun_ip.parse().unwrap_or(Ipv4Addr::new(10, 0, 0, 1));

        Self {
            config,
            rule_engine,
            connection_pool,
            dns_hijacker,
            tcp_sessions: RwLock::new(HashMap::new()),
            udp_sessions: RwLock::new(HashMap::new()),
            local_ip,
        }
    }

    /// Check if this packet should be handled by TUN proxy
    pub fn should_handle(&self, packet: &TunPacket) -> bool {
        // Handle outbound packets (from local to network)
        // and inbound packets (from network to local)

        // Check if destination is our TUN IP
        if let IpAddr::V4(dst) = packet.ip_header.dst_ip {
            if dst == self.local_ip {
                return true;
            }
        }

        // Check if this is DNS hijack
        if packet.is_dns() && self.dns_hijacker.is_hijacked_ip(packet.ip_header.dst_ip) {
            return true;
        }

        // Handle all outbound packets from TUN
        if packet.direction == PacketDirection::Outbound {
            return true;
        }

        false
    }

    /// Route a packet based on rule engine decision
    pub async fn route_packet(&self, packet: TunPacket) -> RouteResult {
        let info = packet.to_packet_info();
        let action = self.rule_engine.match_packet(&info).await;

        debug!(
            "Routing packet: {} -> {} (proto: {:?}, port: {}), action: {:?}",
            packet.ip_header.src_ip,
            packet.ip_header.dst_ip,
            packet.ip_header.protocol,
            packet.dst_port(),
            action
        );

        match action {
            RuleAction::Proxy | RuleAction::Default => {
                // Route through proxy
                self.proxy_packet(packet).await
            }
            RuleAction::Pass | RuleAction::Direct | RuleAction::MustDirect => {
                // Direct forwarding
                self.direct_packet(packet).await
            }
            RuleAction::Drop => {
                // Drop the packet
                RouteResult::Dropped
            }
        }
    }

    /// Proxy a packet through the proxy chain
    async fn proxy_packet(&self, packet: TunPacket) -> RouteResult {
        if packet.is_dns() {
            // Handle DNS specially
            if let Some(ref dns) = packet.dns_query {
                let src_port = packet.src_port();
                if let Some(response) = self
                    .dns_hijacker
                    .handle_query(dns, packet.ip_header.src_ip, src_port)
                    .await
                {
                    // Inject DNS response back to TUN
                    return RouteResult::Response(response);
                }
            }
            return RouteResult::Forwarded;
        }

        if packet.is_tcp() {
            // TCP proxy via connection pool
            if let Some(key) = &packet.connection_key {
                return RouteResult::Forwarded; // Would need actual proxy connection
            }
        }

        if packet.is_udp() {
            // UDP proxy
            return RouteResult::Forwarded; // Would need actual UDP relay
        }

        RouteResult::Dropped
    }

    /// Directly forward a packet (no proxy)
    async fn direct_packet(&self, packet: TunPacket) -> RouteResult {
        // Direct forwarding would send packet back to TUN device
        // The actual network send would be handled by the TUN device write
        RouteResult::Forwarded
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) {
        let tcp_timeout = self.config.tcp_timeout;
        let udp_timeout = self.config.udp_timeout;

        // Cleanup TCP sessions
        {
            let mut sessions = self.tcp_sessions.write().await;
            sessions.retain(|_, session| !session.is_expired(tcp_timeout));
        }

        // Cleanup UDP sessions
        {
            let mut sessions = self.udp_sessions.write().await;
            sessions.retain(|_, session| !session.is_expired(udp_timeout));
        }
    }

    /// Get statistics
    pub async fn stats(&self) -> TunStats {
        let tcp_count = self.tcp_sessions.read().await.len();
        let udp_count = self.udp_sessions.read().await.len();
        let dns_cache_size = self.dns_hijacker.cache.read().await.len();

        TunStats {
            active_tcp_sessions: tcp_count,
            active_udp_sessions: udp_count,
            dns_cache_size,
        }
    }
}

/// Result of routing a packet
#[derive(Debug, Clone)]
pub enum RouteResult {
    /// Packet was dropped
    Dropped,
    /// Packet was forwarded (direct or proxy)
    Forwarded,
    /// Packet should be responded to (e.g., DNS response)
    Response(Vec<u8>),
}

/// TUN proxy statistics
#[derive(Debug, Clone)]
pub struct TunStats {
    /// Number of active TCP sessions
    pub active_tcp_sessions: usize,
    /// Number of active UDP sessions
    pub active_udp_sessions: usize,
    /// DNS cache size
    pub dns_cache_size: usize,
}

/// UDP session data for TUN proxy
#[derive(Debug)]
pub struct UdpSessionData {
    /// Client address (TUN side)
    pub client_addr: SocketAddr,
    /// Server address (network side)
    pub server_addr: SocketAddr,
    /// Client socket
    pub client_socket: Arc<UdpSocket>,
    /// Server socket
    pub server_socket: Arc<UdpSocket>,
    /// Last activity time
    pub last_activity: std::time::Instant,
}

impl UdpSessionData {
    /// Check if session is expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Update last activity
    pub fn touch(&mut self) {
        self.last_activity = std::time::Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_header_parse() {
        // IPv4 packet: 20 bytes header + data
        let packet = vec![
            0x45, // Version 4, IHL 5
            0x00, // DSCP/ECN
            0x00, 0x28, // Total length: 40 bytes
            0x00, 0x00, // ID
            0x00, 0x00, // Flags/Fragment
            0x40, // TTL: 64
            0x06, // Protocol: TCP
            0x00, 0x00, // Checksum (zero for test)
            0xC0, 0xA8, 0x01, 0x64, // Source: 192.168.1.100
            0x08, 0x08, 0x08, 0x08, // Dest: 8.8.8.8
        ];

        let header = IpHeader::parse_ipv4(&packet);
        assert!(header.is_some());

        let header = header.unwrap();
        assert_eq!(header.version, u4::new(4));
        assert_eq!(header.header_length, 20);
        assert_eq!(header.total_length, 40);
        assert_eq!(header.protocol, IpProtocol::Tcp);
        assert_eq!(header.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(header.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_tcp_header_parse() {
        let tcp_header = vec![
            0xC0, 0xA8, // Source port: 49320
            0x00, 0x50, // Dest port: 80
            0x00, 0x00, 0x00, 0x01, // Sequence: 1
            0x00, 0x00, 0x00, 0x00, // Ack: 0
            0x50, // Data offset: 5 (20 bytes)
            0x02, // Flags: SYN
            0xFF, 0xFF, // Window: 65535
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
        ];

        let header = TcpHeader::parse(&tcp_header);
        assert!(header.is_some());

        let header = header.unwrap();
        assert_eq!(header.src_port, 49320);
        assert_eq!(header.dst_port, 80);
        assert!(header.is_syn());
        assert!(!header.is_syn_ack());
    }

    #[test]
    fn test_udp_header_parse() {
        let udp_header = vec![
            0xC0, 0xA8, // Source port: 49320
            0x00, 0x35, // Dest port: 53 (DNS)
            0x00, 0x1C, // Length: 28
            0x00, 0x00, // Checksum
        ];

        let header = UdpHeader::parse(&udp_header);
        assert!(header.is_some());

        let header = header.unwrap();
        assert_eq!(header.src_port, 49320);
        assert_eq!(header.dst_port, 53);
        assert_eq!(header.length, 28);
    }

    #[test]
    fn test_dns_query_parse() {
        // Simplified DNS query for "example.com"
        let dns_query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: recursion desired
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            0x07, // "example" length
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, // "com" length
            b'c', b'o', b'm', // "com"
            0x00, // End
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];

        let query = DnsQuery::parse(&dns_query);
        assert!(query.is_some());

        let query = query.unwrap();
        assert_eq!(query.id, 0x1234);
        assert_eq!(query.domain, "example.com");
        assert_eq!(query.qtype, 1);
    }

    #[tokio::test]
    async fn test_tun_config_default() {
        let config = TunConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.interface, "dae0");
        assert_eq!(config.tun_ip, "10.0.0.1");
        assert_eq!(config.tun_netmask, "255.255.255.0");
        assert_eq!(config.mtu, 1500);
        assert_eq!(config.dns_hijack.len(), 2);
    }

    #[tokio::test]
    async fn test_dns_hijacker_cache() {
        let hijacker = new_dns_hijacker(vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)
        ]);

        // Check initial cache miss
        assert!(hijacker.lookup("example.com").await.is_none());

        // Cache an entry
        hijacker
            .cache_entry("example.com".to_string(), IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
            .await;

        // Check cache hit
        let ip = hijacker.lookup("example.com").await;
        assert!(ip.is_some());
        assert_eq!(ip.unwrap(), IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));

        // Case insensitive lookup
        let ip = hijacker.lookup("EXAMPLE.COM").await;
        assert!(ip.is_some());
    }

    #[tokio::test]
    async fn test_dns_hijacker_is_hijacked_ip() {
        let hijacker = new_dns_hijacker(vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
        ]);

        assert!(hijacker.is_hijacked_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(hijacker.is_hijacked_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))));
        assert!(!hijacker.is_hijacked_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn test_tun_packet_parsing() {
        // Build a simple IPv4 + UDP + DNS packet
        // Total: 20 (IP) + 8 (UDP) + 25 (DNS) = 53 bytes
        let packet = vec![
            0x45, // Version 4, IHL 5
            0x00, // DSCP/ECN
            0x00, 0x35, // Total length: 53
            0x00, 0x00, // ID
            0x00, 0x00, // Flags/Fragment
            0x40, // TTL: 64
            0x11, // Protocol: UDP
            0x00, 0x00, // Checksum
            0xC0, 0xA8, 0x01, 0x64, // Source: 192.168.1.100
            0x08, 0x08, 0x08, 0x08, // Dest: 8.8.8.8
            // UDP header (8 bytes)
            0xC0, 0xA8, // Source port: 49320
            0x00, 0x35, // Dest port: 53
            0x00, 0x19, // Length: 25 (DNS payload only)
            0x00, 0x00, // Checksum
            // DNS query (25 bytes total: 12 header + 8 domain + 1 null + 2 QTYPE + 2 QCLASS)
            0x12, 0x34, // ID
            0x01, 0x00, // Flags
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            0x03, // "foo" length
            b'f', b'o', b'o', // "foo"
            0x03, // "bar" length
            b'b', b'a', b'r', // "bar"
            0x00, // End
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];

        let tun_packet = TunPacket::parse(packet.clone(), PacketDirection::Outbound);
        assert!(tun_packet.is_some());

        let tun_packet = tun_packet.unwrap();
        assert_eq!(tun_packet.dst_port(), 53);
        assert!(tun_packet.is_dns());
        assert!(tun_packet.is_udp());
        assert!(!tun_packet.is_tcp());

        if let Some(ref dns) = tun_packet.dns_query {
            assert_eq!(dns.domain, "foo.bar");
            assert_eq!(dns.qtype, 1);
        } else {
            panic!("DNS query should be parsed");
        }
    }

    #[test]
    fn test_tcp_session_flags() {
        let syn_packet = vec![
            0xC0, 0xA8, // src port: 49320 (0xC0A8)
            0x00, 0x50, // dst port: 80
            0x00, 0x00, 0x00, 0x01, // seq: 1
            0x00, 0x00, 0x00, 0x00, // ack: 0
            0x50, // data offset: 5 (20 bytes header)
            0x02, // SYN flag
            0xFF, 0xFF, // window: 65535
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent pointer
        ];

        let header = TcpHeader::parse(&syn_packet).unwrap();
        assert_eq!(header.src_port, 49320);
        assert_eq!(header.dst_port, 80);
        assert!(header.is_syn());
        assert!(!header.is_syn_ack());
        assert!(!header.is_fin());
        assert!(!header.is_rst());
    }

    #[test]
    fn test_connection_key_from_raw() {
        let key = ConnectionKey::from_raw(
            u32::from_be_bytes([192, 168, 1, 100]),
            u32::from_be_bytes([8, 8, 8, 8]),
            49320,
            80,
            6,
        );

        assert_eq!(key.protocol(), crate::connection::Protocol::Tcp);

        let (src, dst) = key.to_socket_addrs().unwrap();
        assert_eq!(src.port(), 49320);
        assert_eq!(dst.port(), 80);
    }

    #[tokio::test]
    async fn test_tun_proxy_stats() {
        let rule_engine = crate::rule_engine::new_rule_engine(
            crate::rule_engine::RuleEngineConfig::default(),
        );
        let connection_pool = crate::connection_pool::new_connection_pool(
            Duration::from_secs(60),
            Duration::from_secs(30),
            Duration::from_secs(10),
        );
        let dns_hijacker = new_dns_hijacker(vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)
        ]);

        let config = TunConfig::default();
        let proxy = TunProxy::new(config, rule_engine, connection_pool, dns_hijacker);

        let stats = proxy.stats().await;
        assert_eq!(stats.active_tcp_sessions, 0);
        assert_eq!(stats.active_udp_sessions, 0);
        assert_eq!(stats.dns_cache_size, 0);
    }
}
