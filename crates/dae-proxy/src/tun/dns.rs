//! DNS 劫持模块

use crate::tun::packet::DnsQuery;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, error, warn};

/// DNS 劫持条目 - 将查询的 IP 映射到域名，用于规则匹配
///
/// 缓存 DNS 劫持的结果，将域名与返回的 IP 关联起来。
#[derive(Debug, Clone)]
pub struct DnsHijackEntry {
    /// The IP address that was returned in the DNS response
    pub queried_ip: IpAddr,
    /// The domain name that was queried
    pub domain: String,
    /// When this entry was created
    pub timestamp: Instant,
}

impl DnsHijackEntry {
    /// Check if entry is expired (5 minutes TTL)
    pub fn is_expired(&self) -> bool {
        self.timestamp.elapsed() > Duration::from_secs(300)
    }
}

/// DNS 劫持器 - 拦截和处理 DNS 查询
///
/// 拦截 DNS 查询并返回伪造的响应，实现基于域名的流量路由。
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
        self.upstream_servers.iter().any(|server| server.ip() == ip)
    }

    /// Cache a DNS hijack entry
    pub async fn cache_entry(&self, domain: String, ip: IpAddr) {
        let entry = DnsHijackEntry {
            queried_ip: ip,
            domain: domain.clone(),
            timestamp: Instant::now(),
        };
        let mut cache = self.cache.write().await;
        cache.insert(domain.to_lowercase(), entry);
    }

    /// Get the number of cached entries
    pub async fn cache_size(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
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
        _src_ip: IpAddr,
        _src_port: u16,
    ) -> Option<Vec<u8>> {
        // Check cache first
        if let Some(cached_ip) = self.lookup(&query.domain).await {
            debug!("DNS cache hit for {} -> {}", query.domain, cached_ip);
            return Some(self.build_response(query, cached_ip));
        }

        // Forward to upstream
        debug!("DNS forwarding query for {} to upstream", query.domain);
        self.forward_query(query).await
    }

    /// Forward DNS query to upstream and cache result
    async fn forward_query(&self, query: &DnsQuery) -> Option<Vec<u8>> {
        if self.upstream_servers.is_empty() {
            warn!("No upstream DNS servers configured");
            return None;
        }

        let upstream = self.upstream_servers[0];
        let socket =
            match UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await {
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
        let _pos = 12;
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
