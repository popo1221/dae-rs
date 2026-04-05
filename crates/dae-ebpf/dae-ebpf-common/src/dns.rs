//! DNS mapping entry for domain-based routing
//!
//! Provides domain name to IP address mapping for routing decisions.

/// Maximum domain name length (255 bytes minus null terminator)
pub const MAX_DOMAIN_LEN: usize = 254;

/// DNS mapping entry for domain-based routing
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct DnsMapEntry {
    /// Resolved IPv4 address (network byte order, 0 if not set)
    pub ip: u32,
    /// Expiration timestamp (jiffies, 0 = never expires)
    pub expire_time: u64,
    /// Domain name length
    pub domain_len: u8,
    /// Domain name (null-terminated string, up to 254 bytes)
    pub domain: [u8; MAX_DOMAIN_LEN],
}

impl Default for DnsMapEntry {
    fn default() -> Self {
        Self {
            ip: 0,
            expire_time: 0,
            domain_len: 0,
            domain: [0u8; MAX_DOMAIN_LEN],
        }
    }
}

impl DnsMapEntry {
    /// Create a new DNS mapping entry
    pub fn new(domain: &[u8], ip: u32, expire_time: u64) -> Option<Self> {
        if domain.is_empty() || domain.len() > MAX_DOMAIN_LEN {
            return None;
        }

        let mut entry = Self::default();
        entry.ip = ip;
        entry.expire_time = expire_time;
        entry.domain_len = domain.len() as u8;
        entry.domain[..domain.len()].copy_from_slice(domain);
        entry.domain[domain.len()] = 0; // Null terminator

        Some(entry)
    }

    /// Check if the entry has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        if self.expire_time == 0 {
            return false; // Never expires
        }
        self.expire_time < current_time
    }

    /// Get the domain name as a byte slice
    pub fn domain_name(&self) -> &[u8] {
        &self.domain[..self.domain_len as usize]
    }
}

/// DNS query types
pub mod dns_type {
    /// A record (IPv4 address)
    pub const A: u16 = 1;
    /// AAAA record (IPv6 address)
    pub const AAAA: u16 = 28;
    /// CNAME record
    pub const CNAME: u16 = 5;
    /// TXT record
    pub const TXT: u16 = 16;
}
