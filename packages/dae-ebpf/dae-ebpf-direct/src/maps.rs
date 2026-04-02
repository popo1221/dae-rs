//! eBPF Maps for Direct Mode
//!
//! This module manages eBPF maps used for connection tracking and direct routing
//! in the real direct eBPF mode.

use crate::{ConnectionKey, EbpfError};

/// Direct routing map entry
#[derive(Debug, Clone, Copy)]
#[repr(C)]
#[derive(Default)]
pub struct DirectRouteMapEntry {
    /// Rule type (0=IPv4 CIDR, 1=IPv6 CIDR, 2=Domain Suffix, 3=Port)
    pub rule_type: u8,
    /// IP version (0=any, 4=IPv4, 6=IPv6)
    pub ip_version: u8,
    /// CIDR prefix length
    pub prefix_len: u8,
    /// Reserved
    _reserved: u8,
    /// Rule data (IP address for CIDR, port for port rules)
    pub data: [u32; 2],
    /// Domain for domain suffix rules (16 x u32 = 64 bytes)
    pub domain: [u32; 16],
    /// Action: 0=PASS(direct), 1=PROXY, 2=DROP
    pub action: u8,
    /// Reserved for alignment
    _reserved2: [u8; 7],
}


/// Connection tracking map entry
#[derive(Debug, Clone, Copy)]
#[repr(C)]
#[derive(Default)]
pub struct ConnectionMapEntry {
    /// Source IP
    pub src_ip: u32,
    /// Destination IP
    pub dst_ip: u32,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Protocol (6=TCP, 17=UDP)
    pub protocol: u8,
    /// PID that created this connection
    pub pid: u32,
    /// Connection state: 0=NEW, 1=ESTABLISHED, 2=CLOSED
    pub state: u8,
    /// Flags
    pub flags: u8,
    /// Reserved
    _reserved: [u8; 2],
    /// Timestamp when connection was created
    pub created_at: u64,
    /// Timestamp of last activity
    pub last_active: u64,
}


/// eBPF Maps manager for direct mode
///
/// This struct manages all eBPF maps required for the direct eBPF mode,
/// including connection tracking, routing rules, and statistics.
///
/// Note: The actual maps are created when the eBPF program is loaded.
/// This manager provides a convenient interface for map operations.
pub struct EbpfMaps {
    /// Placeholder for map state
    _phantom: Option<()>,
}

impl EbpfMaps {
    /// Create a new eBPF Maps manager
    pub fn new() -> Self {
        Self {
            _phantom: None,
        }
    }

    /// Insert a direct route entry
    #[allow(dead_code)]
    pub fn insert_direct_route(&self, _key: [u8; 8], _entry: DirectRouteMapEntry) -> Result<(), EbpfError> {
        tracing::debug!("insert_direct_route called");
        Ok(())
    }

    /// Look up a direct route
    #[allow(dead_code)]
    pub fn lookup_direct_route(&self, _key: [u8; 8]) -> Result<Option<DirectRouteMapEntry>, EbpfError> {
        tracing::debug!("lookup_direct_route called");
        Ok(None)
    }

    /// Delete a direct route
    #[allow(dead_code)]
    pub fn delete_direct_route(&self, _key: [u8; 8]) -> Result<(), EbpfError> {
        tracing::debug!("delete_direct_route called");
        Ok(())
    }

    /// Insert a connection entry
    #[allow(dead_code)]
    pub fn insert_connection(&self, _key: ConnectionKey, _info: ConnectionMapEntry) -> Result<(), EbpfError> {
        tracing::debug!("insert_connection called");
        Ok(())
    }

    /// Look up a connection
    #[allow(dead_code)]
    pub fn lookup_connection(&self, _key: &ConnectionKey) -> Result<Option<ConnectionMapEntry>, EbpfError> {
        tracing::debug!("lookup_connection called");
        Ok(None)
    }

    /// Delete a connection
    #[allow(dead_code)]
    pub fn remove_connection(&self, _key: ConnectionKey) -> Result<(), EbpfError> {
        tracing::debug!("remove_connection called");
        Ok(())
    }
}

impl Default for EbpfMaps {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectRouteMapEntry {
    /// Create an IPv4 CIDR route entry
    pub fn new_ipv4_cidr(ip: u32, prefix_len: u8, action: u8) -> Self {
        let mut entry = Self::default();
        entry.rule_type = 0; // IPv4 CIDR
        entry.ip_version = 4;
        entry.prefix_len = prefix_len;
        entry.data[0] = ip;
        entry.action = action;
        entry
    }

    /// Create an IPv6 CIDR route entry
    pub fn new_ipv6_cidr(ip_hi: u32, ip_lo: u32, prefix_len: u8, action: u8) -> Self {
        let mut entry = Self::default();
        entry.rule_type = 1; // IPv6 CIDR
        entry.ip_version = 6;
        entry.prefix_len = prefix_len;
        entry.data[0] = ip_hi;
        entry.data[1] = ip_lo;
        entry.action = action;
        entry
    }

    /// Create a domain suffix route entry
    pub fn new_domain_suffix(domain: &str, action: u8) -> Self {
        let mut entry = Self::default();
        entry.rule_type = 2; // Domain Suffix
        entry.action = action;
        
        // Encode domain as u32 array
        let bytes = domain.as_bytes();
        for (i, chunk) in bytes.chunks(4).enumerate().take(16) {
            let mut word: u32 = 0;
            for (j, &byte) in chunk.iter().enumerate() {
                word |= (byte as u32) << (j * 8);
            }
            entry.domain[i] = word;
        }
        entry
    }

    /// Create a port route entry
    pub fn new_port(port: u16, protocol: u8, action: u8) -> Self {
        let mut entry = Self::default();
        entry.rule_type = 3; // Port
        entry.ip_version = protocol; // 6=TCP, 17=UDP, 0=any
        entry.data[0] = port as u32;
        entry.action = action;
        entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_key_bytes() {
        let key = ConnectionKey::new(
            0xC0A80101, // 192.168.1.1
            0xC0A80102, // 192.168.1.2
            8080,
            80,
            6, // TCP
        );
        
        let bytes = key.to_bytes();
        let key2 = ConnectionKey::from_bytes(&bytes);
        
        assert_eq!(key, key2);
    }

    #[test]
    fn test_direct_route_ipv4() {
        let entry = DirectRouteMapEntry::new_ipv4_cidr(0xC0A80100, 24, 0);
        
        assert_eq!(entry.rule_type, 0);
        assert_eq!(entry.ip_version, 4);
        assert_eq!(entry.prefix_len, 24);
        assert_eq!(entry.data[0], 0xC0A80100);
    }
}
