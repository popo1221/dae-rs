//! Direct routing rules for eBPF-based traffic bypass
//!
//! This module defines structures for specifying traffic that should bypass
//! the proxy and be sent directly. Rules are checked in eBPF for zero-cost
//! traffic classification.

/// Direct route entry stored in eBPF map
///
/// The entry describes a single direct routing rule with its type
/// and the actual rule data (IP prefix, domain suffix, or port).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct DirectRouteEntry {
    /// Rule type (DIRECT_RULE_* constants)
    pub rule_type: u8,
    /// IP protocol version (0 = any, 4 = IPv4, 6 = IPv6)
    /// Used for PORT rules to specify TCP/UDP vs. specific IP type
    pub ip_version: u8,
    /// CIDR prefix length (0-32 for IPv4, 0-128 for IPv6)
    /// Used for IP_CIDR rules
    pub prefix_len: u8,
    /// Reserved for alignment
    reserved: u8,
    /// Rule data (network byte order for IPs, port number for PORT rules)
    /// For IPv4 CIDR: dst_ip (upper bits used based on prefix_len)
    /// For IPv6 CIDR: dst_ip_hi (upper 64 bits)
    pub data: [u32; 2],
    /// Domain suffix for DOMAIN_SUFFIX rules (null-terminated, up to 64 bytes)
    /// Stored as 16 x u32 to ensure alignment and size
    pub domain: [u32; 16],
}

/// Direct route rule types
pub mod rule_type {
    /// IPv4 CIDR rule (matches by destination IP prefix)
    pub const DIRECT_RULE_IPV4_CIDR: u8 = 1;
    /// IPv6 CIDR rule (matches by destination IP prefix)
    pub const DIRECT_RULE_IPV6_CIDR: u8 = 2;
    /// Domain suffix rule (matches by domain suffix)
    pub const DIRECT_RULE_DOMAIN_SUFFIX: u8 = 3;
    /// Port rule (matches by destination port and optionally protocol)
    pub const DIRECT_RULE_PORT: u8 = 4;
    /// Process name rule (matches by process name - requires user-space)
    pub const DIRECT_RULE_PROCESS: u8 = 5;
}

impl DirectRouteEntry {
    /// Create a new IPv4 CIDR direct route entry
    pub fn new_ipv4_cidr(dst_ip: u32, prefix_len: u8) -> Self {
        let mut entry = Self::default();
        entry.rule_type = rule_type::DIRECT_RULE_IPV4_CIDR;
        entry.prefix_len = prefix_len;
        entry.data[0] = dst_ip;
        entry
    }

    /// Create a new IPv6 CIDR direct route entry
    pub fn new_ipv6_cidr(dst_ip_hi: u32, dst_ip_lo: u32, prefix_len: u8) -> Self {
        let mut entry = Self::default();
        entry.rule_type = rule_type::DIRECT_RULE_IPV6_CIDR;
        entry.prefix_len = prefix_len;
        entry.ip_version = 6;
        entry.data[0] = dst_ip_hi;
        entry.data[1] = dst_ip_lo;
        entry
    }

    /// Create a new domain suffix direct route entry
    pub fn new_domain_suffix(domain: &str) -> Self {
        let mut entry = Self::default();
        entry.rule_type = rule_type::DIRECT_RULE_DOMAIN_SUFFIX;
        
        // Encode domain as u32 array (null-terminated, max 63 chars + null)
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

    /// Create a new port direct route entry
    pub fn new_port(port: u16, is_tcp: bool, is_udp: bool) -> Self {
        let mut entry = Self::default();
        entry.rule_type = rule_type::DIRECT_RULE_PORT;
        // ip_version field used to encode protocol: bit 0 = TCP, bit 1 = UDP
        // 0 = any protocol
        if is_tcp {
            entry.ip_version |= 1;
        }
        if is_udp {
            entry.ip_version |= 2;
        }
        // Store port in data[0] lower 16 bits
        entry.data[0] = port as u32;
        entry
    }

    /// Check if an IPv4 address matches this entry
    pub fn matches_ipv4(&self, ip: u32) -> bool {
        if self.rule_type != rule_type::DIRECT_RULE_IPV4_CIDR {
            return false;
        }
        
        let mask = if self.prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - self.prefix_len)
        };
        (ip & mask) == (self.data[0] & mask)
    }

    /// Check if a domain matches this entry (suffix match)
    pub fn matches_domain(&self, domain: &str) -> bool {
        if self.rule_type != rule_type::DIRECT_RULE_DOMAIN_SUFFIX {
            return false;
        }
        
        // Extract null-terminated domain string from the array
        let mut stored_len = 0;
        for &word in &self.domain {
            let mut w = word;
            let mut found_null = false;
            for _ in 0..4 {
                if w == 0 {
                    found_null = true;
                    break;
                }
                stored_len += 1;
                w >>= 8;
                if stored_len >= 63 {
                    break;
                }
            }
            if found_null || stored_len >= 63 {
                break;
            }
        }
        
        if stored_len == 0 {
            return false;
        }
        
        // Compare domain suffix (simplified - just check if domain ends with stored suffix)
        if domain.len() < stored_len {
            return false;
        }
        
        // Extract stored suffix bytes
        let mut stored_bytes = [0u8; 64];
        for (i, &word) in self.domain.iter().enumerate() {
            stored_bytes[i * 4] = (word & 0xFF) as u8;
            if i * 4 + 1 >= stored_len { break; }
            stored_bytes[i * 4 + 1] = ((word >> 8) & 0xFF) as u8;
            if i * 4 + 2 >= stored_len { break; }
            stored_bytes[i * 4 + 2] = ((word >> 16) & 0xFF) as u8;
            if i * 4 + 3 >= stored_len { break; }
            stored_bytes[i * 4 + 3] = ((word >> 24) & 0xFF) as u8;
        }
        
        // Compare using byte-by-byte comparison (no Cow needed)
        let domain_lower = domain.as_bytes();
        let stored = &stored_bytes[..stored_len];
        
        // Check if domain ends with stored suffix
        if domain_lower.len() > stored.len() {
            // Check if there's a '.' before the suffix match
            let offset = domain_lower.len() - stored.len();
            if domain_lower[offset..] == stored[..] {
                return true;
            }
            // Also check with leading dot
            if offset > 0 && domain_lower[offset - 1] == b'.' && domain_lower[offset..] == stored[..] {
                return true;
            }
        } else if domain_lower == stored {
            return true;
        }
        
        false
    }

    /// Check if a port matches this entry
    pub fn matches_port(&self, port: u16, proto: u8) -> bool {
        if self.rule_type != rule_type::DIRECT_RULE_PORT {
            return false;
        }
        
        // Check protocol match
        let proto_bit = match proto {
            6 => 0b001, // TCP
            17 => 0b010, // UDP
            _ => 0,
        };
        if (self.ip_version & proto_bit) == 0 && self.ip_version != 0 {
            return false;
        }
        
        // Check port match
        self.data[0] as u16 == port
    }
}

/// Process rule entry for eBPF map
///
/// This entry stores a process name-based routing rule that can be
/// checked in user-space to determine if traffic should bypass the proxy.
/// The key is a hash of the process name, and the value contains
/// the routing action and the actual process name for verification.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct ProcessRuleEntry {
    /// Routing action: 0=PASS(direct), 1=PROXY, 2=DROP
    pub action: u8,
    /// Match type: 0=exact, 1=prefix, 2=contains
    pub match_type: u8,
    /// Process name length (up to 15, TASK_COMM_LEN)
    pub process_len: u8,
    /// Reserved for alignment
    reserved: u8,
    /// Process name (null-terminated, up to 15 chars + null)
    /// TASK_COMM_LEN = 16 bytes
    pub process_name: [u8; 16],
}

/// Process rule action constants
pub mod process_action {
    /// Pass/direct the connection
    pub const PROCESS_ACTION_DIRECT: u8 = 0;
    /// Proxy the connection
    pub const PROCESS_ACTION_PROXY: u8 = 1;
    /// Drop the connection
    pub const PROCESS_ACTION_DROP: u8 = 2;
}

/// Process rule match type constants
pub mod process_match {
    /// Exact match
    pub const MATCH_EXACT: u8 = 0;
    /// Prefix match
    pub const MATCH_PREFIX: u8 = 1;
    /// Contains match
    pub const MATCH_CONTAINS: u8 = 2;
}

impl ProcessRuleEntry {
    /// Create a new process rule entry with exact match
    pub fn new_exact(action: u8, process_name: &str) -> Self {
        Self::new(action, process_name, 0)
    }

    /// Create a new process rule entry with prefix match
    pub fn new_prefix(action: u8, process_name: &str) -> Self {
        Self::new(action, process_name, 1)
    }

    /// Create a new process rule entry with contains match
    pub fn new_contains(action: u8, process_name: &str) -> Self {
        Self::new(action, process_name, 2)
    }

    /// Create a new process rule entry
    fn new(action: u8, process_name: &str, match_type: u8) -> Self {
        let mut entry = Self::default();
        entry.action = action;
        entry.match_type = match_type;

        // Copy process name, max 15 chars (TASK_COMM_LEN - 1)
        let bytes = process_name.as_bytes();
        let len = bytes.len().min(15);
        entry.process_len = len as u8;

        for i in 0..len {
            let byte = bytes[i];
            // Convert to lowercase ASCII if in range
            entry.process_name[i] = if byte.is_ascii_uppercase() {
                byte + 32
            } else {
                byte
            };
        }
        // Null-terminate
        if len < 15 {
            entry.process_name[len] = 0;
        }

        entry
    }

    /// Check if this entry matches the given process name
    pub fn matches(&self, process_name: &str) -> bool {
        let name_lower = process_name.as_bytes();
        let entry_name = match self.get_process_name() {
            Some(name) => name.as_bytes(),
            None => return false,
        };

        match self.match_type {
            0 => name_lower == entry_name, // exact
            1 => name_lower.starts_with(entry_name) || entry_name.starts_with(name_lower), // prefix (bidirectional)
            2 => contains(name_lower, entry_name), // contains
            _ => false,
        }
    }

    /// Get the stored process name as a string slice
    /// Returns None if the name cannot be decoded as UTF-8
    pub fn get_process_name(&self) -> Option<&'_ str> {
        let len = if self.process_len == 0 {
            return None;
        } else {
            self.process_len as usize
        };

        let bytes = &self.process_name[..len.min(16)];
        // Find null terminator
        let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let trimmed = &bytes[..null_pos];
        
        core::str::from_utf8(trimmed).ok()
    }
}

/// Check if haystack contains needle (simplified no_std version)
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
    }
    false
}

/// Process info entry for connection tracking
///
/// This stores process information associated with a connection.
/// It is used to track which process initiated a network connection
/// for traffic classification purposes.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct ProcessInfoEntry {
    /// Process ID
    pub pid: u32,
    /// Process name length
    pub name_len: u8,
    /// Reserved for alignment
    reserved: [u8; 3],
    /// Process name (up to 15 chars + null)
    pub name: [u8; 16],
}

impl ProcessInfoEntry {
    /// Create a new process info entry
    pub fn new(pid: u32, name: &str) -> Self {
        let mut entry = Self::default();
        entry.pid = pid;

        let bytes = name.as_bytes();
        let len = bytes.len().min(15);
        entry.name_len = len as u8;

        for i in 0..len {
            entry.name[i] = bytes[i];
        }

        entry
    }

    /// Get the process name
    /// Returns None if the name cannot be decoded as UTF-8
    pub fn get_name(&self) -> Option<&'_ str> {
        let len = if self.name_len == 0 { 0 } else { self.name_len as usize };
        let bytes = &self.name[..len.min(16)];
        
        // Find null terminator
        let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let trimmed = &bytes[..null_pos];
        
        core::str::from_utf8(trimmed).ok()
    }

    /// Get the process ID
    pub fn get_pid(&self) -> u32 {
        self.pid
    }
}
