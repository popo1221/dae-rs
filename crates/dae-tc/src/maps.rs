//! eBPF Maps for TC program
//!
//! Defines the maps used for session tracking, routing, DNS mapping, and statistics.
//!
//! # Map Types
//!
//! | Map Name     | Type        | Key               | Value          | Purpose                    |
//! |--------------|-------------|-------------------|----------------|----------------------------|
//! | SESSIONS     | HashMap     | SessionKey        | SessionEntry   | Connection tracking        |
//! | ROUTING      | LpmTrie     | u32 (IP prefix)   | RoutingEntry   | CIDR routing rules         |
//! | DNS_MAP      | HashMap     | u64 (domain hash) | DnsMapEntry    | Domain name mapping        |
//! | IP_DOMAIN_MAP| HashMap     | u32 (IP)          | u64 (domain)   | Reverse DNS lookup         |
//! | CONFIG       | Array       | u32 (index)       | ConfigEntry    | Global configuration       |
//! | STATS        | PerCpuArray | u32 (index)       | StatsEntry     | Statistics counters        |
//!
//! # Note on LpmTrie
//!
//! The LpmTrie (Longest Prefix Match Trie) is used for ROUTING to support
//! CIDR notation (e.g., 192.168.0.0/24). The key is a tuple of (prefix_length, IP).
//! When looking up, the kernel automatically finds the longest matching prefix.

/// Re-export statistics indices from dae-ebpf-common
pub use dae_ebpf_common::stats::idx;

/// Default routing entry key (catch-all, prefix length 0)
pub const DEFAULT_ROUTE_KEY: u32 = 0;

/// Create a DNS map key from domain name
///
/// Uses DJB2 hash algorithm to generate a consistent hash key
/// for domain name lookups.
///
/// # Arguments
///
/// * `domain` - Domain name as bytes (e.g., b"example.com")
///
/// # Returns
///
/// A 64-bit hash key
pub fn dns_key(domain: &[u8]) -> u64 {
    let mut key: u64 = 5381;
    for &b in domain {
        // DJB2 hash algorithm
        key = key.wrapping_mul(33).wrapping_add(b as u64);
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_key() {
        let key1 = dns_key(b"example.com");
        let key2 = dns_key(b"example.com");
        assert_eq!(key1, key2);

        let key3 = dns_key(b"google.com");
        assert_ne!(key1, key3);
    }
}
