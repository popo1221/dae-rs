//! eBPF Maps for TC program
//!
//! Defines the maps used for session tracking, routing, DNS mapping, and statistics.

use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, LpmTrie, PerCpuArray};

use dae_ebpf_common::{
    ConfigEntry, DnsMapEntry, RoutingEntry, SessionEntry, SessionKey, StatsEntry,
};

/// Global configuration map
#[map]
pub static CONFIG: Array<ConfigEntry> = Array::with_max_entries(1, 0);

/// Session tracking map (5-tuple to session state)
#[map]
pub static SESSIONS: HashMap<SessionKey, SessionEntry> = HashMap::with_max_entries(65536, 0);

/// Statistics map (per-CPU counters)
#[map]
pub static STATS: PerCpuArray<StatsEntry> = PerCpuArray::with_max_entries(16, 0);

/// Routing rules map (LPM trie for CIDR matching)
#[map]
pub static ROUTING: LpmTrie<u32, RoutingEntry> = LpmTrie::with_max_entries(65536, 0);

/// DNS mapping map (domain name hash to DNS mapping entry)
#[map]
pub static DNS_MAP: HashMap<u64, DnsMapEntry> = HashMap::with_max_entries(65536, 0);

/// IP to domain mapping (reverse lookup for blocked domains)
#[map]
pub static IP_DOMAIN_MAP: HashMap<u32, u64> = HashMap::with_max_entries(65536, 0);

/// Default routing entry (catch-all)
pub const DEFAULT_ROUTE_KEY: u32 = 0;

/// Statistics indices
pub mod idx {
    /// Overall statistics
    pub const OVERALL: u32 = 0;
    /// TCP statistics
    pub const TCP: u32 = 1;
    /// UDP statistics
    pub const UDP: u32 = 2;
    /// ICMP statistics
    pub const ICMP: u32 = 3;
    /// Other protocol statistics
    pub const OTHER: u32 = 4;
}

/// Create a DNS map key from domain name
/// Uses a simple hash of the domain name
pub fn dns_key(domain: &[u8]) -> u64 {
    let mut key: u64 = 0;
    for (i, &b) in domain.iter().enumerate().take(8) {
        key = key.wrapping_add((b as u64).wrapping_mul((i as u64).wrapping_add(1)));
    }
    key
}
