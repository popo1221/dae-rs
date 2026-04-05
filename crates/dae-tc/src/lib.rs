//! dae-tc - TC eBPF program for dae-rs transparent proxy
//!
//! This program captures network packets using tc (traffic control) clsact
//! qdisc and performs traffic classification and redirection for
//! transparent proxy support.
//!
//! # Architecture
//!
//! ```text
//! Network Packet
//!      |
//!      v
//! +-----------------+
//! |  clsact qdisc   | (Kernel TC layer)
//! +-----------------+
//!      |
//!      v
//! +-----------------+
//! |  dae-tc eBPF    | (This program)
//! |  tc_prog_main   |
//! +-----------------+
//!      |
//!      +---> Parse Ethernet header
//!      +---> Parse IPv4 header
//!      +---> Parse TCP/UDP header
//!      +---> Lookup session (SESSIONS map)
//!      +---> Lookup routing (ROUTING map - LPM)
//!      +---> Apply action (PASS/REDIRECT/DROP)
//! ```
//!
//! # Key Features
//!
//! - Attaches to tc clsact qdisc on the specified interface
//! - Parses Ethernet, IPv4, TCP, and UDP headers
//! - Supports VLAN tagging (802.1Q)
//! - Performs longest-prefix-match (LPM) routing lookups
//! - Tracks connection state for stateful proxying
//! - Supports PASS, REDIRECT, and DROP routing actions
//!
//! # Maps
//!
//! - `SESSIONS`: HashMap<SessionKey, SessionEntry> - Connection tracking
//! - `ROUTING`: LpmTrie<u32, RoutingEntry> - CIDR routing rules
//! - `DNS_MAP`: HashMap<u64, DnsMapEntry> - Domain name mapping
//! - `CONFIG`: Array<ConfigEntry> - Global configuration
//! - `STATS`: PerCpuArray<StatsEntry> - Statistics counters
//!
//! # Usage
//!
//! This eBPF program is loaded by the user-space loader (dae-ebpf) using
//! the TC program type. The loader will:
//! 1. Setup clsact qdisc on the target interface
//! 2. Load this eBPF program into the kernel
//! 3. Attach it as an ingress filter

#![no_std]
#![allow(unused)]
// Allow strict clippy lints for eBPF code patterns
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::needless_range_loop)]

use aya_ebpf::bindings::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::map;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{Array, HashMap, LpmTrie, PerCpuArray};
use aya_ebpf::programs::TcContext;

use dae_ebpf_common::{
    action, state, ConfigEntry, DnsMapEntry, RoutingEntry, SessionEntry, SessionKey, StatsEntry,
};

mod maps;
mod packet;

use maps::idx;
use packet::*;

/// Global configuration map
#[map]
static CONFIG: Array<ConfigEntry> = Array::with_max_entries(1, 0);

/// Session tracking map (5-tuple to session state)
#[map]
static SESSIONS: HashMap<SessionKey, SessionEntry> = HashMap::with_max_entries(65536, 0);

/// Routing rules map (LPM trie for CIDR matching)
#[map]
static ROUTING: LpmTrie<u32, RoutingEntry> = LpmTrie::with_max_entries(65536, 0);

/// DNS mapping map (domain name hash to DNS mapping entry)
#[map]
static DNS_MAP: HashMap<u64, DnsMapEntry> = HashMap::with_max_entries(65536, 0);

/// IP to domain mapping (reverse lookup for blocked domains)
#[map]
static IP_DOMAIN_MAP: HashMap<u32, u64> = HashMap::with_max_entries(65536, 0);

/// Statistics map (per-CPU counters)
#[map]
static STATS: PerCpuArray<StatsEntry> = PerCpuArray::with_max_entries(16, 0);

/// TC program entry point
///
/// This function is called for each packet entering the interface via the
/// clsact qdisc. The kernel passes a raw sk_buff pointer, which we wrap
/// in a TcContext for easier access.
///
/// # Arguments
///
/// * `ctx` - Raw pointer to __sk_buff from the kernel
///
/// # Returns
///
/// * `TC_ACT_OK` (1) - Continue processing the packet normally
/// * `TC_ACT_SHOT` (2) - Drop the packet
#[no_mangle]
#[link_section = "classifier"]
pub extern "C" fn tc_prog_main(ctx: *mut __sk_buff) -> i32 {
    let mut tc_ctx = TcContext::new(ctx);
    match tc_prog(&mut tc_ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

/// Main TC program logic
fn tc_prog(ctx: &mut TcContext) -> Result<i32, ()> {
    // Parse Ethernet header
    let eth = match EthHdr::from_ctx(ctx) {
        // SAFETY: EthHdr::from_ctx returns Some only when valid ethernet header exists in packet buffer
        Some(hdr) => unsafe { *hdr },
        None => {
            // Can't parse Ethernet header, pass
            return Ok(TC_ACT_OK);
        }
    };

    // Get source MAC address for potential LAN classification
    let src_mac = eth.src_mac();

    // Handle VLAN tagging
    let (ip_offset, is_ipv4) = if eth.has_vlan() {
        // VLAN tag present - need to look at the VLAN header to get actual EtherType
        let vlan = match VlanHdr::from_ctx_after_eth(ctx, core::mem::size_of::<EthHdr>()) {
            // SAFETY: VlanHdr::from_ctx_after_eth returns Some when VLAN tag is present and valid
            Some(hdr) => unsafe { *hdr },
            None => {
                return Ok(TC_ACT_OK);
            }
        };
        let actual_ethertype = vlan.tpid;
        (
            core::mem::size_of::<EthHdr>() + core::mem::size_of::<VlanHdr>(),
            actual_ethertype == ethertype::IPV4,
        )
    } else {
        (core::mem::size_of::<EthHdr>(), eth.is_ipv4())
    };

    // Check if IPv4
    if !is_ipv4 {
        return Ok(TC_ACT_OK);
    }

    // Parse IPv4 header
    let ip = match IpHdr::from_ctx_after_eth(ctx, ip_offset) {
        // SAFETY: IpHdr::from_ctx_after_eth returns Some when IPv4 header is present and valid
        Some(hdr) => unsafe { *hdr },
        None => {
            return Ok(TC_ACT_OK);
        }
    };

    // Verify IPv4
    if ip.version() != 4 {
        return Ok(TC_ACT_OK);
    }

    let src_ip = ip.src_addr();
    let dst_ip = ip.dst_addr();
    let ip_proto = ip.protocol();
    let ip_hdr_len = ip.header_len();

    // Extract ports for TCP/UDP
    let (src_port, dst_port) = match ip_proto {
        ip_proto::TCP => {
            let tcp = match TcpHdr::from_ctx_after_ip(ctx, ip_offset, ip_hdr_len) {
                // SAFETY: TcpHdr::from_ctx_after_ip returns Some when TCP header is present and valid
                Some(hdr) => unsafe { *hdr },
                None => return Ok(TC_ACT_OK),
            };
            (tcp.src_port(), tcp.dst_port())
        }
        ip_proto::UDP => {
            let udp = match UdpHdr::from_ctx_after_ip(ctx, ip_offset, ip_hdr_len) {
                // SAFETY: UdpHdr::from_ctx_after_ip returns Some when UDP header is present and valid
                Some(hdr) => unsafe { *hdr },
                None => return Ok(TC_ACT_OK),
            };
            (udp.src_port(), udp.dst_port())
        }
        _ => (0, 0),
    };

    // Create session key (5-tuple)
    let session_key = SessionKey::new(src_ip, dst_ip, src_port, dst_port, ip_proto);

    // Get current timestamp
    // SAFETY: bpf_ktime_get_ns is a BPF helper that always returns a valid timestamp
    let now = unsafe { bpf_ktime_get_ns() };

    // Look up or create session
    // SAFETY: SESSIONS map access is safe - we provide a valid key and handle the Option returned
    let session = match unsafe { SESSIONS.get(&session_key) } {
        Some(entry) => {
            // Update existing session
            let mut updated = *entry;
            updated.packets += 1;
            updated.last_time = now;
            updated
        }
        None => {
            // Create new session
            let mut session = SessionEntry::default();
            session.state = state::NEW;
            session.packets = 1;
            session.start_time = now;
            session.last_time = now;
            session.src_mac_len = 6;
            session.src_mac = src_mac;
            session
        }
    };

    // Store/update session
    let _ = SESSIONS.insert(&session_key, &session, 0);

    // Look up routing decision for destination using LPM
    let route = match lookup_routing(dst_ip) {
        Some(r) => r,
        None => {
            // No routing rule matched, pass
            return Ok(TC_ACT_OK);
        }
    };

    // Update session with routing decision
    let mut updated_session = session;
    updated_session.route_id = route.route_id;
    let _ = SESSIONS.insert(&session_key, &updated_session, 0);

    // Update statistics using per-CPU array
    // Note: PerCpuArray values are updated in place via get_ptr_mut
    let stats_idx = match ip_proto {
        ip_proto::TCP => idx::TCP,
        ip_proto::UDP => idx::UDP,
        _ => idx::OTHER,
    };
    if let Some(stats_ptr) = unsafe { STATS.get_ptr_mut(stats_idx) } {
        // SAFETY: stats_ptr is guaranteed to be valid since we got it from the map
        let stats = unsafe { &mut *stats_ptr };
        stats.packets += 1;
        stats.bytes += ip.tot_len() as u64;
    }

    // Handle based on routing action
    match route.action {
        action::PASS => {
            // Packet passes through unchanged
            Ok(TC_ACT_OK)
        }
        action::REDIRECT => {
            // Mark packet for redirection to proxy
            // We set the skb mark which can be read by userspace
            ctx.set_mark(route.route_id);
            Ok(TC_ACT_OK)
        }
        action::DROP => {
            // Drop the packet
            Ok(TC_ACT_SHOT)
        }
        _ => Ok(TC_ACT_OK),
    }
}

/// Look up routing entry for a destination IP using longest prefix match
///
/// Uses the eBPF LpmTrie map which automatically performs longest prefix
/// matching. For compatibility with older kernels, we also try decreasing
/// prefix lengths.
fn lookup_routing(dst_ip: u32) -> Option<RoutingEntry> {
    // First try exact match with /32
    let key = Key::new(32, dst_ip);
    if let Some(route) = ROUTING.get(&key) {
        return Some(*route);
    }

    // Fallback: try decreasing prefix lengths from /24 down to /1
    // This provides compatibility with kernels that may have issues
    // with the exact /32 lookup
    let mut prefix: u32 = 24;
    while prefix > 0 {
        let key = Key::new(prefix, dst_ip);
        if let Some(route) = ROUTING.get(&key) {
            return Some(*route);
        }
        prefix -= 1;
    }

    // Try /0 (catch-all default route)
    let key = Key::new(0, 0);
    ROUTING.get(&key).copied()
}
