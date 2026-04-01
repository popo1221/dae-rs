//! dae-xdp - XDP eBPF program for dae-rs
//!
//! This program captures network packets using XDP and performs
//! initial traffic classification based on routing rules.

#![no_std]
#![deny(warnings)]

use aya_ebpf::bindings::xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS};
use aya_ebpf::macros::map;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{Array, HashMap, LpmTrie, PerCpuArray};
use aya_ebpf::programs::XdpContext;

use dae_ebpf_common::{action, ConfigEntry, RoutingEntry, SessionEntry, SessionKey, StatsEntry};

mod utils;

use utils::packet::*;

/// Global configuration map
#[map]
static CONFIG: Array<ConfigEntry> = Array::with_max_entries(1, 0);

/// Session tracking map
#[map]
static SESSIONS: HashMap<SessionKey, SessionEntry> = HashMap::with_max_entries(65536, 0);

/// Statistics map
#[map]
static STATS: PerCpuArray<StatsEntry> = PerCpuArray::with_max_entries(16, 0);

/// Routing rules map
#[map]
static ROUTING: LpmTrie<u32, RoutingEntry> = LpmTrie::with_max_entries(65536, 0);

/// XDP entry point
///
/// The #[xdp] macro generates an outer function with signature:
/// `fn xdp_prog_main(ctx: *mut xdp_md) -> u32`
/// which calls this inner function.
#[aya_ebpf::macros::xdp]
pub fn xdp_prog_main(mut ctx: XdpContext) -> u32 {
    match xdp_prog(&mut ctx) {
        Ok(ret) => ret,
        Err(_) => XDP_ABORTED,
    }
}

/// Main XDP program logic
fn xdp_prog(ctx: &mut XdpContext) -> Result<u32, ()> {
    // Parse Ethernet header
    let eth = match EthHdr::from_ctx(ctx) {
        Some(hdr) => unsafe { *hdr },
        None => {
            // Can't parse Ethernet header, pass
            return Ok(XDP_PASS);
        }
    };

    // Check if IPv4 (we only support IPv4 for now)
    if !eth.is_ipv4() {
        // Pass non-IPv4 packets
        return Ok(XDP_PASS);
    }

    // Parse IPv4 header (Ethernet header is 14 bytes)
    let ip = match IpHdr::from_ctx_after_eth(ctx, core::mem::size_of::<EthHdr>()) {
        Some(hdr) => unsafe { *hdr },
        None => {
            return Ok(XDP_PASS);
        }
    };

    // Verify this is IPv4
    if ip.version() != 4 {
        return Ok(XDP_PASS);
    }

    // Get destination IP for routing lookup
    let dst_ip = ip.dst_addr();

    // Look up routing decision
    let route = match lookup_routing(dst_ip) {
        Some(r) => r,
        None => {
            // No routing rule matched
            return Ok(XDP_PASS);
        }
    };

    // Handle based on routing action
    match route.action {
        action::PASS => Ok(XDP_PASS),
        action::REDIRECT => Ok(XDP_PASS), // For now, just pass
        action::DROP => Ok(XDP_DROP),
        _ => Ok(XDP_PASS),
    }
}

/// Look up routing entry for a destination IP using longest prefix match
fn lookup_routing(dst_ip: u32) -> Option<RoutingEntry> {
    // Try exact match first (/32)
    let key = Key::new(32, dst_ip);
    if let Some(route) = ROUTING.get(&key) {
        return Some(*route);
    }
    
    // Try decreasing prefix lengths from /24 down to /1
    let mut prefix: u32 = 24;
    while prefix > 0 {
        let key = Key::new(prefix, dst_ip);
        if let Some(route) = ROUTING.get(&key) {
            return Some(*route);
        }
        prefix -= 1;
    }
    
    // Try /0 (catch-all)
    let key = Key::new(0, 0);
    ROUTING.get(&key).map(|r| *r)
}
