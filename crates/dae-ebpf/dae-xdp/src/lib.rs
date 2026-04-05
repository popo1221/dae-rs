//! dae-xdp - XDP eBPF program for dae-rs
//!
//! This program captures network packets using XDP and performs
//! initial traffic classification based on routing rules.

#![no_std]
#![deny(warnings)]
// Allow strict clippy lints for eBPF code patterns
#![allow(clippy::field_reassign_with_default)]

use aya_ebpf::bindings::xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS};
use aya_ebpf::macros::map;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{Array, HashMap, LpmTrie, PerCpuArray};
use aya_ebpf::programs::XdpContext;

use dae_ebpf_common::{
    action, state, ConfigEntry, RoutingEntry, SessionEntry, SessionKey, StatsEntry,
};

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
        // SAFETY: EthHdr::from_ctx returns None if bounds check fails,
        // otherwise returns a valid pointer that can be safely dereferenced.
        Some(hdr) => unsafe { *hdr },
        None => {
            // Can't parse Ethernet header, pass
            return Ok(XDP_PASS);
        }
    };

    // Extract source MAC address for LAN traffic classification
    let src_mac = eth.src_mac();

    // Handle MACv2 extension (VLAN tagging)
    // When VLAN tag is present (EtherType = 0x8100), the actual protocol
    // type is after the 4-byte VLAN tag, and IP header starts at offset 18
    let (ip_offset, is_ipv4) = if eth.has_vlan() {
        // VLAN tag present, check inner EtherType
        let vlan = match VlanHdr::from_ctx_after_eth(ctx, core::mem::size_of::<EthHdr>()) {
            // SAFETY: VlanHdr::from_ctx_after_eth returns None if bounds check fails,
            // otherwise returns a valid pointer that can be safely dereferenced.
            Some(hdr) => unsafe { *hdr },
            None => {
                return Ok(XDP_PASS);
            }
        };
        let inner_ethertype = vlan.inner_ether_type();
        // Inner EtherType is in lower 16 bits of TCI
        let actual_ethertype = inner_ethertype;
        // After EthHdr (14 bytes) + VlanHdr (4 bytes) = 18 bytes
        (
            core::mem::size_of::<EthHdr>() + core::mem::size_of::<VlanHdr>(),
            actual_ethertype == ethertype::IPV4,
        )
    } else {
        // No VLAN tag
        (core::mem::size_of::<EthHdr>(), eth.is_ipv4())
    };

    // Check if IPv4 (we only support IPv4 for now)
    if !is_ipv4 {
        // Pass non-IPv4 packets
        return Ok(XDP_PASS);
    }

    // Parse IPv4 header
    let ip = match IpHdr::from_ctx_after_eth(ctx, ip_offset) {
        // SAFETY: IpHdr::from_ctx_after_eth returns None if bounds check fails,
        // otherwise returns a valid pointer that can be safely dereferenced.
        Some(hdr) => unsafe { *hdr },
        None => {
            return Ok(XDP_PASS);
        }
    };

    // Verify this is IPv4
    if ip.version() != 4 {
        return Ok(XDP_PASS);
    }

    // Get source MAC and destination IP for routing lookup
    let src_ip = ip.src_addr();
    let dst_ip = ip.dst_addr();

    // Create session key
    let session_key = SessionKey::new(src_ip, dst_ip, 0, 0, ip.protocol());

    // Look up or create session entry with MAC information
    // SAFETY: SESSIONS is a valid eBPF map; get() returns None if key not found.
    let session = match unsafe { SESSIONS.get(&session_key) } {
        Some(entry) => {
            // Update existing session, preserve MAC if already set
            let mut updated = *entry;
            if updated.src_mac_len == 0 {
                updated.src_mac = src_mac;
                updated.src_mac_len = 6;
            }
            updated
        }
        None => {
            // Create new session with MAC
            let mut session = SessionEntry::default();
            session.state = state::NEW;
            session.src_mac_len = 6;
            session.src_mac = src_mac;
            session.packets = 1;
            session
        }
    };

    // Store session (ignore errors for now)
    let _ = SESSIONS.insert(&session_key, &session, 0);

    // Look up routing decision
    let route = match lookup_routing(dst_ip) {
        Some(r) => r,
        None => {
            // No routing rule matched
            return Ok(XDP_PASS);
        }
    };

    // Update session with routing decision
    let mut updated_session = session;
    updated_session.route_id = route.route_id;
    let _ = SESSIONS.insert(&session_key, &updated_session, 0);

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
    ROUTING.get(&key).copied()
}
