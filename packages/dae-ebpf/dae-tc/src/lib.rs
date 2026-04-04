//! dae-tc - TC eBPF program for dae-rs transparent proxy
//!
//! This program captures network packets using tc (traffic control) clsact
//! qdisc and performs traffic classification and redirection for
//! transparent proxy support.
//!
//! Key features:
//! - Attaches to tc clsact qdisc on the specified interface
//! - Parses Ethernet, IPv4, TCP, and UDP headers
//! - Performs longest-prefix-match routing lookups
//! - Tracks connection state for stateful proxying
//! - Supports PASS, REDIRECT, and DROP actions
//!
//! # Usage
//!
//! This eBPF program is loaded by the user-space loader (dae-ebpf) using
//! the TC program type. The loader will:
//! 1. Setup clsact qdisc on the target interface
//! 2. Load this eBPF program into the kernel
//! 3. Attach it as an ingress filter
//!
//! # Note
//!
//! This program compiles as a library. The actual eBPF program is a function
//! named `tc_prog_main` that takes a `TcContext` and returns an `i32`.
//! The user-space loader uses this function name when attaching.

#![no_std]
#![allow(unused)]
// Allow strict clippy lints for eBPF code patterns
#![allow(clippy::field_reassign_with_default)]

use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::programs::TcContext;

use dae_ebpf_common::{action, state, RoutingEntry, SessionEntry, SessionKey};

mod maps;
mod packet;

use maps::*;
use packet::*;

/// TC program entry point
///
/// This function is called for each packet entering the interface.
/// It performs packet parsing, session tracking, and routing lookups.
///
/// # Arguments
///
/// * `ctx` - The TC context containing the packet data
///
/// # Returns
///
/// * `TC_ACT_OK` - Continue processing the packet normally
/// * `TC_ACT_SHOT` - Drop the packet
/// * Negative value - Error, drop the packet
#[no_mangle]
pub fn tc_prog_main(ctx: TcContext) -> i32 {
    // TcContext::new takes a *mut __sk_buff, but ctx.skb is a SkBuff struct
    // We need to access the internal raw pointer via ctx.skb.skb
    let mut new_ctx = TcContext::new(ctx.skb.skb);
    match tc_prog(&mut new_ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

/// Main TC program logic
fn tc_prog(ctx: &mut TcContext) -> Result<i32, ()> {
    // Parse Ethernet header
    let eth = match EthHdr::from_ctx(ctx) {
        Some(hdr) => unsafe { *hdr },
        None => {
            // Can't parse Ethernet header, pass
            return Ok(TC_ACT_OK);
        }
    };

    // Get source MAC address for potential LAN classification
    let _src_mac = eth.src_mac();

    // Handle VLAN tagging
    let (ip_offset, is_ipv4) = if eth.has_vlan() {
        // VLAN tag present
        let vlan = match VlanHdr::from_ctx_after_eth(ctx, core::mem::size_of::<EthHdr>()) {
            Some(hdr) => unsafe { *hdr },
            None => {
                return Ok(TC_ACT_OK);
            }
        };
        let actual_ethertype = vlan.tpid;
        (
            core::mem::size_of::<EthHdr>() + core::mem::size_of::<VlanHdr>(),
            actual_ethertype == ethertype::IPV4.to_be(),
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
                Some(hdr) => unsafe { *hdr },
                None => return Ok(TC_ACT_OK),
            };
            (tcp.src_port(), tcp.dst_port())
        }
        ip_proto::UDP => {
            let udp = match UdpHdr::from_ctx_after_ip(ctx, ip_offset, ip_hdr_len) {
                Some(hdr) => unsafe { *hdr },
                None => return Ok(TC_ACT_OK),
            };
            (udp.src_port(), udp.dst_port())
        }
        _ => (0, 0),
    };

    // Create session key
    let session_key = SessionKey::new(src_ip, dst_ip, src_port, dst_port, ip_proto);

    // Look up or create session
    let session = match unsafe { SESSIONS.get(&session_key) } {
        Some(entry) => {
            // Update existing session
            let mut updated = *entry;
            updated.packets += 1;
            updated.last_time = bpf_ktime_get_ns();
            updated
        }
        None => {
            // Create new session
            let mut session = SessionEntry::default();
            session.state = state::NEW;
            session.packets = 1;
            session.start_time = bpf_ktime_get_ns();
            session.last_time = session.start_time;
            session.src_mac_len = 6;
            session.src_mac = _src_mac;
            session
        }
    };

    // Store/update session
    let _ = SESSIONS.insert(&session_key, &session, 0);

    // Look up routing decision for destination
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

/// Get current kernel time in nanoseconds
///
/// This is a placeholder - in actual eBPF programs, you'd use
/// bpf_ktime_get_ns() provided by the BPF helper functions.
/// For compilation purposes, we return 0.
fn bpf_ktime_get_ns() -> u64 {
    // The actual implementation would use bpf_ktime_get_ns() helper
    // Here we just return a placeholder value for compilation
    0
}
