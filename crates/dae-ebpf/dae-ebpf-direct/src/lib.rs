//! dae-ebpf-direct - Direct Socket eBPF programs for dae-rs
//!
//! This crate implements kernel-space eBPF programs for Direct Socket mode,
//! which enables true direct eBPF traffic redirection without iptables.
//!
//! # Programs
//!
//! - **sockops**: TCP congestion control hook (BPF_PROG_TYPE_SOCK_OPS)
//!   - Intercepts TCP socket operations at the cgroup level
//!   - Records connection 5-tuples for later classification
//!   - Adds sockets to sockmap for message redirect
//!
//! - **sk_msg**: Socket message redirect (BPF_PROG_TYPE_SK_MSG)
//!   - Intercepts outgoing/incoming messages on tagged sockets
//!   - Redirects messages via sockmap to a proxy socket
//!   - Enables transparent proxy without packet-level interception

#![no_std]
#![deny(warnings)]
// Allow strict clippy lints for eBPF code patterns
#![allow(clippy::field_reassign_with_default)]
#![allow(dead_code)]

use aya_ebpf::bindings::{
    BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,
    BPF_SOCK_OPS_NEEDS_ECN, BPF_SOCK_OPS_PARSE_HDR_OPT_CB, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
    BPF_SOCK_OPS_RTT_CB, BPF_SOCK_OPS_RTO_CB, BPF_SOCK_OPS_RWND_INIT,
    BPF_SOCK_OPS_STATE_CB, BPF_SOCK_OPS_TCP_CONNECT_CB, BPF_SOCK_OPS_TCP_LISTEN_CB,
    BPF_SOCK_OPS_TIMEOUT_INIT, BPF_SOCK_OPS_VOID, BPF_SOCK_OPS_WRITE_HDR_OPT_CB,
    BPF_TCP_BOUND_INACTIVE, BPF_TCP_CLOSE, BPF_TCP_CLOSE_WAIT, BPF_TCP_CLOSING,
    BPF_TCP_ESTABLISHED, BPF_TCP_FIN_WAIT1, BPF_TCP_FIN_WAIT2, BPF_TCP_LAST_ACK,
    BPF_TCP_LISTEN, BPF_TCP_NEW_SYN_RECV, BPF_TCP_SYN_RECV, BPF_TCP_SYN_SENT,
    BPF_TCP_TIME_WAIT,
};
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::macros::{map, sk_msg, sock_ops};
use aya_ebpf::maps::{HashMap, SockHash, SockMap};
use aya_ebpf::programs::{SkMsgContext, SockOpsContext};

use dae_ebpf_common::direct::{rule_type, DirectRouteEntry};

// ============================================================================
// Constants
// ============================================================================

/// TCP protocol number
const IPPROTO_TCP: u8 = 6;
/// IPv4 address family
const AF_INET: u32 = 2;

// ============================================================================
// Types
// ============================================================================

/// Connection tracking key for sockmap redirect
///
/// This key uniquely identifies a TCP/UDP connection using its 5-tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ConnKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    _padding: u8,
}

impl ConnKey {
    /// Create a new connection key from raw values
    pub fn new(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            _padding: 0,
        }
    }

    /// Create from sock_ops context (TCP connections only)
    ///
    /// Returns None if the socket is not IPv4 TCP.
    pub fn from_sock_ops(ctx: &SockOpsContext) -> Option<Self> {
        let family = ctx.family();
        // Only support IPv4 for now (AF_INET = 2)
        if family != AF_INET {
            return None;
        }

        // Ports are stored in network byte order (big-endian) in upper 16 bits
        let local_port_raw = ctx.local_port();
        let remote_port_raw = ctx.remote_port();
        // Extract port from upper 16 bits and convert from network byte order
        let src_port = u16::from_be((local_port_raw >> 16) as u16);
        let dst_port = u16::from_be((remote_port_raw >> 16) as u16);

        Some(Self::new(
            ctx.local_ip4(),
            ctx.remote_ip4(),
            src_port,
            dst_port,
            IPPROTO_TCP,
        ))
    }

    /// Create from sk_msg context by accessing raw sk_msg_md fields
    pub fn from_sk_msg(ctx: &SkMsgContext) -> Option<Self> {
        // SAFETY: ctx.msg is a valid pointer to sk_msg_md for the duration of this call.
        // The verifier ensures the pointer is valid.
        let family = unsafe { (*ctx.msg).family };
        if family != AF_INET {
            return None;
        }

        let local_port_raw = unsafe { (*ctx.msg).local_port };
        let remote_port_raw = unsafe { (*ctx.msg).remote_port };
        let src_port = u16::from_be((local_port_raw >> 16) as u16);
        let dst_port = u16::from_be((remote_port_raw >> 16) as u16);

        Some(Self::new(
            unsafe { (*ctx.msg).local_ip4 },
            unsafe { (*ctx.msg).remote_ip4 },
            src_port,
            dst_port,
            IPPROTO_TCP,
        ))
    }
}

/// Connection value stored in the tracking map
///
/// Stores metadata about a tracked connection.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ConnValue {
    /// Process ID that owns this connection
    pub pid: u32,
    /// TCP connection state
    pub state: u32,
    /// Routing mark (0 = undecided, 1 = direct, 2 = proxy)
    pub mark: u8,
    /// Reserved for alignment
    _reserved: [u8; 3],
}

impl ConnValue {
    /// Create a new connection value
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            state: 0,
            mark: 0,
            _reserved: [0; 3],
        }
    }
}

// ============================================================================
// eBPF Maps
// ============================================================================

/// Connection tracking map
/// Maps connection 5-tuple -> ConnValue
/// Used by sockops to record connection info for later sk_msg lookup
#[map]
static CONNECTIONS: HashMap<ConnKey, ConnValue> = HashMap::with_max_entries(65536, 0);

/// Sockmap for outbound message redirection
/// sockops program adds sockets to this map; sk_msg uses it to redirect
#[map]
static SOCKMAP_OUT: SockMap = SockMap::with_max_entries(65536, 0);

/// Sockmap for inbound message redirection
#[map]
static SOCKMAP_IN: SockMap = SockMap::with_max_entries(65536, 0);

/// Sock hash for connection-to-socket lookup
/// Maps connection 5-tuple -> socket for redirect
#[map]
static SOCKHASH: SockHash<ConnKey> = SockHash::with_max_entries(65536, 0);

/// Direct routing rules map
/// Lookup: destination IP (network byte order) -> routing action
#[map]
static DIRECT_ROUTES: HashMap<u32, DirectRouteEntry> = HashMap::with_max_entries(65536, 0);

// ============================================================================
// sock_ops Program
// ============================================================================

/// sock_ops entry point
///
/// This program attaches to cgroup_sock_ops and intercepts TCP socket
/// operations. It records connection information for later use by sk_msg.
///
/// # Hook Points (via `op()` value)
///
/// - `BPF_SOCK_OPS_VOID` (0): Void callback, do nothing
/// - `BPF_SOCK_OPS_TIMEOUT_INIT` (1): Initialize connection timeout
/// - `BPF_SOCK_OPS_RWND_INIT` (2): Initialize receive window
/// - `BPF_SOCK_OPS_TCP_CONNECT_CB` (3): Called when initiating TCP connect
/// - `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` (4): Called on active side established
/// - `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB` (5): Called on passive side established
/// - `BPF_SOCK_OPS_NEEDS_ECN` (6): Query if connection needs ECN
/// - `BPF_SOCK_OPS_RTO_CB` (8): Called on RTO timer
/// - `BPF_SOCK_OPS_STATE_CB` (10): Called on TCP state change
/// - `BPF_SOCK_OPS_TCP_LISTEN_CB` (11): Called on TCP listen
/// - `BPF_SOCK_OPS_RTT_CB` (12): Called on RTT change
/// - `BPF_SOCK_OPS_PARSE_HDR_OPT_CB` (13): Parse TCP header options
/// - `BPF_SOCK_OPS_WRITE_HDR_OPT_CB` (15): Write TCP header options
///
/// # Arguments
///
/// * `ctx` - SockOps context containing socket operation details
///
/// # Returns
/// Always returns 1 (success) to allow kernel to continue processing
#[sock_ops]
pub fn sock_ops_main(ctx: SockOpsContext) -> u32 {
    match sock_ops_prog(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

/// Main sock_ops logic
fn sock_ops_prog(ctx: &SockOpsContext) -> Result<u32, ()> {
    let op = ctx.op();

    match op {
        BPF_SOCK_OPS_VOID => Ok(1),
        BPF_SOCK_OPS_TIMEOUT_INIT => handle_timeout_init(ctx),
        BPF_SOCK_OPS_RWND_INIT => Ok(1), // Let kernel set rwnd
        BPF_SOCK_OPS_TCP_CONNECT_CB => handle_tcp_connect(ctx),
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB => handle_active_established(ctx),
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => handle_passive_established(ctx),
        BPF_SOCK_OPS_NEEDS_ECN => Ok(0), // No ECN by default
        BPF_SOCK_OPS_RTO_CB => handle_rto_cb(ctx),
        BPF_SOCK_OPS_STATE_CB => handle_state_change(ctx),
        BPF_SOCK_OPS_TCP_LISTEN_CB => handle_listen(ctx),
        BPF_SOCK_OPS_RTT_CB => handle_rtt_update(ctx),
        BPF_SOCK_OPS_PARSE_HDR_OPT_CB => Ok(1),
        BPF_SOCK_OPS_WRITE_HDR_OPT_CB => Ok(1),
        _ => Ok(1),
    }
}

/// Handle timeout initialization - record new connection
fn handle_timeout_init(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    let pid = bpf_get_current_pid_tgid() as u32;
    let value = ConnValue::new(pid);
    let _ = CONNECTIONS.insert(&key, &value, 0);

    Ok(1)
}

/// Handle TCP connect initiated
fn handle_tcp_connect(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    let pid = bpf_get_current_pid_tgid() as u32;

    // Check routing rules to determine if this should be direct or proxied
    let dst_ip = key.dst_ip;
    let mut value = ConnValue::new(pid);

    // SAFETY: ctx.ops is a valid pointer for the duration of this program.
    // The verifier ensures this.
    unsafe {
        if let Some(route) = DIRECT_ROUTES.get(&dst_ip) {
            match (*route).rule_type {
                rule_type::DIRECT_RULE_IPV4_CIDR => {
                    if (*route).matches_ipv4(dst_ip) {
                        value.mark = 1; // Direct
                    }
                }
                rule_type::DIRECT_RULE_PORT => {
                    if (*route).matches_port(key.dst_port, key.protocol) {
                        value.mark = 1; // Direct
                    }
                }
                _ => {}
            }
        }
    }

    // If marked for direct, add socket to sockmap
    if value.mark == 1 {
        // SAFETY: update requires unsafe because map operations are unsafe.
        // The sock_ops pointer is valid for the duration of this program.
        let _ = unsafe { SOCKMAP_OUT.update(0, ctx.ops, 0) };
    }

    let _ = CONNECTIONS.insert(&key, &value, 0);

    Ok(1)
}

/// Handle active (client) side established callback
fn handle_active_established(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    let state = get_tcp_state(ctx);
    let mut value = ConnValue::new(bpf_get_current_pid_tgid() as u32);
    value.state = state;

    // Check routing rules
    let dst_ip = key.dst_ip;

    // SAFETY: ctx.ops is valid; map operations require unsafe blocks.
    unsafe {
        if let Some(route) = DIRECT_ROUTES.get(&dst_ip) {
            if (*route).rule_type == rule_type::DIRECT_RULE_IPV4_CIDR
                && (*route).matches_ipv4(dst_ip)
            {
                value.mark = 1; // Direct
                // Add to sockmap for redirect
                let _ = SOCKMAP_OUT.update(0, ctx.ops, 0);
            } else if (*route).rule_type == rule_type::DIRECT_RULE_PORT
                && (*route).matches_port(key.dst_port, key.protocol)
            {
                value.mark = 1; // Direct
                let _ = SOCKMAP_OUT.update(0, ctx.ops, 0);
            }
        }
    }

    let _ = CONNECTIONS.insert(&key, &value, 0);

    Ok(1)
}

/// Handle passive (server) side established callback
fn handle_passive_established(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    let mut value = ConnValue::new(0);
    value.state = BPF_TCP_ESTABLISHED;

    let _ = CONNECTIONS.insert(&key, &value, 0);

    Ok(1)
}

/// Handle RTO callback - refresh connection tracking
fn handle_rto_cb(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    // Refresh the connection entry
    let mut value = ConnValue::new(bpf_get_current_pid_tgid() as u32);
    value.state = get_tcp_state(ctx);

    let _ = CONNECTIONS.insert(&key, &value, 0);

    Ok(1)
}

/// Handle TCP state change callback
fn handle_state_change(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    let state = get_tcp_state(ctx);

    match state {
        BPF_TCP_SYN_SENT => {
            let mut value = ConnValue::new(bpf_get_current_pid_tgid() as u32);
            value.state = state;
            let _ = CONNECTIONS.insert(&key, &value, 0);
        }
        BPF_TCP_SYN_RECV => {
            let mut value = ConnValue::default();
            // SAFETY: ctx.ops is valid; map get requires unsafe.
            if let Some(existing) = unsafe { CONNECTIONS.get(&key) } {
                value = *existing;
            }
            value.state = state;
            let _ = CONNECTIONS.insert(&key, &value, 0);
        }
        BPF_TCP_ESTABLISHED => {
            let mut value = ConnValue::default();
            // SAFETY: ctx.ops is valid; map get requires unsafe.
            if let Some(existing) = unsafe { CONNECTIONS.get(&key) } {
                value = *existing;
            }
            value.state = state;
            // Re-check routing on established
            let dst_ip = key.dst_ip;
            if value.mark == 0 {
                // SAFETY: ctx.ops is valid.
                unsafe {
                    if let Some(route) = DIRECT_ROUTES.get(&dst_ip) {
                        if (*route).rule_type == rule_type::DIRECT_RULE_IPV4_CIDR
                            && (*route).matches_ipv4(dst_ip)
                        {
                            value.mark = 1;
                            let _ = SOCKMAP_OUT.update(0, ctx.ops, 0);
                        }
                    }
                }
            }
            let _ = CONNECTIONS.insert(&key, &value, 0);
        }
        BPF_TCP_FIN_WAIT1 | BPF_TCP_FIN_WAIT2 | BPF_TCP_CLOSE_WAIT => {
            let mut value = ConnValue::default();
            // SAFETY: ctx.ops is valid.
            if let Some(existing) = unsafe { CONNECTIONS.get(&key) } {
                value = *existing;
            }
            value.state = state;
            let _ = CONNECTIONS.insert(&key, &value, 0);
        }
        BPF_TCP_TIME_WAIT | BPF_TCP_CLOSE | BPF_TCP_CLOSING | BPF_TCP_LAST_ACK => {
            // Connection closing - clean up tracking
            let _ = CONNECTIONS.remove(&key);
            // SOCKHASH.update requires a key to remove - we use the connection key
            // But SockHash doesn't have remove, so we just remove from CONNECTIONS
        }
        BPF_TCP_LISTEN => {
            let mut value = ConnValue::new(bpf_get_current_pid_tgid() as u32);
            value.state = state;
            let _ = CONNECTIONS.insert(&key, &value, 0);
        }
        BPF_TCP_NEW_SYN_RECV => {
            let mut value = ConnValue::new(0);
            value.state = state;
            let _ = CONNECTIONS.insert(&key, &value, 0);
        }
        BPF_TCP_BOUND_INACTIVE => {
            let mut value = ConnValue::default();
            // SAFETY: ctx.ops is valid.
            if let Some(existing) = unsafe { CONNECTIONS.get(&key) } {
                value = *existing;
            }
            value.state = state;
            let _ = CONNECTIONS.insert(&key, &value, 0);
        }
        _ => {}
    }

    Ok(1)
}

/// Handle listen callback
fn handle_listen(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    let mut value = ConnValue::new(bpf_get_current_pid_tgid() as u32);
    value.state = BPF_TCP_LISTEN;
    let _ = CONNECTIONS.insert(&key, &value, 0);

    Ok(1)
}

/// Handle RTT update callback
fn handle_rtt_update(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    // Update connection with latest RTT metrics
    // SAFETY: ctx.ops is valid; accessing srtt_us field is safe.
    let srtt = unsafe { (*ctx.ops).srtt_us };

    let mut value = ConnValue::default();
    // SAFETY: ctx.ops is valid.
    if let Some(existing) = unsafe { CONNECTIONS.get(&key) } {
        value = *existing;
    }

    // Store srtt in pid field for monitoring (repurpose field)
    value.pid = srtt;

    let _ = CONNECTIONS.insert(&key, &value, 0);

    Ok(1)
}

/// Get TCP state from sock_ops context
fn get_tcp_state(ctx: &SockOpsContext) -> u32 {
    // SAFETY: ctx.ops is a valid pointer for the duration of the program.
    // The verifier ensures the pointer is valid and the field access is within bounds.
    unsafe { (*ctx.ops).state }
}

// ============================================================================
// sk_msg Program
// ============================================================================

/// sk_msg entry point for outbound message redirection
///
/// This program attaches to SOCKMAP_OUT and intercepts outgoing messages
/// on tagged sockets. It redirects messages to the appropriate proxy socket.
///
/// # Arguments
///
/// * `ctx` - SkMsg context containing message details
///
/// # Returns
/// BPF redirect verdict (1 = redirect success, 0 = pass to kernel)
#[sk_msg]
pub fn sk_msg_out(ctx: SkMsgContext) -> u32 {
    match sk_msg_prog_out(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

/// sk_msg entry point for inbound message redirection
///
/// This program attaches to SOCKMAP_IN and intercepts incoming messages
/// from the proxy.
#[sk_msg]
pub fn sk_msg_in(ctx: SkMsgContext) -> u32 {
    match sk_msg_prog_in(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

/// Main sk_msg logic for outbound messages
///
/// Intercepts messages going out and redirects them to the proxy.
fn sk_msg_prog_out(ctx: &SkMsgContext) -> Result<u32, ()> {
    // Look up the connection key for this message
    let key = match ConnKey::from_sk_msg(ctx) {
        Some(k) => k,
        None => return Ok(0), // Unknown connection - don't redirect
    };

    // Check if this connection should be redirected
    // SAFETY: ctx.msg is valid; map get requires unsafe.
    if let Some(value) = unsafe { CONNECTIONS.get(&key) } {
        if (*value).mark == 1 {
            // Marked for direct - redirect via sockmap to proxy
            // Index 0 is used for the proxy socket in our design
            // SAFETY: redirect_msg is unsafe due to raw pointer access.
            let ret = unsafe { SOCKMAP_OUT.redirect_msg(ctx, 0, 0) };
            // Return >= 0 means success (BPF action result)
            if ret >= 0 {
                return Ok(ret as u32);
            }
        }
    }

    // Not in redirect map - pass to kernel
    Ok(0)
}

/// Main sk_msg logic for inbound messages
///
/// Intercepts messages coming from the proxy and redirects them
/// back to the original receiving socket.
fn sk_msg_prog_in(ctx: &SkMsgContext) -> Result<u32, ()> {
    // Similar to outbound - redirect via inbound sockmap
    // SAFETY: redirect_msg is unsafe.
    let ret = unsafe { SOCKMAP_IN.redirect_msg(ctx, 0, 0) };
    if ret >= 0 {
        return Ok(ret as u32);
    }

    Ok(0)
}

// ============================================================================
// Utilities
// ============================================================================

/// Create a connection key from raw parts
#[allow(dead_code)]
pub fn conn_key_from_parts(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
) -> ConnKey {
    ConnKey::new(src_ip, dst_ip, src_port, dst_port, protocol)
}

/// Check if an IP matches a direct route CIDR rule
///
/// # Arguments
///
/// * `ip` - IP address in host byte order
/// * `cidr_ip` - CIDR base IP in host byte order
/// * `prefix_len` - CIDR prefix length (0-32)
///
/// # Returns
/// true if the IP matches the CIDR rule
#[allow(dead_code)]
pub fn ip_matches_cidr(ip: u32, cidr_ip: u32, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 32 {
        return false;
    }

    let mask = !0u32 << (32 - prefix_len);
    (ip & mask) == (cidr_ip & mask)
}
