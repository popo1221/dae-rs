//! Routing map for IP CIDR-based routing rules
//!
//! Determines how packets should be routed based on destination IP.

/// Routing entry containing routing decision
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct RoutingEntry {
    /// Routing rule ID / destination identifier
    pub route_id: u32,
    /// Action: 0=PASS, 1=REDIRECT, 2=DROP
    pub action: u8,
    /// Target interface index (for redirect)
    pub ifindex: u32,
    /// Reserved for future use
    pub reserved: [u8; 4],
}

impl RoutingEntry {
    /// Create a new routing entry
    pub fn new(route_id: u32, action: u8, ifindex: u32) -> Self {
        Self {
            route_id,
            action,
            ifindex,
            reserved: [0; 4],
        }
    }
}

/// Routing actions
pub mod action {
    /// Pass the packet through without modification
    pub const PASS: u8 = 0;
    /// Redirect the packet to another interface
    pub const REDIRECT: u8 = 1;
    /// Drop the packet
    pub const DROP: u8 = 2;
}
