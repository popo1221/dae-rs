//! Session map entry for connection tracking
//!
//! Tracks active connections for stateful proxying.

/// Session key identifying a unique connection
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct SessionKey {
    /// Source IP address (network byte order)
    pub src_ip: u32,
    /// Destination IP address (network byte order)
    pub dst_ip: u32,
    /// Source port (network byte order)
    pub src_port: u16,
    /// Destination port (network byte order)
    pub dst_port: u16,
    /// IP protocol (6 for TCP, 17 for UDP)
    pub proto: u8,
    /// Reserved for padding
    reserved: [u8; 3],
}

impl SessionKey {
    /// Create a new session key from packet info
    pub fn new(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
            reserved: [0; 3],
        }
    }
}

/// Session value containing connection state
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct SessionEntry {
    /// Connection state (0=NEW, 1=ESTABLISHED, 2=CLOSED)
    pub state: u8,
    /// Reserved for padding
    reserved1: [u8; 1],
    /// Source MAC address length (0 = not set, 6 = valid)
    pub src_mac_len: u8,
    /// Marked packet count
    pub packets: u64,
    /// Total bytes transferred
    pub bytes: u64,
    /// Connection start timestamp (jiffies)
    pub start_time: u64,
    /// Last activity timestamp (jiffies)
    pub last_time: u64,
    /// Routing decision for this session
    pub route_id: u32,
    /// Source MAC address (network byte order)
    pub src_mac: [u8; 6],
}

/// Connection states
pub mod state {
    pub const NEW: u8 = 0;
    pub const ESTABLISHED: u8 = 1;
    pub const CLOSED: u8 = 2;
}
