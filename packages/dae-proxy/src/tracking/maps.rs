//! Tracking eBPF map definitions
//!
//! These structures define the eBPF maps used for kernel-space tracking data.
//! All structures must be #[repr(C)] and #[derive(Clone, Copy)] for eBPF compatibility.
//!
//! Note: These are the type definitions only. The actual map implementation
//! requires integration with the aya framework in dae-ebpf crate.

/// Maximum number of protocol types we can track
pub const MAX_PROTOCOLS: usize = 16;

/// Maximum number of nodes we can track
pub const MAX_NODES: usize = 256;

/// Maximum number of rules we can track
pub const MAX_RULES: usize = 1024;

/// Maximum connection tracking entries
pub const MAX_CONNECTION_TRACKING: usize = 65536;

/// Statistics map index constants
pub mod stats_idx {
    /// Overall statistics index
    pub const OVERALL: u32 = 0;
    /// TCP statistics index
    pub const TCP: u32 = 1;
    /// UDP statistics index
    pub const UDP: u32 = 2;
    /// ICMP statistics index
    pub const ICMP: u32 = 3;
    /// DNS statistics index
    pub const DNS: u32 = 4;
    /// Other protocol statistics index
    pub const OTHER: u32 = 5;
    /// Maximum index value
    pub const MAX: u32 = 16;
}

/// Statistics entry for PerCPUArray map
///
/// This is stored in the eBPF PerCPUArray map for efficient per-CPU counting
/// without lock contention.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct EbpfStatsEntry {
    /// Total packets processed
    pub packets: u64,
    /// Total bytes processed
    pub bytes: u64,
    /// Packets marked for redirect
    pub redirected: u64,
    /// Packets passed through (not redirected)
    pub passed: u64,
    /// Packets dropped due to errors
    pub dropped: u64,
    /// Packets matched by routing rules
    pub routed: u64,
    /// Packets that didn't match any rule
    pub unmatched: u64,
}

/// Connection state constants
pub mod conn_state {
    pub const NEW: u8 = 0;
    pub const ESTABLISHED: u8 = 1;
    pub const CLOSING: u8 = 2;
    pub const CLOSED: u8 = 3;
}

/// Connection tracking map key (5-tuple)
///
/// This is the key used for the connection tracking HashMap.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct EbpfConnectionKey {
    /// Source IP (network byte order)
    pub src_ip: u32,
    /// Destination IP (network byte order)
    pub dst_ip: u32,
    /// Source port (network byte order)
    pub src_port: u16,
    /// Destination port (network byte order)
    pub dst_port: u16,
    /// IP protocol (6=TCP, 17=UDP)
    pub proto: u8,
    /// Reserved for padding/alignment
    reserved: [u8; 3],
}

impl EbpfConnectionKey {
    /// Create from raw components
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

    /// Convert to u64 hash for faster map lookups
    #[allow(dead_code)]
    pub fn to_hash(&self) -> u64 {
        // Simple hash combining all fields
        let mut hash: u64 = self.src_ip as u64;
        hash = hash.wrapping_mul(31).wrapping_add(self.dst_ip as u64);
        hash = hash.wrapping_mul(31).wrapping_add(self.src_port as u64);
        hash = hash.wrapping_mul(31).wrapping_add(self.dst_port as u64);
        hash = hash.wrapping_mul(31).wrapping_add(self.proto as u64);
        hash
    }
}

/// Connection statistics entry for tracking individual connections
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct EbpfConnStatsEntry {
    /// Inbound packets count
    pub packets_in: u64,
    /// Outbound packets count
    pub packets_out: u64,
    /// Inbound bytes count
    pub bytes_in: u64,
    /// Outbound bytes count
    pub bytes_out: u64,
    /// Connection start timestamp (epoch ms)
    pub start_time: u64,
    /// Last activity timestamp (epoch ms)
    pub last_time: u64,
    /// Connection state (0=NEW, 1=ESTABLISHED, 2=CLOSING, 3=CLOSED)
    pub state: u8,
    /// Proxy node ID assigned
    pub node_id: u32,
    /// Rule ID that matched
    pub rule_id: u32,
}

/// Node statistics entry for per-node tracking
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct EbpfNodeStatsEntry {
    /// Total requests to this node
    pub total_requests: u64,
    /// Successful requests
    pub successful_requests: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Latency sum for average calculation
    pub latency_sum: u64,
    /// Latency sample count
    pub latency_count: u64,
    /// Last test timestamp
    pub last_test_time: u64,
    /// Node status (0=UP, 1=DOWN, 2=DEGRADED)
    pub status: u8,
}

/// Rule statistics entry for per-rule tracking
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct EbpfRuleStatsEntry {
    /// Match count for this rule
    pub match_count: u64,
    /// Pass action count
    pub pass_count: u64,
    /// Proxy action count
    pub proxy_count: u64,
    /// Drop action count
    pub drop_count: u64,
    /// Total bytes for matched traffic
    pub bytes_matched: u64,
}

/// Rule action constants (matches dae-ebpf-common)
pub mod rule_action {
    pub const PASS: u8 = 0;
    pub const REDIRECT: u8 = 1;
    pub const DROP: u8 = 2;
}

/// Tracking event for ringbuf export
///
/// This structure is sent from eBPF to user-space via ringbuf
/// for real-time event tracking.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EbpfTrackingEvent {
    /// Event type (0=ConnOpen, 1=ConnClose, 2=ConnData, 3=RuleMatch, 4=NodeUpdate)
    pub event_type: u8,
    /// Event subtype for additional classification
    pub subtype: u8,
    /// Timestamp (epoch ms)
    pub timestamp: u64,
    /// Key field (connection key hash, rule id, or node id)
    pub key: u64,
    /// Value field (bytes, latency, etc.)
    pub value: u64,
    /// Additional data
    pub data: [u8; 24],
}

/// Event type constants
pub mod event_type {
    pub const CONN_OPEN: u8 = 0;
    pub const CONN_CLOSE: u8 = 1;
    pub const CONN_DATA: u8 = 2;
    pub const RULE_MATCH: u8 = 3;
    pub const NODE_UPDATE: u8 = 4;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_key_hash() {
        let key = EbpfConnectionKey::new(
            0x7F000001,
            0x08080808,
            12345,
            80,
            6,
        );
        let hash = key.to_hash();
        assert_ne!(hash, 0);
    }
}
