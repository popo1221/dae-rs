//! Tracking eBPF map definitions
//!
//! These structures define the eBPF maps used for kernel-space tracking data.
//! All structures must be #[repr(C)] and #[derive(Clone, Copy)] for eBPF compatibility.

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

impl EbpfStatsEntry {
    /// Increment packet counter
    pub fn inc_packets(&mut self, pkt_bytes: u64) {
        self.packets += 1;
        self.bytes += pkt_bytes;
    }

    /// Increment redirected counter
    pub fn inc_redirected(&mut self) {
        self.redirected += 1;
    }

    /// Increment passed counter
    pub fn inc_passed(&mut self) {
        self.passed += 1;
    }

    /// Increment dropped counter
    pub fn inc_dropped(&mut self) {
        self.dropped += 1;
    }

    /// Increment routed counter
    pub fn inc_routed(&mut self) {
        self.routed += 1;
    }

    /// Increment unmatched counter
    pub fn inc_unmatched(&mut self) {
        self.unmatched += 1;
    }
}

/// Connection statistics entry for tracking individual connections
///
/// This is stored in the eBPF HashMap for connection-level tracking.
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

impl EbpfConnStatsEntry {
    /// Create a new connection stats entry
    pub fn new(now: u64) -> Self {
        Self {
            start_time: now,
            last_time: now,
            state: 0, // NEW
            node_id: 0,
            rule_id: 0,
            ..Default::default()
        }
    }

    /// Update with inbound packet
    pub fn record_inbound(&mut self, bytes: u64, now: u64) {
        self.packets_in += 1;
        self.bytes_in += bytes;
        self.last_time = now;
    }

    /// Update with outbound packet
    pub fn record_outbound(&mut self, bytes: u64, now: u64) {
        self.packets_out += 1;
        self.bytes_out += bytes;
        self.last_time = now;
    }

    /// Mark connection as established
    pub fn establish(&mut self, now: u64) {
        self.state = 1; // ESTABLISHED
        self.last_time = now;
    }

    /// Mark connection as closing
    pub fn start_closing(&mut self, now: u64) {
        self.state = 2; // CLOSING
        self.last_time = now;
    }

    /// Mark connection as closed
    pub fn close(&mut self, now: u64) {
        self.state = 3; // CLOSED
        self.last_time = now;
    }
}

/// Connection state constants
pub mod conn_state {
    pub const NEW: u8 = 0;
    pub const ESTABLISHED: u8 = 1;
    pub const CLOSING: u8 = 2;
    pub const CLOSED: u8 = 3;
}

/// Node statistics entry for per-node tracking
///
/// This is stored in the eBPF HashMap for node-level statistics.
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

impl EbpfNodeStatsEntry {
    /// Create a new node stats entry
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a request completion
    pub fn record_request(
        &mut self,
        latency_ms: u32,
        success: bool,
        bytes_sent: u64,
        bytes_received: u64,
    ) {
        self.total_requests += 1;
        self.bytes_sent += bytes_sent;
        self.bytes_received += bytes_received;

        if success {
            self.successful_requests += 1;
        } else {
            self.failed_requests += 1;
        }

        if latency_ms > 0 {
            self.latency_sum += latency_ms as u64;
            self.latency_count += 1;
        }
    }

    /// Get average latency
    pub fn latency_avg(&self) -> u32 {
        if self.latency_count == 0 {
            0
        } else {
            (self.latency_sum / self.latency_count) as u32
        }
    }

    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.successful_requests as f64 / self.total_requests as f64
        }
    }
}

/// Rule statistics entry for per-rule tracking
///
/// This is stored in the eBPF HashMap for rule-level statistics.
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

impl EbpfRuleStatsEntry {
    /// Create a new rule stats entry
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a match with action
    pub fn record_match(&mut self, action: u8, bytes: u64) {
        self.match_count += 1;
        self.bytes_matched += bytes;

        match action {
            0 | 3 | 4 => self.pass_count += 1, // PASS, DEFAULT, DIRECT
            1 => self.proxy_count += 1,        // PROXY
            2 => self.drop_count += 1,         // DROP
            _ => {}
        }
    }
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
    /// Event type (0=ConnOpen, 1=ConnClose, 2=RuleMatch, 3=NodeUpdate)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_entry() {
        let mut stats = EbpfStatsEntry::default();
        stats.inc_packets(100);
        assert_eq!(stats.packets, 1);
        assert_eq!(stats.bytes, 100);
    }

    #[test]
    fn test_connection_key_hash() {
        let key = EbpfConnectionKey::new(0x7F000001, 0x08080808, 12345, 80, 6);
        let hash = key.to_hash();
        assert_ne!(hash, 0);
    }

    #[test]
    fn test_node_stats() {
        let mut stats = EbpfNodeStatsEntry::new();
        stats.record_request(50, true, 100, 200);
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.successful_requests, 1);
        assert_eq!(stats.latency_avg(), 50);
    }
}
