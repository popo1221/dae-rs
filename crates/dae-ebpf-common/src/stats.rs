//! Statistics map for tracking packet and byte counts
//!
//! Provides counters for monitoring proxy activity.

/// Statistics entry for counting proxy activity
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct StatsEntry {
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

impl StatsEntry {
    /// Increment packet counter
    pub fn inc_packets(&mut self, bytes: u64) {
        self.packets += 1;
        self.bytes += bytes;
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
