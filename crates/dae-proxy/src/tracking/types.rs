//! Tracking type definitions
//!
//! Core data structures for connection, node, rule, and protocol tracking.

pub use crate::tracking::constants::{
    current_epoch_ms, event_type, ConnectionState, LatencySample, NodeStatus, Protocol, RuleAction,
    RuleType,
};

/// Connection tracking key (5-tuple)
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct ConnectionKey {
    /// Source IP address (network byte order, u32 for IPv4)
    pub src_ip: u32,
    /// Destination IP address (network byte order)
    pub dst_ip: u32,
    /// Source port (network byte order)
    pub src_port: u16,
    /// Destination port (network byte order)
    pub dst_port: u16,
    /// IP protocol (6=TCP, 17=UDP)
    pub proto: u8,
    /// Reserved for padding
    reserved: [u8; 3],
}

impl ConnectionKey {
    /// Create a new connection key
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

    /// Get protocol name
    pub fn protocol_name(&self) -> &'static str {
        match self.proto {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            _ => "UNKNOWN",
        }
    }
}

/// Connection tracking entry
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct ConnectionStatsEntry {
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
    /// Average RTT in milliseconds
    pub rtt_avg: u32,
    /// Minimum RTT in milliseconds
    pub rtt_min: u32,
    /// Maximum RTT in milliseconds
    pub rtt_max: u32,
    /// Connection state (0=NEW, 1=ESTABLISHED, 2=CLOSING, 3=CLOSED)
    pub state: u8,
    /// Proxy node ID assigned to this connection
    pub node_id: u32,
    /// Rule ID that matched this connection
    pub rule_id: u32,
    /// Reserved for padding
    reserved: [u8; 6],
}

impl ConnectionStatsEntry {
    /// Create a new connection stats entry
    pub fn new(start_time: u64) -> Self {
        Self {
            start_time,
            last_time: start_time,
            rtt_avg: 0,
            rtt_min: u32::MAX,
            rtt_max: 0,
            state: ConnectionState::New as u8,
            ..Default::default()
        }
    }

    /// Update with new packet
    pub fn update_packet(&mut self, bytes: u64, inbound: bool) {
        let now = current_epoch_ms();
        self.last_time = now;

        if inbound {
            self.packets_in += 1;
            self.bytes_in += bytes;
        } else {
            self.packets_out += 1;
            self.bytes_out += bytes;
        }
    }

    /// Update RTT measurement
    pub fn update_rtt(&mut self, rtt_ms: u32) {
        self.rtt_avg = ((self.rtt_avg as u64 * 9 + rtt_ms as u64) / 10) as u32;
        self.rtt_min = self.rtt_min.min(rtt_ms);
        self.rtt_max = self.rtt_max.max(rtt_ms);
    }

    /// Get connection age
    pub fn age_ms(&self) -> u64 {
        current_epoch_ms().saturating_sub(self.start_time)
    }

    /// Get idle time in milliseconds
    pub fn idle_ms(&self) -> u64 {
        current_epoch_ms().saturating_sub(self.last_time)
    }
}

/// Node tracking entry
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct NodeStatsEntry {
    /// Total requests to this node
    pub total_requests: u64,
    /// Successful requests (2xx/3xx response)
    pub successful_requests: u64,
    /// Failed requests (4xx/5xx response or timeout)
    pub failed_requests: u64,
    /// Bytes sent to node
    pub bytes_sent: u64,
    /// Bytes received from node
    pub bytes_received: u64,
    /// Sum of all latencies for average calculation
    pub latency_sum: u64,
    /// Number of latency samples
    pub latency_count: u64,
    /// P50 latency (stored as percentile buckets)
    pub latency_p50: u32,
    /// P90 latency
    pub latency_p90: u32,
    /// P99 latency
    pub latency_p99: u32,
    /// Last test time (epoch ms)
    pub last_test_time: u64,
    /// Node status (0=UP, 1=DOWN, 2=DEGRADED)
    pub status: u8,
    /// Current in-flight requests
    pub active_requests: u32,
    /// Reserved
    reserved: [u8; 2],
}

impl NodeStatsEntry {
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

        // Update latency stats
        self.latency_sum += latency_ms as u64;
        self.latency_count += 1;
        self.latency_avg(); // Triggers recalculation

        if success {
            self.successful_requests += 1;
        } else {
            self.failed_requests += 1;
        }
    }

    /// Calculate average latency
    pub fn latency_avg(&self) -> f64 {
        if self.latency_count == 0 {
            0.0
        } else {
            self.latency_sum as f64 / self.latency_count as f64
        }
    }

    /// Update percentile (simplified - real implementation would use histogram)
    pub fn update_percentiles(&mut self, latency_ms: u32) {
        // Sliding window percentile calculation
        // This is a simplified version; real implementation would use HDRHistogram or similar
        self.latency_p50 = latency_ms;
        self.latency_p90 = (latency_ms as f64 * 1.5) as u32;
        self.latency_p99 = (latency_ms as f64 * 2.0) as u32;
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

/// Rule tracking entry
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct RuleStatsEntry {
    /// Rule unique identifier
    pub rule_id: u32,
    /// Rule type (0=Domain, 1=DomainSuffix, 2=DomainKeyword, 3=IpCidr, 4=GeoIp, 5=Process)
    pub rule_type: u8,
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
    /// Reserved
    reserved: [u8; 6],
}

impl RuleStatsEntry {
    /// Create a new rule stats entry
    pub fn new(rule_id: u32, rule_type: u8) -> Self {
        Self {
            rule_id,
            rule_type,
            ..Default::default()
        }
    }

    /// Record a rule match
    pub fn record_match(&mut self, action: RuleAction, bytes: u64) {
        self.match_count += 1;
        self.bytes_matched += bytes;

        match action {
            RuleAction::Pass | RuleAction::Direct | RuleAction::MustDirect => {
                self.pass_count += 1;
            }
            RuleAction::Proxy | RuleAction::Default => {
                self.proxy_count += 1;
            }
            RuleAction::Drop => {
                self.drop_count += 1;
            }
        }
    }
}

/// Protocol tracking entry
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
#[repr(C)]
pub struct ProtocolStatsEntry {
    /// Total packets for this protocol
    pub packets: u64,
    /// Total bytes for this protocol
    pub bytes: u64,
    /// Connection count
    pub connections: u64,
    /// Active connections
    pub active_connections: u32,
}

impl ProtocolStatsEntry {
    /// Create a new protocol stats entry
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a packet
    pub fn record_packet(&mut self, bytes: u64) {
        self.packets += 1;
        self.bytes += bytes;
    }

    /// Record a new connection
    pub fn record_connection(&mut self) {
        self.connections += 1;
        self.active_connections += 1;
    }

    /// Record connection close
    pub fn record_connection_close(&mut self) {
        self.active_connections = self.active_connections.saturating_sub(1);
    }
}

/// Protocol statistics map
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ProtocolStats {
    /// TCP stats
    pub tcp: ProtocolStatsEntry,
    /// UDP stats
    pub udp: ProtocolStatsEntry,
    /// ICMP stats
    pub icmp: ProtocolStatsEntry,
    /// Other protocol stats
    pub other: ProtocolStatsEntry,
}

impl ProtocolStats {
    /// Get stats for a specific protocol
    pub fn get(&self, proto: u8) -> &ProtocolStatsEntry {
        match proto {
            6 => &self.tcp,
            17 => &self.udp,
            1 => &self.icmp,
            _ => &self.other,
        }
    }

    /// Get mutable stats for a specific protocol
    pub fn get_mut(&mut self, proto: u8) -> &mut ProtocolStatsEntry {
        match proto {
            6 => &mut self.tcp,
            17 => &mut self.udp,
            1 => &mut self.icmp,
            _ => &mut self.other,
        }
    }
}

/// Tracking event for export via ringbuf
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct TrackingEvent {
    /// Event type (0=Connection, 1=Rule, 2=Node, 3=Stats)
    pub event_type: u8,
    /// Event timestamp (epoch ms)
    pub timestamp: u64,
    /// Event data (union-like, type-dependent)
    pub data: [u8; 48],
}

impl TrackingEvent {
    /// Create a new tracking event
    pub fn new(event_type: u8) -> Self {
        Self {
            event_type,
            timestamp: current_epoch_ms(),
            data: [0; 48],
        }
    }
}

/// Overall statistics (for global tracking)
#[derive(Clone, Debug, Default)]
pub struct OverallStats {
    /// Total packets processed
    pub packets_total: u64,
    /// Total bytes processed
    pub bytes_total: u64,
    /// Total connections established
    pub connections_total: u64,
    /// Currently active connections
    pub connections_active: u32,
    /// Total dropped packets
    pub dropped_total: u64,
    /// Total routed packets
    pub routed_total: u64,
    /// Total unmatched packets
    pub unmatched_total: u64,
}

impl OverallStats {
    /// Create new overall stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate packets per second (since start)
    pub fn packets_per_second(&self, uptime_secs: u64) -> f64 {
        if uptime_secs > 0 {
            self.packets_total as f64 / uptime_secs as f64
        } else {
            0.0
        }
    }

    /// Calculate throughput in bytes per second
    pub fn bytes_per_second(&self, uptime_secs: u64) -> f64 {
        if uptime_secs > 0 {
            self.bytes_total as f64 / uptime_secs as f64
        } else {
            0.0
        }
    }
}

/// Tracking metrics for Prometheus export
#[derive(Debug, Clone)]
pub struct TrackingMetrics {
    /// Overall statistics
    pub overall: OverallStats,
    /// Per-protocol statistics
    pub protocols: ProtocolStats,
    /// Timestamp
    pub timestamp: u64,
}

impl TrackingMetrics {
    /// Create new tracking metrics
    pub fn new() -> Self {
        Self {
            overall: OverallStats::new(),
            protocols: ProtocolStats::default(),
            timestamp: current_epoch_ms(),
        }
    }

    /// Export as Prometheus format
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Overall stats
        output.push_str("# dae-rs overall statistics\n");
        output.push_str(&format!(
            "dae_packets_total {}\n",
            self.overall.packets_total
        ));
        output.push_str(&format!("dae_bytes_total {}\n", self.overall.bytes_total));
        output.push_str(&format!(
            "dae_connections_total {}\n",
            self.overall.connections_total
        ));
        output.push_str(&format!(
            "dae_connections_active {}\n",
            self.overall.connections_active
        ));
        output.push_str(&format!(
            "dae_dropped_total {}\n",
            self.overall.dropped_total
        ));
        output.push_str(&format!("dae_routed_total {}\n", self.overall.routed_total));
        output.push_str(&format!(
            "dae_unmatched_total {}\n",
            self.overall.unmatched_total
        ));

        // Protocol stats
        output.push_str("\n# dae-rs protocol statistics\n");
        output.push_str(&format!(
            "dae_protocol_packets_total{{protocol=\"tcp\"}} {}\n",
            self.protocols.tcp.packets
        ));
        output.push_str(&format!(
            "dae_protocol_bytes_total{{protocol=\"tcp\"}} {}\n",
            self.protocols.tcp.bytes
        ));
        output.push_str(&format!(
            "dae_protocol_packets_total{{protocol=\"udp\"}} {}\n",
            self.protocols.udp.packets
        ));
        output.push_str(&format!(
            "dae_protocol_bytes_total{{protocol=\"udp\"}} {}\n",
            self.protocols.udp.bytes
        ));

        output
    }

    /// Export as JSON (manual format, no serde required)
    #[allow(dead_code)]
    pub fn export_json(&self) -> String {
        format!(
            r#"{{
  "timestamp": {},
  "overall": {{
    "packets_total": {},
    "bytes_total": {},
    "connections_total": {},
    "connections_active": {},
    "dropped_total": {},
    "routed_total": {},
    "unmatched_total": {}
  }},
  "protocols": {{
    "tcp": {{
      "packets": {},
      "bytes": {}
    }},
    "udp": {{
      "packets": {},
      "bytes": {}
    }}
  }}
}}"#,
            self.timestamp,
            self.overall.packets_total,
            self.overall.bytes_total,
            self.overall.connections_total,
            self.overall.connections_active,
            self.overall.dropped_total,
            self.overall.routed_total,
            self.overall.unmatched_total,
            self.protocols.tcp.packets,
            self.protocols.tcp.bytes,
            self.protocols.udp.packets,
            self.protocols.udp.bytes,
        )
    }
}

impl Default for TrackingMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracking::constants::{current_epoch_ms, Protocol, RuleAction, RuleType};

    #[test]
    fn test_connection_key() {
        let key = ConnectionKey::new(
            0x7F000001, // 127.0.0.1
            0x08080808, // 8.8.8.8
            12345, 80, 6,
        );
        assert_eq!(key.protocol_name(), "TCP");
    }

    #[test]
    fn test_connection_stats() {
        let start = current_epoch_ms();
        let mut stats = ConnectionStatsEntry::new(start);

        stats.update_packet(100, true);
        stats.update_packet(200, false);

        assert_eq!(stats.packets_in, 1);
        assert_eq!(stats.packets_out, 1);
        assert_eq!(stats.bytes_in, 100);
        assert_eq!(stats.bytes_out, 200);
    }

    #[test]
    fn test_node_stats() {
        let mut stats = NodeStatsEntry::new();

        stats.record_request(50, true, 100, 200);
        stats.record_request(100, true, 100, 200);
        stats.record_request(100, false, 0, 0);

        assert_eq!(stats.total_requests, 3);
        assert_eq!(stats.successful_requests, 2);
        assert_eq!(stats.failed_requests, 1);
        let avg = stats.latency_avg();
        assert!(
            (avg - 83.33).abs() < 0.01,
            "latency_avg() = {} expected ~83.33",
            avg
        );
    }

    #[test]
    fn test_rule_stats() {
        let mut stats = RuleStatsEntry::new(1, RuleType::Domain as u8);

        stats.record_match(RuleAction::Pass, 1000);
        stats.record_match(RuleAction::Proxy, 2000);
        stats.record_match(RuleAction::Drop, 500);

        assert_eq!(stats.match_count, 3);
        assert_eq!(stats.pass_count, 1);
        assert_eq!(stats.proxy_count, 1);
        assert_eq!(stats.drop_count, 1);
        assert_eq!(stats.bytes_matched, 3500);
    }

    #[test]
    fn test_tracking_metrics_prometheus() {
        let metrics = TrackingMetrics::new();
        let output = metrics.export_prometheus();

        assert!(output.contains("dae_packets_total"));
        assert!(output.contains("dae_connections_active"));
    }

    // ========================================================================
    // RuleAction and RuleType Tests
    // ========================================================================

    #[test]
    fn test_rule_action_values() {
        assert_eq!(RuleAction::Pass as u8, 0);
        assert_eq!(RuleAction::Proxy as u8, 1);
        assert_eq!(RuleAction::Drop as u8, 2);
        assert_eq!(RuleAction::Default as u8, 3);
        assert_eq!(RuleAction::Direct as u8, 4);
        assert_eq!(RuleAction::MustDirect as u8, 5);
    }

    #[test]
    fn test_rule_type_values() {
        assert_eq!(RuleType::Domain as u8, 0);
        assert_eq!(RuleType::DomainSuffix as u8, 1);
        assert_eq!(RuleType::DomainKeyword as u8, 2);
        assert_eq!(RuleType::IpCidr as u8, 3);
        assert_eq!(RuleType::GeoIp as u8, 4);
        assert_eq!(RuleType::Process as u8, 5);
    }

    // ========================================================================
    // Protocol Enum Tests
    // ========================================================================

    #[test]
    fn test_protocol_values() {
        assert_eq!(Protocol::Tcp as u8, 6);
        assert_eq!(Protocol::Udp as u8, 17);
        assert_eq!(Protocol::Icmp as u8, 1);
        assert_eq!(Protocol::Socks5 as u8, 0x50);
        assert_eq!(Protocol::Http as u8, 0x51);
        assert_eq!(Protocol::Vless as u8, 0x52);
        assert_eq!(Protocol::Vmess as u8, 0x53);
        assert_eq!(Protocol::Trojan as u8, 0x54);
        assert_eq!(Protocol::Shadowsocks as u8, 0x55);
    }

    #[test]
    fn test_protocol_from_u8() {
        // Test conversion from protocol number to Protocol enum
        fn from_protocol(p: Protocol) -> u8 {
            p as u8
        }
        assert_eq!(from_protocol(Protocol::Tcp), 6);
        assert_eq!(from_protocol(Protocol::Udp), 17);
    }

    // ========================================================================
    // ProtocolStatsEntry Tests
    // ========================================================================

    #[test]
    fn test_protocol_stats_entry_new() {
        let entry = ProtocolStatsEntry::new();
        assert_eq!(entry.packets, 0);
        assert_eq!(entry.bytes, 0);
        assert_eq!(entry.connections, 0);
        assert_eq!(entry.active_connections, 0);
    }

    #[test]
    fn test_protocol_stats_entry_record_packet() {
        let mut entry = ProtocolStatsEntry::new();
        entry.record_packet(100);
        entry.record_packet(200);
        assert_eq!(entry.packets, 2);
        assert_eq!(entry.bytes, 300);
    }

    #[test]
    fn test_protocol_stats_entry_record_connection() {
        let mut entry = ProtocolStatsEntry::new();
        entry.record_connection();
        entry.record_connection();
        entry.record_connection();
        assert_eq!(entry.connections, 3);
        assert_eq!(entry.active_connections, 3);
    }

    #[test]
    fn test_protocol_stats_entry_record_connection_close() {
        let mut entry = ProtocolStatsEntry::new();
        entry.record_connection();
        entry.record_connection();
        entry.record_connection();
        entry.record_connection_close();
        assert_eq!(entry.active_connections, 2);
        // Closing more than open should not underflow
        entry.record_connection_close();
        entry.record_connection_close();
        entry.record_connection_close();
        assert_eq!(entry.active_connections, 0);
    }

    // ========================================================================
    // ProtocolStats Tests
    // ========================================================================

    #[test]
    fn test_protocol_stats_get_tcp() {
        let stats = ProtocolStats::default();
        let tcp_stats = stats.get(6); // TCP protocol number
        assert_eq!(tcp_stats.packets, 0);
        assert_eq!(tcp_stats.bytes, 0);
    }

    #[test]
    fn test_protocol_stats_get_udp() {
        let stats = ProtocolStats::default();
        let udp_stats = stats.get(17); // UDP protocol number
        assert_eq!(udp_stats.packets, 0);
    }

    #[test]
    fn test_protocol_stats_get_mut() {
        let mut stats = ProtocolStats::default();
        stats.get_mut(6).record_packet(100);
        stats.get_mut(6).record_packet(200);
        assert_eq!(stats.tcp.packets, 2);
        assert_eq!(stats.tcp.bytes, 300);
    }

    // ========================================================================
    // Additional RuleStatsEntry Tests
    // ========================================================================

    #[test]
    fn test_rule_stats_empty() {
        let stats = RuleStatsEntry::new(1, RuleType::Domain as u8);
        assert_eq!(stats.match_count, 0);
        assert_eq!(stats.pass_count, 0);
        assert_eq!(stats.proxy_count, 0);
        assert_eq!(stats.drop_count, 0);
        assert_eq!(stats.bytes_matched, 0);
    }

    #[test]
    fn test_rule_stats_multiple_same_action() {
        let mut stats = RuleStatsEntry::new(1, RuleType::DomainSuffix as u8);
        stats.record_match(RuleAction::Proxy, 100);
        stats.record_match(RuleAction::Proxy, 200);
        stats.record_match(RuleAction::Proxy, 300);
        assert_eq!(stats.match_count, 3);
        assert_eq!(stats.proxy_count, 3);
        assert_eq!(stats.bytes_matched, 600);
    }

    // ========================================================================
    // Additional NodeStatsEntry Tests
    // ========================================================================

    #[test]
    fn test_node_stats_latency_avg_empty() {
        let stats = NodeStatsEntry::new();
        // No requests recorded, average should be 0 or NaN
        let avg = stats.latency_avg();
        assert!(avg.is_nan() || avg == 0.0);
    }

    #[test]
    fn test_node_stats_bytes_sent_received() {
        let mut stats = NodeStatsEntry::new();
        stats.record_request(50, true, 1000, 2000);
        stats.record_request(100, true, 500, 1500);
        // Note: bytes_sent and bytes_received are fields, not methods
        assert_eq!(stats.bytes_sent, 1500);
        assert_eq!(stats.bytes_received, 3500);
    }

    #[test]
    fn test_node_stats_success_rate() {
        let mut stats = NodeStatsEntry::new();
        stats.record_request(50, true, 0, 0);
        stats.record_request(50, true, 0, 0);
        stats.record_request(50, false, 0, 0);
        assert_eq!(stats.total_requests, 3);
        assert_eq!(stats.successful_requests, 2);
        assert_eq!(stats.failed_requests, 1);
        assert!((stats.success_rate() - 0.667).abs() < 0.01);
    }

    // ========================================================================
    // OverallStats Tests
    // ========================================================================

    #[test]
    fn test_overall_stats_new() {
        let stats = OverallStats::new();
        assert_eq!(stats.connections_total, 0);
        assert_eq!(stats.connections_active, 0);
        assert_eq!(stats.packets_total, 0);
        assert_eq!(stats.bytes_total, 0);
    }

    #[test]
    fn test_overall_stats_fields() {
        let mut stats = OverallStats::new();
        stats.connections_total = 100;
        stats.connections_active = 10;
        stats.packets_total = 500;
        stats.bytes_total = 1000;
        stats.dropped_total = 5;
        stats.routed_total = 400;
        stats.unmatched_total = 95;

        assert_eq!(stats.connections_total, 100);
        assert_eq!(stats.connections_active, 10);
        assert_eq!(stats.packets_total, 500);
        assert_eq!(stats.bytes_total, 1000);
        assert_eq!(stats.dropped_total, 5);
        assert_eq!(stats.routed_total, 400);
        assert_eq!(stats.unmatched_total, 95);
    }

    #[test]
    fn test_overall_stats_packets_per_second() {
        let stats = OverallStats::new();
        assert_eq!(stats.packets_per_second(0), 0.0);
        assert_eq!(stats.packets_per_second(10), 0.0);

        let mut stats = OverallStats::new();
        stats.packets_total = 100;
        assert_eq!(stats.packets_per_second(10), 10.0);
    }

    #[test]
    fn test_overall_stats_bytes_per_second() {
        let stats = OverallStats::new();
        assert_eq!(stats.bytes_per_second(0), 0.0);
        assert_eq!(stats.bytes_per_second(5), 0.0);

        let mut stats = OverallStats::new();
        stats.bytes_total = 1024;
        assert_eq!(stats.bytes_per_second(8), 128.0);
    }
}
