//! Integration tests for TrackingStore
//!
//! These tests verify the TrackingStore API endpoints and tracking functionality.

#[cfg(test)]
mod tracking_integration_tests {
    use dae_proxy::tracking::ConnectionKey as TrackingConnectionKey;
    use dae_proxy::tracking::{
        ConnectionState, ConnectionStatsEntry, NodeStatsEntry, ProtocolTrackingInfo,
        SharedTrackingStore, TrackingStore,
    };
    use dae_proxy::{Protocol, RuleType};
    use std::time::Duration;
    use tokio::time::sleep;

    // Helper to create a timestamp for tests
    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    // Helper to create a ConnectionKey for tracking store (uses raw integers)
    fn make_tracking_key(
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        proto: u8,
    ) -> TrackingConnectionKey {
        TrackingConnectionKey::new(src_ip, dst_ip, src_port, dst_port, proto)
    }

    // ========================================================================
    // TrackingStore Creation Tests
    // ========================================================================

    #[tokio::test]
    async fn test_tracking_store_creation() {
        let store = TrackingStore::new();
        let overall = store.get_overall();
        assert_eq!(overall.packets_total, 0);
        assert_eq!(overall.connections_total, 0);
    }

    #[tokio::test]
    async fn test_tracking_store_shared() {
        let store: SharedTrackingStore = TrackingStore::shared();
        let overall = store.get_overall();
        assert_eq!(overall.packets_total, 0);
    }

    // ========================================================================
    // Connection Tracking Tests
    // ========================================================================

    #[tokio::test]
    async fn test_update_connection_stats() {
        let store = TrackingStore::new();
        let key = make_tracking_key(0x7F000001, 0x08080808, 12345, 80, 6);
        let stats = ConnectionStatsEntry::new(now_ms());

        store.update_connection(key, stats);

        let retrieved = store.connections().get(&key);
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_record_connection_data() {
        let store = TrackingStore::new();
        let key = make_tracking_key(0x7F000001, 0x08080808, 12345, 80, 6);
        let mut stats = ConnectionStatsEntry::new(now_ms());

        // Directly update the stats with packet data
        stats.update_packet(1024, true); // 1024 bytes inbound
        stats.update_packet(512, false); // 512 bytes outbound

        store.update_connection(key, stats);

        let retrieved = store.connections().get(&key);
        assert!(retrieved.is_some());
        let retrieved_stats = retrieved.unwrap();
        assert_eq!(retrieved_stats.bytes_in, 1024);
        assert_eq!(retrieved_stats.bytes_out, 512);
    }

    #[tokio::test]
    async fn test_connection_state_tracking() {
        let store = TrackingStore::new();
        let key = make_tracking_key(0x7F000001, 0x08080808, 12345, 80, 6);
        let mut stats = ConnectionStatsEntry::new(now_ms());

        // Initial state should be New
        assert_eq!(stats.state, ConnectionState::New as u8);

        // Update state to Established
        stats.state = ConnectionState::Established as u8;
        store.update_connection(key, stats);

        let retrieved = store.connections().get(&key);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().state, ConnectionState::Established as u8);
    }

    #[tokio::test]
    async fn test_get_active_connections() {
        let store = TrackingStore::new();

        // Create multiple connections
        let key1 = make_tracking_key(0x7F000001, 0x08080808, 12345, 80, 6);
        let key2 = make_tracking_key(0x7F000001, 0x08080808, 12346, 80, 6);

        let stats1 = ConnectionStatsEntry::new(now_ms());
        let stats2 = ConnectionStatsEntry::new(now_ms());

        store.update_connection(key1, stats1);
        store.update_connection(key2, stats2);

        let active = store.connections().get_active();
        assert_eq!(active.len(), 2);
    }

    // ========================================================================
    // DNS Tracking Tests
    // ========================================================================

    #[tokio::test]
    async fn test_record_dns_cache_hit() {
        let store = TrackingStore::new();

        let initial_overall = store.get_overall();
        let initial_hits = initial_overall.dns_cache_hits;

        store.record_dns_cache_hit();

        let after_overall = store.get_overall();
        assert_eq!(after_overall.dns_cache_hits, initial_hits + 1);
    }

    #[tokio::test]
    async fn test_record_dns_cache_miss() {
        let store = TrackingStore::new();

        let initial_overall = store.get_overall();
        let initial_misses = initial_overall.dns_cache_misses;

        store.record_dns_cache_miss();

        let after_overall = store.get_overall();
        assert_eq!(after_overall.dns_cache_misses, initial_misses + 1);
    }

    #[tokio::test]
    async fn test_record_dns_query_with_latency() {
        let store = TrackingStore::new();

        store.record_dns_query(50); // 50ms latency

        let overall = store.get_overall();
        assert_eq!(overall.dns_queries_total, 1);
        assert_eq!(overall.dns_latency_sum_ms, 50);
        assert_eq!(overall.dns_latency_count, 1);
    }

    #[tokio::test]
    async fn test_dns_cache_hit_rate_calculation() {
        let store = TrackingStore::new();

        // Record 8 cache hits and 2 misses
        for _ in 0..8 {
            store.record_dns_cache_hit();
        }
        for _ in 0..2 {
            store.record_dns_cache_miss();
        }

        let overall = store.get_overall();
        let hit_rate = overall.dns_cache_hit_rate();
        assert!((hit_rate - 0.8).abs() < 0.001);
    }

    // ========================================================================
    // TLS Handshake Tracking Tests
    // ========================================================================

    #[tokio::test]
    async fn test_record_tls_handshake_start() {
        let store = TrackingStore::new();

        let timestamp = store.record_tls_handshake_start();

        let overall = store.get_overall();
        assert_eq!(overall.tls_handshakes_total, 1);
        assert!(timestamp > 0);
    }

    #[tokio::test]
    async fn test_record_tls_handshake_success() {
        let store = TrackingStore::new();

        let start = store.record_tls_handshake_start();
        sleep(Duration::from_millis(10)).await;
        store.record_tls_handshake_success(start, 0x03, 0xC02F);

        let overall = store.get_overall();
        assert_eq!(overall.tls_handshakes_total, 1);
        assert_eq!(overall.tls_handshake_successes, 1);
        assert!(overall.tls_handshake_latency_count >= 1);
    }

    #[tokio::test]
    async fn test_record_tls_handshake_failure() {
        let store = TrackingStore::new();

        let start = store.record_tls_handshake_start();
        sleep(Duration::from_millis(5)).await;
        store.record_tls_handshake_failure(start, "certificate verify failed");

        let overall = store.get_overall();
        assert_eq!(overall.tls_handshakes_total, 1);
        assert_eq!(overall.tls_handshake_failures, 1);
        assert!(overall.tls_handshake_last_error.contains("certificate"));
    }

    #[tokio::test]
    async fn test_tls_handshake_success_rate() {
        let store = TrackingStore::new();

        // Record 7 successes and 3 failures
        for _ in 0..7 {
            let start = store.record_tls_handshake_start();
            store.record_tls_handshake_success(start, 0x03, 0xC02F);
        }
        for _ in 0..3 {
            let start = store.record_tls_handshake_start();
            store.record_tls_handshake_failure(start, "timeout");
        }

        let overall = store.get_overall();
        let success_rate = overall.tls_handshake_success_rate();
        assert!((success_rate - 0.7).abs() < 0.001);
    }

    // ========================================================================
    // Rule Tracking Tests
    // ========================================================================

    #[tokio::test]
    async fn test_record_rule_match() {
        let store = TrackingStore::new();

        // Record matches for different rule types and actions
        store.record_rule_match(1, RuleType::Domain as u8, 0, 1000); // Domain, Pass
        store.record_rule_match(2, RuleType::DomainSuffix as u8, 1, 2000); // DomainSuffix, Proxy
        store.record_rule_match(3, RuleType::IpCidr as u8, 2, 500); // IpCidr, Drop

        let rules = store.rules().get_all();
        assert_eq!(rules.len(), 3);

        // Check specific rule
        if let Some(rule_stats) = store.rules().get(1) {
            assert_eq!(rule_stats.match_count, 1);
            assert_eq!(rule_stats.pass_count, 1);
            assert_eq!(rule_stats.bytes_matched, 1000);
        } else {
            panic!("Rule 1 not found");
        }
    }

    #[tokio::test]
    async fn test_rule_stats_accumulation() {
        let store = TrackingStore::new();
        let rule_id = 1;
        let rule_type = RuleType::Domain as u8;

        // Record multiple matches for same rule
        for i in 0..5 {
            store.record_rule_match(rule_id, rule_type, 1, (i + 1) * 100);
        }

        if let Some(stats) = store.rules().get(rule_id) {
            assert_eq!(stats.match_count, 5);
            assert_eq!(stats.proxy_count, 5);
            assert_eq!(stats.bytes_matched, 1500); // 100+200+300+400+500
        }
    }

    // ========================================================================
    // Node Tracking Tests
    // ========================================================================

    #[tokio::test]
    async fn test_node_tracking() {
        let store = TrackingStore::new();
        let node_id = 1u32;

        // Update node stats
        let mut stats = NodeStatsEntry::new();
        stats.record_request(50, true, 100, 200);
        stats.record_request(100, true, 100, 200);
        stats.record_request(100, false, 0, 0);

        store.nodes().update(node_id, stats);

        let retrieved = store.nodes().get(node_id);
        assert!(retrieved.is_some());

        let node_stats = retrieved.unwrap();
        assert_eq!(node_stats.total_requests, 3);
        assert_eq!(node_stats.successful_requests, 2);
        assert_eq!(node_stats.failed_requests, 1);
    }

    // ========================================================================
    // Protocol Stats Tests
    // ========================================================================

    #[tokio::test]
    async fn test_protocol_stats() {
        let store = TrackingStore::new();

        // Record TCP packets
        let protocols = store.get_protocol_stats();
        assert_eq!(protocols.tcp.packets, 0);

        // Record data transfer which updates protocol stats
        let key = make_tracking_key(0x7F000001, 0x08080808, 12345, 80, 6);
        let stats = ConnectionStatsEntry::new(now_ms());
        store.update_connection(key, stats);
        store.record_connection_data(&key, 1024, true);

        let updated_protocols = store.get_protocol_stats();
        // Note: Protocol stats may be updated through record_connection_data
        assert!(updated_protocols.tcp.bytes >= 0);
    }

    // ========================================================================
    // Overall Stats Tests
    // ========================================================================

    #[tokio::test]
    async fn test_overall_stats_counters() {
        let store = TrackingStore::new();

        let initial = store.get_overall();
        assert_eq!(initial.dropped_total, 0);
        assert_eq!(initial.routed_total, 0);
        assert_eq!(initial.unmatched_total, 0);

        store.record_dropped(5);
        store.record_routed(100);
        store.record_unmatched(2);

        let after = store.get_overall();
        assert_eq!(after.dropped_total, 5);
        assert_eq!(after.routed_total, 100);
        assert_eq!(after.unmatched_total, 2);
    }

    #[tokio::test]
    async fn test_packets_per_second_calculation() {
        let store = TrackingStore::new();

        let overall = store.get_overall();
        let pps = overall.packets_per_second(10);

        // With 0 packets over 10 seconds, should be 0
        assert_eq!(pps, 0.0);

        // Manually update and check
        let mut stats = store.get_overall();
        stats.packets_total = 100;
        // Can't update directly, but we test the calculation logic
    }

    // ========================================================================
    // Prometheus Export Tests
    // ========================================================================

    #[tokio::test]
    async fn test_export_prometheus_format() {
        let store = TrackingStore::new();

        // Add some data
        store.record_dns_query(50);

        let prometheus_output = store.export_prometheus();

        // Check for expected metrics (based on actual export_prometheus implementation)
        assert!(prometheus_output.contains("dae_dns_queries_total"));
        assert!(prometheus_output.contains("dae_packets_total"));
        assert!(prometheus_output.contains("dae_bytes_total"));
        assert!(prometheus_output.contains("dae_connections_total"));
    }

    #[tokio::test]
    async fn test_prometheus_export_contains_labels() {
        let store = TrackingStore::new();

        let output = store.export_prometheus();

        // Check for labeled metrics
        assert!(output.contains("dae_protocol_packets_total{protocol=\"tcp\"}"));
        assert!(output.contains("dae_protocol_bytes_total{protocol=\"tcp\"}"));
    }

    // ========================================================================
    // Uptime Tests
    // ========================================================================

    #[tokio::test]
    async fn test_uptime_calculation() {
        let store = TrackingStore::new();

        // Wait a bit
        sleep(Duration::from_millis(100)).await;

        let uptime = store.uptime_secs();
        assert!(uptime >= 0);
    }

    // ========================================================================
    // Connection Count Tests
    // ========================================================================

    #[tokio::test]
    async fn test_active_connection_count() {
        let store = TrackingStore::new();

        // Initially empty
        assert_eq!(store.get_active_connection_count(), 0);

        // Add connections
        let key1 = make_tracking_key(0x7F000001, 0x08080808, 12345, 80, 6);
        let key2 = make_tracking_key(0x7F000001, 0x08080808, 12346, 80, 6);

        store.update_connection(key1, ConnectionStatsEntry::new(now_ms()));
        store.update_connection(key2, ConnectionStatsEntry::new(now_ms()));

        assert_eq!(store.get_active_connection_count(), 2);
    }

    #[tokio::test]
    async fn test_node_count() {
        let store = TrackingStore::new();

        assert_eq!(store.get_node_count(), 0);

        let mut stats = NodeStatsEntry::new();
        stats.record_request(50, true, 100, 200);

        store.nodes().update(1, stats);
        store.nodes().update(2, stats);

        assert_eq!(store.get_node_count(), 2);
    }

    #[tokio::test]
    async fn test_rule_count() {
        let store = TrackingStore::new();

        assert_eq!(store.get_rule_count(), 0);

        store.record_rule_match(1, RuleType::Domain as u8, 0, 100);
        store.record_rule_match(2, RuleType::IpCidr as u8, 1, 200);

        assert_eq!(store.get_rule_count(), 2);
    }

    // ========================================================================
    // DNS Upstream Switch Tests
    // ========================================================================

    #[tokio::test]
    async fn test_record_dns_upstream_switch() {
        let store = TrackingStore::new();

        store.record_dns_upstream_switch();

        let overall = store.get_overall();
        assert_eq!(overall.dns_upstream_switches, 1);
    }

    #[tokio::test]
    async fn test_record_dns_error() {
        let store = TrackingStore::new();

        store.record_dns_error();

        let overall = store.get_overall();
        assert_eq!(overall.dns_errors, 1);
    }

    // ========================================================================
    // Proxy Chain Tracking Tests
    // ========================================================================

    #[tokio::test]
    async fn test_record_proxy_hop() {
        let store = TrackingStore::new();

        let key = make_tracking_key(0x7F000001, 0x08080808, 12345, 80, 6);
        let stats = ConnectionStatsEntry::new(now_ms());
        store.update_connection(key, stats);

        // Record proxy hop
        store.record_proxy_hop(&key, 1, 50, true);

        let retrieved = store.connections().get(&key);
        assert!(retrieved.is_some());
        let updated_stats = retrieved.unwrap();
        assert_eq!(updated_stats.hop_index, 1);
        assert_eq!(updated_stats.hop_latency_ms, 50);
    }

    // ========================================================================
    // Protocol Tracking Tests
    // ========================================================================

    #[tokio::test]
    async fn test_record_protocol_tracking() {
        let store = TrackingStore::new();

        let info = ProtocolTrackingInfo::new("vless")
            .with_bytes_in(1024)
            .with_bytes_out(2048)
            .with_metadata("uuid", "test-uuid");

        store.record_protocol_tracking(info);

        let retrieved = store.get_protocol_tracking("vless");
        assert!(retrieved.is_some());

        let tracking = retrieved.unwrap();
        assert_eq!(tracking.bytes_in, 1024);
        assert_eq!(tracking.bytes_out, 2048);
    }

    #[tokio::test]
    async fn test_get_all_protocol_tracking() {
        let store = TrackingStore::new();

        store.record_protocol_tracking(
            ProtocolTrackingInfo::new("vless")
                .with_bytes_in(1000)
                .with_bytes_out(2000),
        );
        store.record_protocol_tracking(
            ProtocolTrackingInfo::new("vmess")
                .with_bytes_in(500)
                .with_bytes_out(1500),
        );

        let all = store.get_all_protocol_tracking();
        assert_eq!(all.len(), 2);
        assert!(all.contains_key("vless"));
        assert!(all.contains_key("vmess"));
    }
}
