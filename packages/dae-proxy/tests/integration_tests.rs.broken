//! Integration tests for dae-proxy
//!
//! These tests verify end-to-end functionality and stress test
//! the proxy system under load.

#[cfg(test)]
mod integration_tests {
    use dae_proxy::{
        connection::Connection,
        connection_pool::{ConnectionKey, ConnectionPool},
        rule_engine::{PacketInfo, RuleEngine, RuleEngineConfig},
        rules::{DomainRule, IpCidrRule, Rule, RuleGroup, RuleMatchAction},
        socks5::Socks5Handler,
        shadowsocks::{ShadowsocksHandler, SsCipherType, SsServerConfig},
    };
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_socks5_handler_basic() {
        let handler = Socks5Handler::new();
        assert!(!handler.is_closed());
    }

    #[tokio::test]
    async fn test_shadowsocks_handler_creation() {
        let config = SsServerConfig {
            cipher: SsCipherType::ChaCha20IetfPoly1305,
            password: "test-password-12345".to_string(),
            ..Default::default()
        };
        let handler = ShadowsocksHandler::new(config);
        assert!(!handler.is_closed());
    }

    #[tokio::test]
    async fn test_rule_engine_basic_matching() {
        let mut group = RuleGroup::default();
        group.name = "test".to_string();
        group.rules.push(Rule::Domain(DomainRule {
            pattern: "example.com".to_string(),
            action: RuleMatchAction::Allow,
        }));

        let config = RuleEngineConfig {
            groups: vec![group],
            ..Default::default()
        };

        let engine = RuleEngine::new(config).expect("Failed to create engine");

        let mut packet = PacketInfo::new(
            Ipv4Addr::new(192, 168, 1, 100).into(),
            Ipv4Addr::new(8, 8, 8, 8).into(),
            12345,
            443,
            6,
        );
        packet.destination_domain = Some("example.com".to_string());

        let result = engine.match_packet(&packet);
        assert!(result.is_allow());
    }

    #[tokio::test]
    async fn test_connection_pool_basic_ops() {
        let pool = ConnectionPool::new(100);

        let key = ConnectionKey::new(
            Ipv4Addr::new(192, 168, 1, 100).into(),
            Ipv4Addr::new(8, 8, 8, 8).into(),
            12345,
            443,
            6,
        );

        let conn = Connection::new(
            SocketAddr::new(Ipv4Addr::new(192, 168, 1, 100).into(), 12345),
            SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 443),
        );

        pool.insert(key.clone(), Arc::new(conn));

        assert_eq!(pool.len(), 1);
        assert!(pool.get(&key).is_some());

        pool.remove(&key);
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test]
    async fn test_concurrent_connection_insertions() {
        use tokio::task::JoinSet;

        let pool: Arc<ConnectionPool> = Arc::new(ConnectionPool::new(10000));
        let mut join_set = JoinSet::new();

        for task_id in 0..50 {
            let pool_clone = pool.clone();
            join_set.spawn(async move {
                for i in 0..200 {
                    let key = ConnectionKey::new(
                        Ipv4Addr::new(192, 168, 1, task_id as u8).into(),
                        Ipv4Addr::new(8, 8, 8, 8).into(),
                        12345 + i,
                        443,
                        6,
                    );
                    let conn = Connection::new(
                        SocketAddr::new(Ipv4Addr::new(192, 168, 1, task_id as u8).into(), 12345 + i),
                        SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 443),
                    );
                    pool_clone.insert(key, Arc::new(conn));
                }
            });
        }

        while join_set.join_next().await.is_some() {}

        assert_eq!(pool.len(), 10000);
    }

    #[tokio::test]
    async fn test_concurrent_read_write() {
        use tokio::task::JoinSet;

        let pool: Arc<ConnectionPool> = Arc::new(ConnectionPool::new(1000));

        for i in 0..100 {
            let key = ConnectionKey::new(
                Ipv4Addr::new(192, 168, 1, 100).into(),
                Ipv4Addr::new(8, 8, 8, 8).into(),
                12345 + i,
                443,
                6,
            );
            let conn = Connection::new(
                SocketAddr::new(Ipv4Addr::new(192, 168, 1, 100).into(), 12345 + i),
                SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 443),
            );
            pool.insert(key, Arc::new(conn));
        }

        let mut join_set = JoinSet::new();

        for task_id in 0..10 {
            let pool_clone = pool.clone();
            join_set.spawn(async move {
                for i in 0..50 {
                    let key = ConnectionKey::new(
                        Ipv4Addr::new(192, 168, 1, task_id as u8).into(),
                        Ipv4Addr::new(8, 8, 8, 8).into(),
                        20000 + i,
                        443,
                        6,
                    );
                    let conn = Connection::new(
                        SocketAddr::new(Ipv4Addr::new(192, 168, 1, task_id as u8).into(), 20000 + i),
                        SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 443),
                    );
                    pool_clone.insert(key, Arc::new(conn));
                }
            });
        }

        for _ in 0..10 {
            let pool_clone = pool.clone();
            join_set.spawn(async move {
                for _ in 0..100 {
                    let key = ConnectionKey::new(
                        Ipv4Addr::new(192, 168, 1, 100).into(),
                        Ipv4Addr::new(8, 8, 8, 8).into(),
                        12345,
                        443,
                        6,
                    );
                    let _ = pool_clone.get(&key);
                    sleep(Duration::from_micros(1)).await;
                }
            });
        }

        while join_set.join_next().await.is_some() {}
        assert_eq!(pool.len(), 600);
    }

    #[tokio::test]
    async fn test_rule_engine_many_rules() {
        let mut group = RuleGroup::default();
        group.name = "stress_test".to_string();

        for i in 0..10000 {
            group.rules.push(Rule::Domain(DomainRule {
                pattern: format!("domain{}.example.com", i),
                action: if i % 2 == 0 {
                    RuleMatchAction::Allow
                } else {
                    RuleMatchAction::Deny
                },
            }));
        }

        let config = RuleEngineConfig {
            groups: vec![group],
            ..Default::default()
        };

        let engine = RuleEngine::new(config).expect("Failed to create engine");

        let packet = PacketInfo::new(
            Ipv4Addr::new(192, 168, 1, 100).into(),
            Ipv4Addr::new(8, 8, 8, 8).into(),
            12345,
            443,
            6,
        );

        let mut early_packet = packet.clone();
        early_packet.destination_domain = Some("domain0.example.com".to_string());
        let result = engine.match_packet(&early_packet);
        assert!(result.is_allow());

        let mut mid_packet = packet.clone();
        mid_packet.destination_domain = Some("domain5000.example.com".to_string());
        let result = engine.match_packet(&mid_packet);
        assert!(result.is_deny());
    }

    #[tokio::test]
    async fn test_rule_engine_concurrent_matching() {
        use tokio::task::JoinSet;

        let mut group = RuleGroup::default();
        for i in 0..1000 {
            group.rules.push(Rule::IpCidr(IpCidrRule {
                cidr: format!("{}.{}.{}.0/24", i / 256, i % 256, 0),
                action: RuleMatchAction::Allow,
            }));
        }

        let config = RuleEngineConfig {
            groups: vec![group],
            ..Default::default()
        };

        let engine = Arc::new(RuleEngine::new(config).expect("Failed to create engine"));
        let mut join_set = JoinSet::new();

        for task_id in 0..20 {
            let engine_clone = engine.clone();
            join_set.spawn(async move {
                for i in 0..100 {
                    let mut packet = PacketInfo::new(
                        Ipv4Addr::new(192, 168, 1, 100).into(),
                        Ipv4Addr::new(8, 8, 8, 8).into(),
                        12345 + i,
                        443,
                        6,
                    );
                    packet.source_ip = Ipv4Addr::new(task_id as u8, (i / 256) as u8, (i % 256) as u8, 1).into();
                    let _ = engine_clone.match_packet(&packet);
                }
            });
        }

        while join_set.join_next().await.is_some() {}
    }

    #[tokio::test]
    async fn test_connection_expiration() {
        let pool = ConnectionPool::new(100);

        let key = ConnectionKey::new(
            Ipv4Addr::new(192, 168, 1, 100).into(),
            Ipv4Addr::new(8, 8, 8, 8).into(),
            12345,
            443,
            6,
        );

        let conn = Connection::new(
            SocketAddr::new(Ipv4Addr::new(192, 168, 1, 100).into(), 12345),
            SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 443),
        );

        pool.insert_with_ttl(key.clone(), Arc::new(conn), Duration::from_millis(50));

        assert_eq!(pool.len(), 1);

        sleep(Duration::from_millis(100)).await;

        pool.clear_expired();
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test]
    async fn test_connection_pool_max_size_enforcement() {
        let pool = ConnectionPool::new(10);

        for i in 0..20 {
            let key = ConnectionKey::new(
                Ipv4Addr::new(192, 168, 1, (i % 255) as u8).into(),
                Ipv4Addr::new(8, 8, 8, 8).into(),
                12345 + i,
                443,
                6,
            );
            let conn = Connection::new(
                SocketAddr::new(Ipv4Addr::new(192, 168, 1, (i % 255) as u8).into(), 12345 + i),
                SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 443),
            );
            pool.insert(key, Arc::new(conn));
        }

        assert!(pool.len() <= 15);
    }

    #[tokio::test]
    #[ignore]
    async fn test_thirty_second_memory_stability() {
        let pool: Arc<ConnectionPool> = Arc::new(ConnectionPool::new(1000));

        let start = std::time::Instant::now();

        let mut iteration = 0u64;
        while start.elapsed() < Duration::from_secs(30) {
            for i in 0..10 {
                let key = ConnectionKey::new(
                    Ipv4Addr::new(192, 168, 1, ((iteration + i) % 255) as u8).into(),
                    Ipv4Addr::new(8, 8, 8, 8).into(),
                    10000 + i,
                    443,
                    6,
                );
                let conn = Connection::new(
                    SocketAddr::new(Ipv4Addr::new(192, 168, 1, ((iteration + i) % 255) as u8).into(), 10000 + i),
                    SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 443),
                );
                pool.insert(key, Arc::new(conn));
            }

            iteration += 1;
            sleep(Duration::from_millis(100)).await;
        }

        pool.clear();
    }

    #[tokio::test]
    #[ignore]
    async fn test_config_hot_reload_stability() {
        for reload in 0..10 {
            let mut group = RuleGroup::default();
            group.name = format!("reload_{}", reload);

            for i in 0..100 {
                group.rules.push(Rule::Domain(DomainRule {
                    pattern: format!("domain{}_{}.com", reload, i),
                    action: RuleMatchAction::Allow,
                }));
            }

            let config = RuleEngineConfig {
                groups: vec![group],
                ..Default::default()
            };

            let _engine = RuleEngine::new(config).expect("Failed to create engine");

            sleep(Duration::from_millis(500)).await;
        }
    }

    #[tokio::test]
    async fn test_ipv6_connections() {
        let pool = ConnectionPool::new(100);

        let key = ConnectionKey::new(
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001).into(),
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0x0000, 0x0000, 0x0000, 0x0000, 0x0002).into(),
            12345,
            443,
            6,
        );

        let conn = Connection::new(
            SocketAddr::new(
                Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001).into(),
                12345,
            ),
            SocketAddr::new(
                Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0x0000, 0x0000, 0x0000, 0x0000, 0x0002).into(),
                443,
            ),
        );

        pool.insert(key, Arc::new(conn));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_packet_info_creation() {
        let packet = PacketInfo::new(
            Ipv4Addr::new(192, 168, 1, 100).into(),
            Ipv4Addr::new(8, 8, 8, 8).into(),
            12345,
            443,
            6,
        );

        assert_eq!(packet.source_ip, Ipv4Addr::new(192, 168, 1, 100).into());
        assert_eq!(packet.destination_ip, Ipv4Addr::new(8, 8, 8, 8).into());
        assert_eq!(packet.src_port, 12345);
        assert_eq!(packet.dst_port, 443);
        assert_eq!(packet.protocol, 6);
    }

    #[test]
    fn test_packet_info_with_domain() {
        let packet = PacketInfo::new(
            Ipv4Addr::new(192, 168, 1, 100).into(),
            Ipv4Addr::new(8, 8, 8, 8).into(),
            12345,
            443,
            6,
        )
        .with_domain("example.com");

        assert_eq!(packet.destination_domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_packet_info_with_geoip() {
        let packet = PacketInfo::new(
            Ipv4Addr::new(192, 168, 1, 100).into(),
            Ipv4Addr::new(8, 8, 8, 8).into(),
            12345,
            443,
            6,
        )
        .with_geoip("US");

        assert_eq!(packet.geoip_country, Some("US".to_string()));
    }
}
