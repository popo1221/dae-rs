//! Integration tests for dae-proxy
//!
//! Basic functionality tests that verify the proxy components work correctly.

#[cfg(test)]
mod integration_tests {
    use dae_proxy::{
        RuleEngine, RuleEngineConfig, RuleAction, Rule,
        RuleGroup, RuleMatchAction, DomainRule, IpCidrRule,
        Socks5Handler,
        ConnectionPool, ConnectionKey,
        TrojanServerConfig, TrojanTlsConfig,
        Protocol,
    };
    use dae_proxy::socks5::Socks5HandlerConfig;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn test_socks5_handler_creation() {
        let config = Socks5HandlerConfig::default();
        let _handler = Socks5Handler::new(config);
        // Handler created successfully
        assert!(true);
    }

    #[tokio::test]
    async fn test_socks5_handler_no_auth() {
        let _handler = Socks5Handler::new_no_auth();
        // Handler created successfully
        assert!(true);
    }

    #[tokio::test]
    async fn test_rule_engine_config_default() {
        let config = RuleEngineConfig::default();
        assert!(config.geoip_enabled);
        assert!(!config.process_matching_enabled);
        assert!(!config.hot_reload_enabled);
    }

    #[tokio::test]
    async fn test_rule_group_creation() {
        let mut group = RuleGroup::new("test_group");
        group.add_rule(Rule::new(
            "domain",
            "test.com",
            RuleMatchAction::Drop,
            10,
        ).expect("Failed to create rule"));
        
        assert_eq!(group.name, "test_group");
        assert_eq!(group.rules.len(), 1);
        assert_eq!(group.default_action, RuleMatchAction::Proxy);
    }

    #[tokio::test]
    async fn test_rule_with_action_creation() {
        let rule = Rule::new(
            "domain",
            "example.com",
            RuleMatchAction::Pass,
            10,
        );
        assert!(rule.is_ok());
        let rule = rule.unwrap();
        assert_eq!(rule.action, RuleMatchAction::Pass);
    }

    #[tokio::test]
    async fn test_domain_rule_matching() {
        let rule = DomainRule::new("example.com");
        let mut packet = dae_proxy::PacketInfo::default();
        packet.destination_domain = Some("example.com".to_string());
        
        assert!(rule.matches_packet(&packet));
    }

    #[tokio::test]
    async fn test_ip_cidr_rule_matching() {
        let rule = IpCidrRule::new("10.0.0.0/8").expect("Invalid CIDR");
        let mut packet = dae_proxy::PacketInfo::default();
        packet.destination_ip = Ipv4Addr::new(10, 0, 1, 100).into();
        
        assert!(rule.matches_packet(&packet));
    }

    #[tokio::test]
    async fn test_ip_cidr_rule_no_match() {
        let rule = IpCidrRule::new("10.0.0.0/8").expect("Invalid CIDR");
        let mut packet = dae_proxy::PacketInfo::default();
        packet.destination_ip = Ipv4Addr::new(192, 168, 1, 100).into();
        
        assert!(!rule.matches_packet(&packet));
    }

    #[tokio::test]
    async fn test_packet_info_default() {
        let packet = dae_proxy::PacketInfo::default();
        assert_eq!(packet.src_port, 0);
        assert_eq!(packet.dst_port, 0);
        assert!(packet.destination_domain.is_none());
    }

    #[tokio::test]
    async fn test_packet_info_ipv6() {
        let mut packet = dae_proxy::PacketInfo::default();
        packet.source_ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into();
        packet.destination_ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2).into();
        
        assert!(packet.source_ip.is_ipv6());
        assert!(packet.destination_ip.is_ipv6());
    }

    #[tokio::test]
    async fn test_trojan_server_config() {
        let config = TrojanServerConfig {
            addr: "example.com".to_string(),
            port: 443,
            password: "test-password".to_string(),
            tls: TrojanTlsConfig::default(),
        };
        
        assert_eq!(config.addr, "example.com");
        assert_eq!(config.port, 443);
    }

    #[tokio::test]
    async fn test_connection_pool_creation() {
        let pool = ConnectionPool::new(
            Duration::from_secs(60),
            Duration::from_secs(30),
            Duration::from_secs(10),
        );
        let len = pool.len().await;
        assert_eq!(len, 0);
    }

    #[tokio::test]
    async fn test_connection_key_tcp() {
        let key = ConnectionKey::new(
            SocketAddr::new(Ipv4Addr::new(192, 168, 1, 100).into(), 12345),
            SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 443),
            Protocol::Tcp,
        );
        assert_eq!(key.src_port, 12345);
        assert_eq!(key.dst_port, 443);
    }

    #[tokio::test]
    async fn test_connection_key_udp() {
        let key = ConnectionKey::new(
            SocketAddr::new(Ipv4Addr::new(192, 168, 1, 100).into(), 12345),
            SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 53),
            Protocol::Udp,
        );
        assert_eq!(key.src_port, 12345);
        assert_eq!(key.dst_port, 53);
    }

    #[tokio::test]
    async fn test_rule_match_action_conversion() {
        assert_eq!(RuleMatchAction::Pass.to_action(), RuleAction::Pass);
        assert_eq!(RuleMatchAction::Proxy.to_action(), RuleAction::Proxy);
        assert_eq!(RuleMatchAction::Drop.to_action(), RuleAction::Drop);
    }

    #[tokio::test]
    async fn test_rule_engine_default_action_proxy() {
        let config = RuleEngineConfig {
            geoip_enabled: false,
            geoip_db_path: None,
            process_matching_enabled: false,
            default_action: RuleAction::Proxy,
            hot_reload_enabled: false,
            reload_interval_secs: 60,
        };

        let engine = RuleEngine::new(config);
        let packet = dae_proxy::PacketInfo::default();
        let result = engine.match_packet(&packet).await;
        assert_eq!(result, RuleAction::Proxy);
    }

    #[tokio::test]
    async fn test_rule_engine_default_action_drop() {
        let config = RuleEngineConfig {
            geoip_enabled: false,
            geoip_db_path: None,
            process_matching_enabled: false,
            default_action: RuleAction::Drop,
            hot_reload_enabled: false,
            reload_interval_secs: 60,
        };

        let engine = RuleEngine::new(config);
        let packet = dae_proxy::PacketInfo::default();
        let result = engine.match_packet(&packet).await;
        assert_eq!(result, RuleAction::Drop);
    }

    #[tokio::test]
    async fn test_concurrent_rule_matching() {
        use tokio::task::JoinSet;

        let config = RuleEngineConfig {
            geoip_enabled: false,
            geoip_db_path: None,
            process_matching_enabled: false,
            default_action: RuleAction::Proxy,
            hot_reload_enabled: false,
            reload_interval_secs: 60,
        };

        let engine = Arc::new(RuleEngine::new(config));
        let mut join_set = JoinSet::new();

        for i in 0..10 {
            let engine = engine.clone();
            join_set.spawn(async move {
                let mut packet = dae_proxy::PacketInfo::default();
                packet.src_port = 12345 + i as u16;
                engine.match_packet(&packet).await
            });
        }

        let mut results = Vec::new();
        while let Some(res) = join_set.join_next().await {
            results.push(res.expect("Task panicked"));
        }
        
        assert_eq!(results.len(), 10);
    }

    #[tokio::test]
    async fn test_rule_action_direct() {
        let config = RuleEngineConfig {
            geoip_enabled: false,
            geoip_db_path: None,
            process_matching_enabled: false,
            default_action: RuleAction::Direct,
            hot_reload_enabled: false,
            reload_interval_secs: 60,
        };

        let engine = RuleEngine::new(config);
        let packet = dae_proxy::PacketInfo::default();
        let result = engine.match_packet(&packet).await;
        assert_eq!(result, RuleAction::Direct);
    }
}
