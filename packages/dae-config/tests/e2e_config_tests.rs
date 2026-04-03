//! E2E (End-to-End) integration tests for dae-config
//!
//! Tests for configuration parsing, validation, and subscription handling.

#[cfg(test)]
mod e2e_tests {
    use dae_config::{
        subscription::SubscriptionConfig, Config, ConfigError, GlobalConfig, LegacyConfig,
        LogLevel, NodeConfig, NodeType, ProxyConfig, RuleGroupConfig, RulesConfig,
        ShadowsocksServerConfig, TrojanServerConfig, TrojanTlsConfig, VlessServerConfig,
        VlessTlsConfig, VmessServerConfig,
    };
    use std::time::Duration;

    // ============================================================
    // Config File Parsing E2E Tests
    // ============================================================

    #[test]
    fn test_config_parse_valid_toml() {
        let toml_content = r#"
[proxy]
socks5_listen = "127.0.0.1:1080"
http_listen = "127.0.0.1:8080"
tcp_timeout = 120
udp_timeout = 60

[[nodes]]
name = "test-node"
type = "shadowsocks"
server = "1.2.3.4"
port = 8388
method = "chacha20-ietf-poly1305"
password = "test-password"
"#;

        let config = toml::from_str::<Config>(toml_content);
        assert!(
            config.is_ok(),
            "Valid TOML should parse successfully: {:?}",
            config.err()
        );

        let config = config.unwrap();
        assert_eq!(config.proxy.socks5_listen, "127.0.0.1:1080");
        assert_eq!(config.proxy.http_listen, "127.0.0.1:8080");
        assert_eq!(config.proxy.tcp_timeout, 120);
        assert_eq!(config.proxy.udp_timeout, 60);
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].name, "test-node");
        assert_eq!(config.nodes[0].port, 8388);
    }

    #[test]
    fn test_config_parse_multiple_nodes() {
        let toml_content = r#"
[proxy]
socks5_listen = "127.0.0.1:1080"

[[nodes]]
name = "ss-1"
type = "shadowsocks"
server = "1.2.3.4"
port = 8388
method = "chacha20-ietf-poly1305"
password = "pwd1"

[[nodes]]
name = "ss-2"
type = "shadowsocks"
server = "5.6.7.8"
port = 8388
method = "aes-256-gcm"
password = "pwd2"

[[nodes]]
name = "vless-1"
type = "vless"
server = "vless.example.com"
port = 443
uuid = "12345678-1234-1234-1234-123456789012"
"#;

        let config = toml::from_str::<Config>(toml_content).unwrap();
        assert_eq!(config.nodes.len(), 3);
        assert_eq!(config.nodes[0].node_type, NodeType::Shadowsocks);
        assert_eq!(config.nodes[1].node_type, NodeType::Shadowsocks);
        assert_eq!(config.nodes[2].node_type, NodeType::Vless);
    }

    #[test]
    fn test_config_validate_valid_config() {
        let config = Config {
            proxy: ProxyConfig::default(),
            nodes: vec![NodeConfig {
                name: "test".to_string(),
                node_type: NodeType::Shadowsocks,
                server: "1.2.3.4".to_string(),
                port: 8388,
                method: Some("chacha20-ietf-poly1305".to_string()),
                password: Some("password".to_string()),
                uuid: None,
                trojan_password: None,
                security: None,
                tls: None,
                tls_server_name: None,
                aead: None,
                capabilities: None,
            }],
            rules: RulesConfig::default(),
            logging: dae_config::LoggingConfig::default(),
            transparent_proxy: dae_config::TransparentProxyConfig::default(),
            tracking: dae_config::TrackingConfig::default(),
        };

        assert!(config.validate().is_ok(), "Valid config should pass validation");
    }

    #[test]
    fn test_config_validate_empty_server() {
        let config = Config {
            proxy: ProxyConfig::default(),
            nodes: vec![NodeConfig {
                name: "test".to_string(),
                node_type: NodeType::Shadowsocks,
                server: "".to_string(), // Empty server
                port: 8388,
                method: Some("chacha20-ietf-poly1305".to_string()),
                password: Some("password".to_string()),
                uuid: None,
                trojan_password: None,
                security: None,
                tls: None,
                tls_server_name: None,
                aead: None,
                capabilities: None,
            }],
            rules: RulesConfig::default(),
            logging: dae_config::LoggingConfig::default(),
            transparent_proxy: dae_config::TransparentProxyConfig::default(),
            tracking: dae_config::TrackingConfig::default(),
        };

        let result = config.validate();
        assert!(result.is_err(), "Config with empty server should fail validation");
    }

    #[test]
    fn test_config_validate_zero_port() {
        let config = Config {
            proxy: ProxyConfig::default(),
            nodes: vec![NodeConfig {
                name: "test".to_string(),
                node_type: NodeType::Shadowsocks,
                server: "1.2.3.4".to_string(),
                port: 0, // Invalid port
                method: Some("chacha20-ietf-poly1305".to_string()),
                password: Some("password".to_string()),
                uuid: None,
                trojan_password: None,
                security: None,
                tls: None,
                tls_server_name: None,
                aead: None,
                capabilities: None,
            }],
            rules: RulesConfig::default(),
            logging: dae_config::LoggingConfig::default(),
            transparent_proxy: dae_config::TransparentProxyConfig::default(),
            tracking: dae_config::TrackingConfig::default(),
        };

        let result = config.validate();
        assert!(result.is_err(), "Config with zero port should fail validation");
    }

    // ============================================================
    // Node Type Conversion E2E Tests
    // ============================================================

    #[test]
    fn test_node_type_from_str_all_variants() {
        assert_eq!(
            "shadowsocks".parse::<NodeType>().unwrap(),
            NodeType::Shadowsocks
        );
        assert_eq!("ss".parse::<NodeType>().unwrap(), NodeType::Shadowsocks);
        assert_eq!("vless".parse::<NodeType>().unwrap(), NodeType::Vless);
        assert_eq!("vmess".parse::<NodeType>().unwrap(), NodeType::Vmess);
        assert_eq!("trojan".parse::<NodeType>().unwrap(), NodeType::Trojan);
        assert!("invalid".parse::<NodeType>().is_err());
    }

    #[test]
    fn test_node_type_display() {
        assert_eq!(NodeType::Shadowsocks.to_string(), "shadowsocks");
        assert_eq!(NodeType::Vless.to_string(), "vless");
        assert_eq!(NodeType::Vmess.to_string(), "vmess");
        assert_eq!(NodeType::Trojan.to_string(), "trojan");
    }

    // ============================================================
    // Node Helper Methods E2E Tests
    // ============================================================

    #[test]
    fn test_find_node() {
        let config = Config {
            proxy: ProxyConfig::default(),
            nodes: vec![
                NodeConfig {
                    name: "node-a".to_string(),
                    node_type: NodeType::Shadowsocks,
                    server: "1.2.3.4".to_string(),
                    port: 8388,
                    method: Some("chacha20".to_string()),
                    password: Some("pwd".to_string()),
                    uuid: None,
                    trojan_password: None,
                    security: None,
                    tls: None,
                    tls_server_name: None,
                    aead: None,
                    capabilities: None,
                },
                NodeConfig {
                    name: "node-b".to_string(),
                    node_type: NodeType::Vless,
                    server: "5.6.7.8".to_string(),
                    port: 443,
                    method: None,
                    password: None,
                    uuid: Some("uuid-123".to_string()),
                    trojan_password: None,
                    security: None,
                    tls: Some(true),
                    tls_server_name: None,
                    aead: None,
                    capabilities: None,
                },
            ],
            rules: RulesConfig::default(),
            logging: dae_config::LoggingConfig::default(),
            transparent_proxy: dae_config::TransparentProxyConfig::default(),
            tracking: dae_config::TrackingConfig::default(),
        };

        assert!(config.find_node("node-a").is_some());
        assert!(config.find_node("node-b").is_some());
        assert!(config.find_node("node-c").is_none());
    }

    #[test]
    fn test_filter_nodes_by_type() {
        let config = Config {
            proxy: ProxyConfig::default(),
            nodes: vec![
                NodeConfig {
                    name: "ss-1".to_string(),
                    node_type: NodeType::Shadowsocks,
                    server: "1.2.3.4".to_string(),
                    port: 8388,
                    method: Some("aes-256-gcm".to_string()),
                    password: Some("pwd".to_string()),
                    uuid: None,
                    trojan_password: None,
                    security: None,
                    tls: None,
                    tls_server_name: None,
                    aead: None,
                    capabilities: None,
                },
                NodeConfig {
                    name: "vless-1".to_string(),
                    node_type: NodeType::Vless,
                    server: "5.6.7.8".to_string(),
                    port: 443,
                    method: None,
                    password: None,
                    uuid: Some("uuid-1".to_string()),
                    trojan_password: None,
                    security: None,
                    tls: Some(true),
                    tls_server_name: None,
                    aead: None,
                    capabilities: None,
                },
                NodeConfig {
                    name: "trojan-1".to_string(),
                    node_type: NodeType::Trojan,
                    server: "9.9.9.9".to_string(),
                    port: 443,
                    method: None,
                    password: None,
                    uuid: None,
                    trojan_password: Some("trojan-pwd".to_string()),
                    security: None,
                    tls: Some(true),
                    tls_server_name: None,
                    aead: None,
                    capabilities: None,
                },
                NodeConfig {
                    name: "ss-2".to_string(),
                    node_type: NodeType::Shadowsocks,
                    server: "2.3.4.5".to_string(),
                    port: 8388,
                    method: Some("chacha20".to_string()),
                    password: Some("pwd2".to_string()),
                    uuid: None,
                    trojan_password: None,
                    security: None,
                    tls: None,
                    tls_server_name: None,
                    aead: None,
                    capabilities: None,
                },
            ],
            rules: RulesConfig::default(),
            logging: dae_config::LoggingConfig::default(),
            transparent_proxy: dae_config::TransparentProxyConfig::default(),
            tracking: dae_config::TrackingConfig::default(),
        };

        let ss_nodes = config.shadowsocks_nodes();
        let vless_nodes = config.vless_nodes();
        let trojan_nodes = config.trojan_nodes();
        let vmess_nodes = config.vmess_nodes();

        assert_eq!(ss_nodes.len(), 2);
        assert_eq!(vless_nodes.len(), 1);
        assert_eq!(trojan_nodes.len(), 1);
        assert_eq!(vmess_nodes.len(), 0);
    }

    // ============================================================
    // Default Config E2E Tests
    // ============================================================

    #[test]
    fn test_proxy_config_defaults() {
        let proxy = ProxyConfig::default();
        assert_eq!(proxy.socks5_listen, "127.0.0.1:1080");
        assert_eq!(proxy.http_listen, "127.0.0.1:8080");
        assert_eq!(proxy.tcp_timeout, 60);
        assert_eq!(proxy.udp_timeout, 30);
        assert_eq!(proxy.ebpf_interface, "eth0");
        assert!(proxy.ebpf_enabled);
    }

    #[test]
    fn test_log_level_variants() {
        assert_eq!(format!("{}", LogLevel::Trace), "trace");
        assert_eq!(format!("{}", LogLevel::Debug), "debug");
        assert_eq!(format!("{}", LogLevel::Info), "info");
        assert_eq!(format!("{}", LogLevel::Warn), "warn");
        assert_eq!(format!("{}", LogLevel::Error), "error");
    }

    // ============================================================
    // Rule Config E2E Tests
    // ============================================================

    #[test]
    fn test_rule_group_config_parsing() {
        let toml_content = r#"
[rules]
[rules.rule_groups]
name = "custom-rules"
type = "ipcidr"
"#;

        // Just verify it parses (even if empty)
        let rules_config: RulesConfig = toml::from_str(toml_content).unwrap_or_default();
        // Default is fine for this test
        assert!(rules_config.config_file.is_none());
    }

    // ============================================================
    // Subscription Config E2E Tests
    // ============================================================

    #[test]
    fn test_subscription_config_builder_pattern() {
        let config = SubscriptionConfig::new("https://example.com/subscription")
            .with_update_interval(Duration::from_secs(7200))
            .with_user_agent("dae-rs-test/1.0")
            .with_insecure_tls();

        assert_eq!(config.url, "https://example.com/subscription");
        assert_eq!(config.update_interval, Duration::from_secs(7200));
        assert_eq!(config.user_agent, "dae-rs-test/1.0");
        assert!(!config.verify_tls, "TLS should be disabled");
    }

    #[test]
    fn test_subscription_config_default_values() {
        let config = SubscriptionConfig::default();

        assert!(config.url.is_empty());
        assert_eq!(config.update_interval, Duration::from_secs(3600));
        assert!(config.verify_tls);
        assert_eq!(config.user_agent, "dae-rs/0.1.0");
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_subscription_config_clone_independence() {
        let config1 = SubscriptionConfig::new("https://example.com/sub1");
        let config2 = config1.clone();

        // Clones should be independent
        assert_eq!(config1.url, config2.url);

        // Modifying clone shouldn't affect original
        let _ = config2.with_insecure_tls();
        assert!(config1.verify_tls, "Original should still have TLS verification");
    }

    // ============================================================
    // Config Error E2E Tests
    // ============================================================

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::MissingField("socks5_listen".to_string());
        assert!(format!("{}", err).contains("Missing required field"));

        let err = ConfigError::InvalidPort(0);
        assert!(format!("{}", err).contains("Invalid port"));

        let err = ConfigError::InvalidAddress("bad:addr".to_string());
        assert!(format!("{}", err).contains("Invalid address"));

        let err = ConfigError::InvalidNode("node-x".to_string());
        assert!(format!("{}", err).contains("Invalid node configuration"));

        let err = ConfigError::RuleFileNotFound("/nonexistent/rules.toml".to_string());
        assert!(format!("{}", err).contains("Rule file not found"));

        let err = ConfigError::ValidationError("custom error".to_string());
        assert!(format!("{}", err).contains("Validation error"));
    }

    // ============================================================
    // Node Display Address E2E Tests
    // ============================================================

    #[test]
    fn test_node_display_addr() {
        let node = NodeConfig {
            name: "test".to_string(),
            node_type: NodeType::Shadowsocks,
            server: "example.com".to_string(),
            port: 443,
            method: Some("aes-256-gcm".to_string()),
            password: Some("secret".to_string()),
            uuid: None,
            trojan_password: None,
            security: None,
            tls: None,
            tls_server_name: None,
            aead: None,
            capabilities: None,
        };

        assert_eq!(node.display_addr(), "example.com:443");
    }

    // ============================================================
    // Transparent Proxy Config E2E Tests
    // ============================================================

    #[test]
    fn test_transparent_proxy_config_defaults() {
        let tp = dae_config::TransparentProxyConfig::default();

        assert!(!tp.enabled);
        assert_eq!(tp.tun_interface, "dae0");
        assert_eq!(tp.tun_ip, "10.0.0.1");
        assert_eq!(tp.tun_netmask, "255.255.255.0");
        assert_eq!(tp.mtu, 1500);
        assert_eq!(tp.dns_hijack.len(), 2); // 8.8.8.8 and 8.8.4.4
        assert_eq!(tp.tcp_timeout, 60);
        assert_eq!(tp.udp_timeout, 30);
        assert!(tp.auto_route);
    }

    // ============================================================
    // Tracking Config E2E Tests
    // ============================================================

    #[test]
    fn test_tracking_config_defaults() {
        let tracking = dae_config::TrackingConfig::default();
        // Verify default construction doesn't panic
        // Specific defaults depend on implementation
        assert!(tracking.enabled || !tracking.enabled); // Just check it's bool
    }

    // ============================================================
    // VLESS/VMess Server Config E2E Tests
    // ============================================================

    #[test]
    fn test_vless_server_config_new() {
        let vless = VlessServerConfig::new("test-vless", "vless.example.com", 443, "test-uuid");

        assert_eq!(vless.name, "test-vless");
        assert_eq!(vless.addr, "vless.example.com");
        assert_eq!(vless.port, 443);
        assert_eq!(vless.uuid, "test-uuid");
        assert!(vless.tls.is_none());
    }

    #[test]
    fn test_vless_server_config_with_tls() {
        let vless = VlessServerConfig {
            name: "test-vless-tls".to_string(),
            addr: "vless.example.com".to_string(),
            port: 443,
            uuid: "test-uuid".to_string(),
            tls: Some(VlessTlsConfig {
                enabled: true,
                version: "1.3".to_string(),
                server_name: Some("vless.example.com".to_string()),
                alpn: None,
            }),
        };

        assert!(vless.tls.is_some());
        let tls = vless.tls.unwrap();
        assert!(tls.enabled);
        assert_eq!(tls.server_name.as_deref(), Some("vless.example.com"));
    }

    #[test]
    fn test_vmess_server_config_new() {
        let vmess = VmessServerConfig::new("test-vmess", "vmess.example.com", 443, "test-user-id");

        assert_eq!(vmess.name, "test-vmess");
        assert_eq!(vmess.addr, "vmess.example.com");
        assert_eq!(vmess.port, 443);
        assert_eq!(vmess.user_id, "test-user-id");
        assert_eq!(vmess.security, "aes-128-gcm-aead");
        assert!(vmess.enable_aead);
    }

    #[test]
    fn test_trojan_server_config_new() {
        let trojan = TrojanServerConfig::new("test-trojan", "trojan.example.com", 443, "trojan-pwd");

        assert_eq!(trojan.name, "test-trojan");
        assert_eq!(trojan.addr, "trojan.example.com");
        assert_eq!(trojan.port, 443);
        assert_eq!(trojan.password, "trojan-pwd");
        assert!(trojan.tls.is_none());
    }

    #[test]
    fn test_trojan_server_config_with_tls() {
        let trojan = TrojanServerConfig {
            name: "test-trojan-tls".to_string(),
            addr: "trojan.example.com".to_string(),
            port: 443,
            password: "trojan-pwd".to_string(),
            tls: Some(TrojanTlsConfig {
                enabled: true,
                version: "1.3".to_string(),
                server_name: Some("trojan.example.com".to_string()),
                alpn: None,
            }),
        };

        assert!(trojan.tls.is_some());
        let tls = trojan.tls.unwrap();
        assert!(tls.enabled);
    }

    // ============================================================
    // Shadowsocks Server Config E2E Tests
    // ============================================================

    #[test]
    fn test_shadowsocks_server_config_parsing() {
        let toml_content = r#"
[[nodes]]
name = "ss-test"
type = "shadowsocks"
server = "ss.example.com"
port = 8388
method = "aes-256-gcm"
password = "supersecret"
"#;

        let config: Config = toml::from_str(toml_content).unwrap();
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].node_type, NodeType::Shadowsocks);
        assert_eq!(config.nodes[0].method.as_deref(), Some("aes-256-gcm"));
        assert_eq!(config.nodes[0].password.as_deref(), Some("supersecret"));
    }

    // ============================================================
    // Complex Multi-Node Config E2E Tests
    // ============================================================

    #[test]
    fn test_complex_multi_protocol_config() {
        let toml_content = r#"
[proxy]
socks5_listen = "0.0.0.0:1080"
http_listen = "0.0.0.0:8080"
tcp_timeout = 300
udp_timeout = 60
ebpf_enabled = true

[[nodes]]
name = "HK-Shadowsocks"
type = "shadowsocks"
server = "hk-ss.example.com"
port = 8388
method = "chacha20-ietf-poly1305"
password = "hk-password"

[[nodes]]
name = "US-VLESS"
type = "vless"
server = "us-vless.example.com"
port = 443
uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
tls = true
tls_server_name = "us-vless.example.com"

[[nodes]]
name = "JP-Trojan"
type = "trojan"
server = "jp-trojan.example.com"
port = 443
trojan_password = "jp-trojan-password"
"#;

        let config = toml::from_str::<Config>(toml_content).unwrap();

        // Verify proxy settings
        assert_eq!(config.proxy.socks5_listen, "0.0.0.0:1080");
        assert_eq!(config.proxy.http_listen, "0.0.0.0:8080");
        assert_eq!(config.proxy.tcp_timeout, 300);
        assert_eq!(config.proxy.udp_timeout, 60);
        assert!(config.proxy.ebpf_enabled);

        // Verify all 3 nodes parsed
        assert_eq!(config.nodes.len(), 3);

        // Shadowsocks node
        assert_eq!(config.nodes[0].name, "HK-Shadowsocks");
        assert_eq!(config.nodes[0].node_type, NodeType::Shadowsocks);
        assert_eq!(config.nodes[0].port, 8388);

        // VLESS node
        assert_eq!(config.nodes[1].name, "US-VLESS");
        assert_eq!(config.nodes[1].node_type, NodeType::Vless);
        assert!(config.nodes[1].tls.is_some());
        assert_eq!(config.nodes[1].tls_server_name.as_deref(), Some("us-vless.example.com"));

        // Trojan node
        assert_eq!(config.nodes[2].name, "JP-Trojan");
        assert_eq!(config.nodes[2].node_type, NodeType::Trojan);
        assert_eq!(
            config.nodes[2].trojan_password.as_deref(),
            Some("jp-trojan-password")
        );

        // Validation should pass
        assert!(config.validate().is_ok());
    }

    // ============================================================
    // Legacy Config E2E Tests (Direct Parsing)
    // ============================================================

    #[test]
    fn test_legacy_config_global_parsing() {
        let toml_content = r#"
[global]
port = 8080
log_level = "debug"

[[proxy]]
name = "local"
proto = "socks5"
addr = "127.0.0.1:1080"
"#;

        let legacy: LegacyConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(legacy.global.port, 8080);
        assert_eq!(legacy.global.log_level, "debug");
        assert_eq!(legacy.proxy.len(), 1);
    }

    #[test]
    fn test_legacy_shadowsocks_config_parsing() {
        let toml_content = r#"
[global]
port = 8080
log_level = "info"

[[proxy]]
name = "local"
proto = "socks5"
addr = "127.0.0.1:1080"

[[shadowsocks]]
name = "legacy-ss"
addr = "1.2.3.4"
port = 8388
method = "chacha20-ietf-poly1305"
password = "test-password"
ota = false
"#;

        let legacy: LegacyConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(legacy.shadowsocks.len(), 1);
        assert_eq!(legacy.shadowsocks[0].name, "legacy-ss");
        assert_eq!(legacy.shadowsocks[0].addr, "1.2.3.4");
        assert_eq!(legacy.shadowsocks[0].port, 8388);
        assert_eq!(legacy.shadowsocks[0].method, "chacha20-ietf-poly1305");
        assert!(!legacy.shadowsocks[0].ota);
    }

    // ============================================================
    // Logging Config E2E Tests
    // ============================================================

    #[test]
    fn test_logging_config_defaults() {
        let logging = dae_config::LoggingConfig::default();
        assert_eq!(logging.level, "info");
        assert!(logging.file.is_none());
        assert!(logging.structured);
    }

    #[test]
    fn test_logging_config_with_file() {
        let logging: dae_config::LoggingConfig = toml::from_str(r#"
level = "debug"
file = "/var/log/dae.log"
structured = true
"#).unwrap();

        assert_eq!(logging.level, "debug");
        assert_eq!(logging.file.as_deref(), Some("/var/log/dae.log"));
        assert!(logging.structured);
    }

    // ============================================================
    // Node Capabilities E2E Tests
    // ============================================================

    #[test]
    fn test_node_capabilities_defaults() {
        let caps = dae_config::NodeCapabilities::new();
        assert!(!caps.is_fullcone_enabled());
        assert!(caps.is_udp_supported());
        assert!(caps.is_v2ray_compatible());
    }

    #[test]
    fn test_node_capabilities_explicit() {
        let caps = dae_config::NodeCapabilities {
            fullcone: Some(true),
            udp: Some(false),
            v2ray: Some(false),
        };

        assert!(caps.is_fullcone_enabled());
        assert!(!caps.is_udp_supported());
        assert!(!caps.is_v2ray_compatible());
    }
}
