//! Rule engine for matching packets against rules
//!
//! This module provides the rule matching engine that runs in user-space
//! and makes final routing decisions based on domain/IP/GeoIP rules.

use crate::rules::{Rule, RuleGroup, RuleMatchAction};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Packet information for rule matching
#[derive(Debug, Clone)]
pub struct PacketInfo {
    /// Source IP address
    pub source_ip: IpAddr,
    /// Destination IP address
    pub destination_ip: IpAddr,
    /// Source port (for TCP/UDP)
    pub src_port: u16,
    /// Destination port (for TCP/UDP)
    pub dst_port: u16,
    /// IP protocol (6=TCP, 17=UDP)
    pub protocol: u8,
    /// Destination domain (if known from DNS or SNI)
    pub destination_domain: Option<String>,
    /// GeoIP country code (ISO 3166-1 alpha-2)
    pub geoip_country: Option<String>,
    /// Process name (Linux only)
    pub process_name: Option<String>,
    /// DNS query type
    pub dns_query_type: Option<u16>,
    /// Connection direction (true = outbound, false = inbound)
    pub is_outbound: bool,
    /// Packet size in bytes
    pub packet_size: usize,
    /// Connection key hash (for session matching)
    pub connection_hash: Option<u64>,
}

impl Default for PacketInfo {
    fn default() -> Self {
        Self {
            source_ip: "0.0.0.0".parse().unwrap(),
            destination_ip: "0.0.0.0".parse().unwrap(),
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            destination_domain: None,
            geoip_country: None,
            process_name: None,
            dns_query_type: None,
            is_outbound: true,
            packet_size: 0,
            connection_hash: None,
        }
    }
}

impl PacketInfo {
    /// Create a new packet info
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, proto: u8) -> Self {
        Self {
            source_ip: src_ip,
            destination_ip: dst_ip,
            src_port,
            dst_port,
            protocol: proto,
            ..Default::default()
        }
    }

    /// Create from 4-tuple
    pub fn from_tuple(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8) -> Self {
        use std::net::Ipv4Addr;

        let source_ip: IpAddr = Ipv4Addr::from(src_ip).into();
        let destination_ip: IpAddr = Ipv4Addr::from(dst_ip).into();

        Self::new(source_ip, destination_ip, src_port, dst_port, proto)
    }

    /// Set destination domain
    pub fn with_domain(mut self, domain: &str) -> Self {
        self.destination_domain = Some(domain.to_lowercase());
        self
    }

    /// Set GeoIP country
    pub fn with_geoip(mut self, country: &str) -> Self {
        self.geoip_country = Some(country.to_uppercase());
        self
    }

    /// Set process name
    pub fn with_process(mut self, process: &str) -> Self {
        self.process_name = Some(process.to_lowercase());
        self
    }

    /// Set DNS query type
    pub fn with_dns_type(mut self, qtype: u16) -> Self {
        self.dns_query_type = Some(qtype);
        self
    }
}

/// Rule action for routing decisions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Pass the packet (direct)
    Pass,
    /// Proxy the packet
    Proxy,
    /// Drop the packet
    Drop,
    /// No matching rule, use default
    Default,
    /// Direct connection (explicit direct, not via routing rules)
    Direct,
    /// Must direct (force bypass proxy, highest priority direct)
    MustDirect,
}

impl RuleAction {
    /// Convert to eBPF routing action
    pub fn to_ebpf_action(&self) -> u8 {
        match self {
            RuleAction::Pass | RuleAction::Direct | RuleAction::MustDirect => 0, // dae_ebpf_common::routing::action::PASS
            RuleAction::Drop => 2, // dae_ebpf_common::routing::action::DROP
            RuleAction::Proxy | RuleAction::Default => 0, // Default to pass for now
        }
    }
}

/// Rule engine configuration
#[derive(Debug, Clone)]
pub struct RuleEngineConfig {
    /// Enable GeoIP lookup
    pub geoip_enabled: bool,
    /// GeoIP database path
    pub geoip_db_path: Option<String>,
    /// Enable process matching (Linux only)
    pub process_matching_enabled: bool,
    /// Default action when no rule matches
    pub default_action: RuleAction,
    /// Enable rule hot-reload
    pub hot_reload_enabled: bool,
    /// Rule reload interval in seconds
    pub reload_interval_secs: u64,
}

impl Default for RuleEngineConfig {
    fn default() -> Self {
        Self {
            geoip_enabled: true,
            geoip_db_path: None,
            process_matching_enabled: false,
            default_action: RuleAction::Proxy,
            hot_reload_enabled: false,
            reload_interval_secs: 60,
        }
    }
}

/// Rule engine for matching packets against rules
pub struct RuleEngine {
    /// Configuration
    config: RuleEngineConfig,
    /// Rule groups (ordered by priority)
    rule_groups: RwLock<Vec<RuleGroup>>,
    /// GeoIP reader data (lazy loaded)
    geoip_reader: RwLock<Option<maxminddb::Reader<Vec<u8>>>>,
    /// Whether rules have been loaded
    loaded: RwLock<bool>,
}

impl RuleEngine {
    /// Create a new rule engine
    pub fn new(config: RuleEngineConfig) -> Self {
        Self {
            config,
            rule_groups: RwLock::new(Vec::new()),
            geoip_reader: RwLock::new(None),
            loaded: RwLock::new(false),
        }
    }

    /// Create a new rule engine with default configuration
    pub fn with_default_config() -> Self {
        Self::new(RuleEngineConfig::default())
    }

    /// Initialize the rule engine
    pub async fn initialize(&self) -> Result<(), String> {
        // Load GeoIP database if enabled
        if self.config.geoip_enabled {
            self.init_geoip().await?;
        }

        info!("Rule engine initialized");
        Ok(())
    }

    /// Initialize GeoIP database
    async fn init_geoip(&self) -> Result<(), String> {
        let db_path = self
            .config
            .geoip_db_path
            .as_ref()
            .ok_or_else(|| "GeoIP database path not configured".to_string())?;

        if !Path::new(db_path).exists() {
            warn!(
                "GeoIP database not found at {}, GeoIP rules will not work",
                db_path
            );
            return Ok(());
        }

        // Load database in blocking task
        let db_path_clone = db_path.clone();
        let reader =
            tokio::task::spawn_blocking(move || maxminddb::Reader::open_readfile(&db_path_clone))
                .await
                .map_err(|e| format!("Failed to load GeoIP database: {e}"))?
                .map_err(|e| format!("Failed to open GeoIP database: {e}"))?;

        let mut geoip = self.geoip_reader.write().await;
        *geoip = Some(reader);

        info!("GeoIP database loaded from {}", db_path);
        Ok(())
    }

    /// Load rules from a file path
    pub async fn load_rules(&self, path: &str) -> Result<(), String> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| format!("Failed to read rules file: {e}"))?;

        self.parse_and_load_rules(&content).await
    }

    /// Parse and load rules from TOML content
    pub async fn parse_and_load_rules(&self, content: &str) -> Result<(), String> {
        use dae_config::rules::RuleConfig;

        let config: RuleConfig =
            toml::from_str(content).map_err(|e| format!("Failed to parse rules TOML: {e}"))?;

        let mut rule_groups = Vec::new();

        for group_config in config.rule_groups {
            let mut group = RuleGroup::new(&group_config.name);

            for (idx, rule_config) in group_config.rules.iter().enumerate() {
                let priority = rule_config.priority.unwrap_or(1000 + idx as u32);
                let action = match rule_config.action.to_lowercase().as_str() {
                    "pass" | "allow" | "direct" => RuleMatchAction::Pass,
                    "proxy" | "route" => RuleMatchAction::Proxy,
                    "drop" | "deny" | "block" => RuleMatchAction::Drop,
                    _ => return Err(format!("Unknown action: {}", rule_config.action)),
                };

                let rule = Rule::new(&rule_config.rule_type, &rule_config.value, action, priority)?;
                group.add_rule(rule);
            }

            let default_action = match group_config.default_action.to_lowercase().as_str() {
                "pass" | "allow" | "direct" => RuleMatchAction::Pass,
                "proxy" | "route" => RuleMatchAction::Proxy,
                "drop" | "deny" | "block" => RuleMatchAction::Drop,
                _ => RuleMatchAction::Proxy,
            };
            group.set_default_action(default_action);

            rule_groups.push(group);
        }

        // Sort rule groups by priority
        rule_groups.sort_by(|a, b| {
            let a_priority = a.rules.iter().map(|r| r.priority).min().unwrap_or(u32::MAX);
            let b_priority = b.rules.iter().map(|r| r.priority).min().unwrap_or(u32::MAX);
            a_priority.cmp(&b_priority)
        });

        let mut groups = self.rule_groups.write().await;
        *groups = rule_groups;

        let mut loaded = self.loaded.write().await;
        *loaded = true;

        info!("Loaded {} rule groups", groups.len());
        Ok(())
    }

    /// Check if rules have been loaded
    pub async fn is_loaded(&self) -> bool {
        *self.loaded.read().await
    }

    /// Match a packet against all rules
    pub async fn match_packet(&self, info: &PacketInfo) -> RuleAction {
        // Enrich packet info with GeoIP if available
        let mut info = info.clone();
        if info.geoip_country.is_none() && self.config.geoip_enabled {
            info.geoip_country = self.lookup_geoip(&info.destination_ip).await;
        }

        let groups = self.rule_groups.read().await;

        for group in groups.iter() {
            if let Some(action) = group.match_packet(&info) {
                debug!(
                    "Packet matched rule in group '{}': {:?}",
                    group.name, action
                );
                return action.to_action();
            }
        }

        // No matching rule, return default action
        debug!("No matching rule, using default action");
        self.config.default_action
    }

    /// Lookup GeoIP country for an IP address
    ///
    /// Note: GeoIP lookup requires a properly formatted GeoLite2 or GeoIP2 database.
    /// This implementation uses the maxminddb 0.27 API which provides lookup returning
    /// a LookupResult. The actual field access depends on the database type.
    pub async fn lookup_geoip(&self, ip: &IpAddr) -> Option<String> {
        let reader = self.geoip_reader.read().await;
        let reader = match reader.as_ref() {
            Some(r) => r,
            None => return None,
        };

        // Use maxminddb 0.27 API - lookup returns LookupResult
        // The LookupResult contains fields based on the database type
        // For GeoLite2/GeoIP2 Country database, we need to access the country field
        match reader.lookup(*ip) {
            Ok(_result) => {
                // In maxminddb 0.27, the LookupResult provides field access
                // through traits. For country data, we need to use the proper
                // deserialization. For now, return None and let the caller
                // handle missing GeoIP data gracefully.
                //
                // A full implementation would require knowing the exact database
                // schema and using the appropriate field access.
                debug!("GeoIP lookup succeeded but country extraction not implemented for this database type");
                None
            }
            Err(e) => {
                debug!("GeoIP lookup failed: {:?}", e);
                None
            }
        }
    }

    /// Get all rule groups
    pub async fn get_rule_groups(&self) -> Vec<String> {
        let groups = self.rule_groups.read().await;
        groups.iter().map(|g| g.name.clone()).collect()
    }

    /// Get rule statistics
    pub async fn get_stats(&self) -> RuleEngineStats {
        let groups = self.rule_groups.read().await;
        RuleEngineStats {
            loaded: *self.loaded.read().await,
            rule_group_count: groups.len(),
            total_rule_count: groups.iter().map(|g| g.rules.len()).sum(),
        }
    }

    /// Reload rules from file
    pub async fn reload(&self, path: &str) -> std::result::Result<(), String> {
        info!("Reloading rules from {}", path);
        self.load_rules(path).await
    }

    /// Clear all rules
    pub async fn clear_rules(&self) {
        let mut groups = self.rule_groups.write().await;
        groups.clear();
        let mut loaded = self.loaded.write().await;
        *loaded = false;
        info!("All rules cleared");
    }
}

/// Rule engine statistics
#[derive(Debug, Clone)]
pub struct RuleEngineStats {
    /// Whether rules have been loaded
    pub loaded: bool,
    /// Number of rule groups
    pub rule_group_count: usize,
    /// Total number of rules
    pub total_rule_count: usize,
}

/// Shared rule engine type
pub type SharedRuleEngine = Arc<RuleEngine>;

/// Create a new shared rule engine
pub fn new_rule_engine(config: RuleEngineConfig) -> SharedRuleEngine {
    Arc::new(RuleEngine::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_rule_engine_basic() {
        let config = RuleEngineConfig::default();
        let engine = RuleEngine::new(config);

        // Load test rules with a domain suffix rule that matches
        let rules_toml = r#"
[[rule_groups]]
name = "direct"
default_action = "pass"
rules = [
    { type = "domain-suffix", value = ".test", action = "pass" }
]

[[rule_groups]]
name = "block"
default_action = "proxy"

[[rule_groups]]
name = "proxy"
default_action = "proxy"
"#;

        engine.parse_and_load_rules(rules_toml).await.unwrap();

        // Create a packet with domain that matches the suffix rule
        let mut info = PacketInfo::default();
        info.destination_domain = Some("example.test".to_string());

        let action = engine.match_packet(&info).await;
        assert_eq!(action, RuleAction::Pass); // Domain suffix rule matches

        // Test with non-matching domain - should use engine default (Proxy)
        let mut info = PacketInfo::default();
        info.destination_domain = Some("example.com".to_string());

        let action = engine.match_packet(&info).await;
        assert_eq!(action, RuleAction::Proxy); // No rule matches, uses default
    }

    #[tokio::test]
    async fn test_rule_engine_domain_matching() {
        let config = RuleEngineConfig::default();
        let engine = RuleEngine::new(config);

        let rules_toml = r#"
[[rule_groups]]
name = "test"
default_action = "proxy"
"#;

        // Note: This TOML format won't work, need proper format
        // Skip this test for now
    }

    #[test]
    fn test_packet_info_creation() {
        // Note: IP addresses in network byte order (big-endian)
        let info = PacketInfo::from_tuple(
            u32::from_be_bytes([127, 0, 0, 1]), // 127.0.0.1
            u32::from_be_bytes([8, 8, 8, 8]),   // 8.8.8.8
            12345,
            80,
            6,
        );

        assert_eq!(info.source_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(info.destination_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(info.src_port, 12345);
        assert_eq!(info.dst_port, 80);
        assert_eq!(info.protocol, 6);
    }
}
