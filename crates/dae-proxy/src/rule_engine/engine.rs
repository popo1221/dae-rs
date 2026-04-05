//! Rule engine implementation
//!
//! Contains the core RuleEngine implementation for matching packets against rules.

use super::{RuleAction, RuleEngineConfig, RuleEngineStats};
use crate::metrics::observe_rule_match_latency;
use crate::rules::{Rule, RuleGroup, RuleMatchAction};
use std::path::Path;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

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
    #[allow(dead_code)]
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
    pub async fn match_packet(&self, info: &super::PacketInfo) -> RuleAction {
        let start = Instant::now();

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
                // Track rule match (rule type unknown at this level)
                observe_rule_match_latency(start.elapsed().as_secs_f64());
                return action.to_action();
            }
        }

        // No matching rule, return default action
        debug!("No matching rule, using default action");
        observe_rule_match_latency(start.elapsed().as_secs_f64());
        self.config.default_action
    }

    /// Lookup GeoIP country for an IP address
    ///
    /// Note: GeoIP lookup requires a properly formatted GeoLite2 or GeoIP2 database.
    /// This implementation uses the maxminddb 0.27 API which provides lookup returning
    /// a LookupResult. The actual field access depends on the database type.
    pub async fn lookup_geoip(&self, ip: &std::net::IpAddr) -> Option<String> {
        let reader = self.geoip_reader.read().await;
        let reader = match reader.as_ref() {
            Some(r) => r,
            None => return None,
        };

        // Use maxminddb 0.27 API - lookup returns LookupResult
        // For GeoLite2/GeoIP2 Country database, we decode as geoip2::Country
        match reader.lookup(*ip) {
            Ok(result) => {
                // Decode the lookup result as a Country struct
                match result.decode::<maxminddb::geoip2::Country>() {
                    Ok(Some(country)) => {
                        // Return the ISO country code (e.g., "US", "CN")
                        country.country.iso_code.map(|code| code.to_uppercase())
                    }
                    Ok(None) => {
                        // IP not found in database
                        debug!("IP not found in GeoIP database");
                        None
                    }
                    Err(e) => {
                        debug!("Failed to decode GeoIP result: {:?}", e);
                        None
                    }
                }
            }
            Err(e) => {
                // Log at debug level - this is expected for non-GeoIP databases or invalid IPs
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

#[cfg(test)]
mod tests {
    use super::super::PacketInfo;
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
