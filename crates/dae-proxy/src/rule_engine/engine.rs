//! 规则引擎实现
//!
//! 包含核心 RuleEngine 实现，用于将数据包与规则进行匹配。

use super::{RuleAction, RuleEngineConfig, RuleEngineStats};
use crate::metrics::observe_rule_match_latency;
use crate::rules::{Rule, RuleGroup, RuleMatchAction};
use std::path::Path;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// GeoIP database kind - determines which lookup struct to use
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GeoIpDatabaseKind {
    /// GeoLite2-Country or GeoIP2-Country database
    Country,
    /// GeoLite2-City or GeoIP2-City database
    City,
    /// GeoLite2-ASN or GeoIP2-ISP database (not suitable for country lookup)
    Asn,
    /// Unknown database type
    Unknown,
}

impl std::fmt::Display for GeoIpDatabaseKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeoIpDatabaseKind::Country => write!(f, "Country"),
            GeoIpDatabaseKind::City => write!(f, "City"),
            GeoIpDatabaseKind::Asn => write!(f, "ASN"),
            GeoIpDatabaseKind::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Detect GeoIP database kind from database type string
///
/// Database type strings include:
/// - "GeoLite2-Country", "GeoIP2-Country"
/// - "GeoLite2-City", "GeoIP2-City", "GeoLite2-City-IPv6"
/// - "GeoLite2-ASN", "GeoIP2-ISP"
fn detect_geoip_database_kind(database_type: &str) -> GeoIpDatabaseKind {
    let dt = database_type.to_lowercase();
    if dt.contains("asn") || dt.contains("isp") {
        GeoIpDatabaseKind::Asn
    } else if dt.contains("city") {
        GeoIpDatabaseKind::City
    } else if dt.contains("country") {
        GeoIpDatabaseKind::Country
    } else {
        // Unknown type, try Country decode first as fallback
        GeoIpDatabaseKind::Unknown
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
    /// GeoIP database kind (detected on load)
    geoip_kind: RwLock<GeoIpDatabaseKind>,
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
            geoip_kind: RwLock::new(GeoIpDatabaseKind::Unknown),
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
    ///
    /// Supports multiple database types:
    /// - GeoLite2-Country / GeoIP2-Country: returns ISO country code
    /// - GeoLite2-City / GeoIP2-City: returns ISO country code from city data
    /// - GeoLite2-ASN / GeoIP2-ISP: suitable for ASN lookup (country returns None)
    ///
    /// The database type is auto-detected from the database metadata.
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

        // Detect database type from metadata
        let db_type = reader.metadata.database_type.clone();
        let kind = detect_geoip_database_kind(&db_type);
        info!(
            "GeoIP database loaded from {} (type: {}, kind: {})",
            db_path, db_type, kind
        );

        // Warn if using ASN database for country lookup (won't work well)
        if kind == GeoIpDatabaseKind::Asn {
            warn!(
                "GeoIP ASN database loaded. Note: country lookup will return None. \
                 Use a Country or City database for GeoIP country rules."
            );
        }

        let mut geoip = self.geoip_reader.write().await;
        *geoip = Some(reader);

        let mut geoip_kind = self.geoip_kind.write().await;
        *geoip_kind = kind;

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

        // Assign unique rule IDs to all rules
        let mut next_rule_id: u32 = 0;
        for group in &mut rule_groups {
            for rule in &mut group.rules {
                rule.set_rule_id(next_rule_id);
                next_rule_id += 1;
            }
        }

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
            if let Some((action, _rule_id, _rule_type)) = group.match_packet(&info) {
                debug!(
                    "Packet matched rule in group '{}': {:?}",
                    group.name, action
                );
                observe_rule_match_latency(start.elapsed().as_secs_f64());
                return action.to_action();
            }
        }

        // No matching rule, return default action
        debug!("No matching rule, using default action");
        observe_rule_match_latency(start.elapsed().as_secs_f64());
        self.config.default_action
    }

    /// Match a packet against all rules and return match info
    ///
    /// Returns detailed information about which rule matched, including
    /// rule_id and rule_type for tracking purposes.
    #[allow(dead_code)]
    pub async fn match_packet_info(&self, info: &super::PacketInfo) -> super::RuleMatchInfo {
        let start = Instant::now();

        // Enrich packet info with GeoIP if available
        let mut info = info.clone();
        if info.geoip_country.is_none() && self.config.geoip_enabled {
            info.geoip_country = self.lookup_geoip(&info.destination_ip).await;
        }

        let groups = self.rule_groups.read().await;

        for group in groups.iter() {
            if let Some((action, rule_id, rule_type)) = group.match_packet(&info) {
                debug!(
                    "Packet matched rule in group '{}': {:?} (rule_id={}, rule_type={})",
                    group.name, action, rule_id, rule_type
                );
                observe_rule_match_latency(start.elapsed().as_secs_f64());
                return super::RuleMatchInfo {
                    action: action.to_action(),
                    rule_id,
                    rule_type,
                    matched: true,
                };
            }
        }

        // No matching rule, return default action
        debug!("No matching rule, using default action");
        observe_rule_match_latency(start.elapsed().as_secs_f64());
        super::RuleMatchInfo {
            action: self.config.default_action,
            rule_id: u32::MAX, // Invalid rule_id indicates no match
            rule_type: 0,
            matched: false,
        }
    }

    /// Lookup GeoIP country for an IP address
    ///
    /// **Supported Database Types:**
    /// - **GeoLite2-Country / GeoIP2-Country**: Returns ISO 3166-1 alpha-2 country codes
    /// - **GeoLite2-City / GeoIP2-City**: Returns ISO country codes from city data
    /// - **GeoLite2-ASN / GeoIP2-ISP**: Returns `None` (ASN has no country info)
    ///
    /// Returns uppercase ISO 3166-1 alpha-2 country codes (e.g., "US", "CN", "JP")
    /// or `None` if the IP is not found or the database doesn't support country lookup.
    pub async fn lookup_geoip(&self, ip: &std::net::IpAddr) -> Option<String> {
        let reader = self.geoip_reader.read().await;
        let reader = match reader.as_ref() {
            Some(r) => r,
            None => return None,
        };

        let kind = *self.geoip_kind.read().await;

        match reader.lookup(*ip) {
            Ok(result) => match kind {
                GeoIpDatabaseKind::Country | GeoIpDatabaseKind::Unknown => {
                    // Try Country struct first (works for Country databases)
                    match result.decode::<maxminddb::geoip2::Country>() {
                        Ok(Some(country)) => {
                            country.country.iso_code.map(|code| code.to_uppercase())
                        }
                        Ok(None) => {
                            debug!("IP not found in GeoIP database");
                            None
                        }
                        Err(_) => {
                            // Country decode failed, might be a City database
                            // Try City struct
                            match result.decode::<maxminddb::geoip2::City>() {
                                Ok(Some(city)) => {
                                    city.country.iso_code.map(|code| code.to_uppercase())
                                }
                                Ok(None) => {
                                    debug!("IP not found in GeoIP database");
                                    None
                                }
                                Err(e) => {
                                    debug!("Failed to decode GeoIP City result: {:?}", e);
                                    None
                                }
                            }
                        }
                    }
                }
                GeoIpDatabaseKind::City => {
                    // Use City struct directly
                    match result.decode::<maxminddb::geoip2::City>() {
                        Ok(Some(city)) => city.country.iso_code.map(|code| code.to_uppercase()),
                        Ok(None) => {
                            debug!("IP not found in GeoIP City database");
                            None
                        }
                        Err(e) => {
                            debug!("Failed to decode GeoIP City result: {:?}", e);
                            None
                        }
                    }
                }
                GeoIpDatabaseKind::Asn => {
                    // ASN database has no country info
                    debug!("ASN database does not contain country information");
                    None
                }
            },
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
