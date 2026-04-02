//! Rule configuration parsing for dae-config
//!
//! This module provides TOML configuration parsing for the rule engine.

use serde::Deserialize;

/// Top-level rule configuration
#[derive(Debug, Deserialize)]
pub struct RuleConfig {
    /// Rule groups
    #[serde(default)]
    pub rule_groups: Vec<RuleGroupConfig>,
}

/// A rule group configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RuleGroupConfig {
    /// Group name
    pub name: String,
    /// Rules in this group
    #[serde(default)]
    pub rules: Vec<RuleConfigItem>,
    /// Default action when no rule matches
    #[serde(default = "default_action")]
    pub default_action: String,
    /// Whether to stop after first match
    #[serde(default = "default_first_match")]
    pub first_match: bool,
}

/// A single rule configuration item
#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfigItem {
    /// Rule type (domain, domain-suffix, domain-keyword, ipcidr, geoip, process, dnstype)
    #[serde(rename = "type")]
    pub rule_type: String,
    /// Rule value (domain, CIDR, country code, etc.)
    pub value: String,
    /// Action when rule matches (pass, proxy, drop)
    pub action: String,
    /// Rule priority (lower = higher priority)
    #[serde(default)]
    pub priority: Option<u32>,
}

fn default_action() -> String {
    "proxy".to_string()
}

fn default_first_match() -> bool {
    true
}

/// Rule validation error
#[derive(Debug)]
pub enum RuleValidationError {
    /// Invalid rule type
    InvalidRuleType(String),
    /// Invalid rule value
    InvalidRuleValue(String),
    /// Empty rule value
    EmptyValue,
    /// Invalid action
    InvalidAction(String),
    /// Invalid GeoIP country code
    InvalidGeoIp(String),
    /// Invalid DNS query type
    InvalidDnsType(String),
    /// Invalid CIDR notation
    InvalidCidr(String),
}

impl std::fmt::Display for RuleValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleValidationError::InvalidRuleType(t) => write!(f, "Invalid rule type: {t}"),
            RuleValidationError::InvalidRuleValue(v) => write!(f, "Invalid rule value: {v}"),
            RuleValidationError::EmptyValue => write!(f, "Empty rule value"),
            RuleValidationError::InvalidAction(a) => write!(f, "Invalid action: {a}"),
            RuleValidationError::InvalidGeoIp(c) => write!(f, "Invalid GeoIP country code: {c}"),
            RuleValidationError::InvalidDnsType(t) => write!(f, "Invalid DNS query type: {t}"),
            RuleValidationError::InvalidCidr(c) => write!(f, "Invalid CIDR notation: {c}"),
        }
    }
}

impl std::error::Error for RuleValidationError {}

/// Validate a single rule
pub fn validate_rule(rule: &RuleConfigItem) -> Result<(), RuleValidationError> {
    // Check empty value
    if rule.value.is_empty() {
        return Err(RuleValidationError::EmptyValue);
    }

    // Validate rule type and value
    match rule.rule_type.to_lowercase().as_str() {
        "domain" | "domain-suffix" | "domain-keyword" => {
            // Domain validation is mostly just checking it's not empty
            Ok(())
        }
        "ipcidr" | "ip-cidr" | "cidr" => {
            // Validate CIDR notation
            let value = rule.value.trim_start_matches('!');
            if value.parse::<ipnet::IpNet>().is_err() {
                Err(RuleValidationError::InvalidCidr(value.to_string()))
            } else {
                Ok(())
            }
        }
        "geoip" | "geo-ip" => {
            // Validate country code (ISO 3166-1 alpha-2, 2 characters)
            let code = rule.value.trim_start_matches('!').to_uppercase();
            if code.len() != 2 || !code.chars().all(|c| c.is_ascii_alphabetic()) {
                Err(RuleValidationError::InvalidGeoIp(code))
            } else {
                Ok(())
            }
        }
        "process" | "process-name" => {
            // Process name validation - just check not empty
            Ok(())
        }
        "dnstype" | "dns-type" | "dns" => {
            // Validate DNS query types
            let types: Result<Vec<_>, _> = rule
                .value
                .split(',')
                .map(|t| validate_dns_type(t.trim()))
                .collect();
            types.map(|_| ())
        }
        // Node capability rules (fullcone, udp, v2ray)
        "fullcone" | "full-cone" | "fullcone(enabled)" => {
            // Value should be "true", "false", "1", "0", "enabled", "disabled"
            let value = rule.value.to_lowercase();
            match value.as_str() {
                "true" | "false" | "1" | "0" | "enabled" | "disabled" => Ok(()),
                _ => Err(RuleValidationError::InvalidRuleValue(value)),
            }
        }
        "udp" | "udp(enabled)" => {
            let value = rule.value.to_lowercase();
            match value.as_str() {
                "true" | "false" | "1" | "0" | "enabled" | "disabled" => Ok(()),
                _ => Err(RuleValidationError::InvalidRuleValue(value)),
            }
        }
        "v2ray" | "v2ray(compatible)" => {
            let value = rule.value.to_lowercase();
            match value.as_str() {
                "true" | "false" | "1" | "0" | "enabled" | "disabled" | "compatible" => Ok(()),
                _ => Err(RuleValidationError::InvalidRuleValue(value)),
            }
        }
        _ => Err(RuleValidationError::InvalidRuleType(rule.rule_type.clone())),
    }?;

    // Validate action
    match rule.action.to_lowercase().as_str() {
        "pass" | "allow" | "direct" | "proxy" | "route" | "drop" | "deny" | "block" => Ok(()),
        _ => Err(RuleValidationError::InvalidAction(rule.action.clone())),
    }
}

/// Validate a DNS query type
fn validate_dns_type(t: &str) -> Result<(), RuleValidationError> {
    match t.to_uppercase().as_str() {
        "A" | "AAAA" | "NS" | "CNAME" | "SOA" | "PTR" | "MX" | "TXT" | "SRV" | "ANY" => Ok(()),
        _ => Err(RuleValidationError::InvalidDnsType(t.to_string())),
    }
}

/// Validate all rules in a rule group
pub fn validate_rule_group(group: &RuleGroupConfig) -> Vec<RuleValidationError> {
    let mut errors = Vec::new();

    for rule in &group.rules {
        if let Err(e) = validate_rule(rule) {
            errors.push(e);
        }
    }

    errors
}

/// Validate the entire rule configuration
pub fn validate_config(config: &RuleConfig) -> Vec<RuleValidationError> {
    let mut errors = Vec::new();

    for group in &config.rule_groups {
        errors.extend(validate_rule_group(group));
    }

    errors
}

/// Parse and validate rules from TOML content
pub fn parse_and_validate(
    content: &str,
) -> Result<RuleConfig, (RuleConfig, Vec<RuleValidationError>)> {
    #[allow(clippy::vec_init_then_push)]
    let config: RuleConfig = toml::from_str(content)
        .map_err(|e| {
            // Return empty config with parse error
            let mut errors = Vec::new();
            errors.push(RuleValidationError::InvalidRuleValue(e.to_string()));
            (
                RuleConfig {
                    rule_groups: vec![],
                },
                errors,
            )
        })
        .ok()
        .unwrap();

    let errors = validate_config(&config);
    if !errors.is_empty() {
        return Err((config, errors));
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_rules() {
        let toml_content = r#"
[[rule_groups]]
name = "direct"
default_action = "pass"
rules = [
    { type = "domain-suffix", value = ".cn", action = "pass" },
    { type = "ipcidr", value = "10.0.0.0/8", action = "pass" },
]

[[rule_groups]]
name = "proxy"
default_action = "proxy"
rules = [
    { type = "geoip", value = "cn", action = "pass" },
]
"#;

        let config: RuleConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.rule_groups.len(), 2);
        assert_eq!(config.rule_groups[0].name, "direct");
        assert_eq!(config.rule_groups[0].rules.len(), 2);
        assert_eq!(config.rule_groups[1].name, "proxy");
    }

    #[test]
    fn test_validate_domain_rule() {
        let rule = RuleConfigItem {
            rule_type: "domain".to_string(),
            value: "example.com".to_string(),
            action: "pass".to_string(),
            priority: None,
        };
        assert!(validate_rule(&rule).is_ok());

        let rule = RuleConfigItem {
            rule_type: "domain-suffix".to_string(),
            value: ".example.com".to_string(),
            action: "pass".to_string(),
            priority: None,
        };
        assert!(validate_rule(&rule).is_ok());
    }

    #[test]
    fn test_validate_cidr_rule() {
        let rule = RuleConfigItem {
            rule_type: "ipcidr".to_string(),
            value: "10.0.0.0/8".to_string(),
            action: "pass".to_string(),
            priority: None,
        };
        assert!(validate_rule(&rule).is_ok());

        let rule = RuleConfigItem {
            rule_type: "ipcidr".to_string(),
            value: "!10.0.0.0/8".to_string(),
            action: "pass".to_string(),
            priority: None,
        };
        assert!(validate_rule(&rule).is_ok());

        let rule = RuleConfigItem {
            rule_type: "ipcidr".to_string(),
            value: "invalid".to_string(),
            action: "pass".to_string(),
            priority: None,
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_geoip_rule() {
        let rule = RuleConfigItem {
            rule_type: "geoip".to_string(),
            value: "CN".to_string(),
            action: "pass".to_string(),
            priority: None,
        };
        assert!(validate_rule(&rule).is_ok());

        let rule = RuleConfigItem {
            rule_type: "geoip".to_string(),
            value: "CHN".to_string(), // 3 chars - invalid
            action: "pass".to_string(),
            priority: None,
        };
        assert!(validate_rule(&rule).is_err());

        let rule = RuleConfigItem {
            rule_type: "geoip".to_string(),
            value: "C1".to_string(), // Contains digit - invalid
            action: "pass".to_string(),
            priority: None,
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_dnstype_rule() {
        let rule = RuleConfigItem {
            rule_type: "dnstype".to_string(),
            value: "A,AAAA,CNAME".to_string(),
            action: "pass".to_string(),
            priority: None,
        };
        assert!(validate_rule(&rule).is_ok());

        let rule = RuleConfigItem {
            rule_type: "dnstype".to_string(),
            value: "INVALID".to_string(),
            action: "pass".to_string(),
            priority: None,
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_action() {
        let rule = RuleConfigItem {
            rule_type: "domain".to_string(),
            value: "example.com".to_string(),
            action: "invalid".to_string(),
            priority: None,
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_empty_value() {
        let rule = RuleConfigItem {
            rule_type: "domain".to_string(),
            value: "".to_string(),
            action: "pass".to_string(),
            priority: None,
        };
        assert!(validate_rule(&rule).is_err());
    }
}
