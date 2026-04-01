//! MAC address rules
//!
//! Defines MAC address rule structures and the MAC rule set for matching.

use std::fmt;
use std::net::IpAddr;

use crate::rule_engine::RuleAction;

/// MAC address type (6 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// Create a new MAC address from 6 bytes
    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Create from a colon-separated string like "AA:BB:CC:DD:EE:FF"
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            // Also try hyphen separator
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() != 6 {
                return None;
            }
            let bytes: Option<Vec<u8>> = parts
                .iter()
                .map(|p| u8::from_str_radix(p, 16).ok())
                .collect();
            return bytes.and_then(|b| {
                if b.len() == 6 {
                    let mut arr = [0u8; 6];
                    arr.copy_from_slice(&b);
                    Some(Self(arr))
                } else {
                    None
                }
            });
        }
        let bytes: Option<Vec<u8>> = parts
            .iter()
            .map(|p| u8::from_str_radix(p, 16).ok())
            .collect();
        bytes.and_then(|b| {
            if b.len() == 6 {
                let mut arr = [0u8; 6];
                arr.copy_from_slice(&b);
                Some(Self(arr))
            } else {
                None
            }
        })
    }

    /// Get the 6 bytes of this MAC address
    pub fn bytes(&self) -> [u8; 6] {
        self.0
    }

    /// Get the first 3 bytes (OUI prefix)
    pub fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    /// Get a specific byte by index
    pub fn byte(&self, idx: usize) -> Option<u8> {
        self.0.get(idx).copied()
    }

    /// Check if this is a broadcast MAC address
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xFF; 6]
    }

    /// Check if this is a multicast MAC address
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Check if this is a locally administered MAC address
    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl Default for MacAddr {
    fn default() -> Self {
        Self([0x00; 6])
    }
}

/// MAC address rule for matching traffic by device MAC address
#[derive(Debug, Clone)]
pub struct MacRule {
    /// Exact MAC address to match
    pub mac: MacAddr,
    /// Optional MAC mask for prefix matching (e.g., AA:BB:CC:00:00:00)
    /// When mask is Some, only bits where mask is non-zero are compared
    pub mac_mask: Option<MacAddr>,
    /// The action to take when this rule matches
    pub action: RuleAction,
}

impl MacRule {
    /// Create a new MAC rule with exact match
    pub fn new_exact(mac: MacAddr, action: RuleAction) -> Self {
        Self {
            mac,
            mac_mask: None,
            action,
        }
    }

    /// Create a new MAC rule with mask (prefix match)
    pub fn new_masked(mac: MacAddr, mask: MacAddr, action: RuleAction) -> Self {
        Self {
            mac,
            mac_mask: Some(mask),
            action,
        }
    }

    /// Create from string (parsing "AA:BB:CC:DD:EE:FF" or "AA:BB:CC-DD-EE-FF")
    pub fn parse(s: &str, action: RuleAction) -> Option<Self> {
        let (mac_str, mask_str) = if let Some((m, mask)) = s.split_once('/') {
            (m, Some(mask))
        } else {
            (s, None)
        };

        let mac = MacAddr::parse(mac_str)?;
        let mac_mask = mask_str.map(MacAddr::parse).flatten();
        Some(Self { mac, mac_mask, action })
    }
}

/// MAC address rule set for matching traffic
#[derive(Debug, Clone)]
pub struct MacRuleSet {
    /// List of MAC rules (evaluated in order)
    pub rules: Vec<MacRule>,
    /// Default action when no rule matches
    pub default_action: RuleAction,
}

impl Default for MacRuleSet {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default_action: RuleAction::Proxy,
        }
    }
}

impl MacRuleSet {
    /// Create a new empty rule set with default action
    pub fn new(default_action: RuleAction) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
        }
    }

    /// Add a rule to the set
    pub fn add_rule(&mut self, rule: MacRule) {
        self.rules.push(rule);
    }

    /// Add a rule from string and action
    pub fn add_rule_str(&mut self, s: &str, action: RuleAction) -> Option<()> {
        let rule = MacRule::parse(s, action)?;
        self.rules.push(rule);
        Some(())
    }

    /// Match a MAC address against all rules in order
    /// Returns the action of the first matching rule, or default_action
    pub fn match_mac(&self, mac: &MacAddr) -> RuleAction {
        for rule in &self.rules {
            if let Some(true) = super::matcher::match_mac_with_mask_opt(mac, &rule.mac, &rule.mac_mask) {
                return rule.action.clone();
            }
        }
        self.default_action.clone()
    }

    /// Get number of rules
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}
