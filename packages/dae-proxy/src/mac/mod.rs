//! MAC address rule module
//!
//! Provides MAC address-based traffic routing rules.
//!
//! # Architecture
//!
//! - `rule`: MacRule, MacRuleSet definitions
//! - `matcher`: MAC matching logic with mask support
//! - `oui`: OUI vendor database for device identification

pub mod matcher;
pub mod oui;
pub mod rule;

pub use matcher::{get_mac_by_ip, match_mac_with_mask};
pub use oui::OuiDatabase;
pub use rule::MacAddr;
pub use rule::{MacRule, MacRuleSet};
