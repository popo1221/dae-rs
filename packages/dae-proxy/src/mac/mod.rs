//! MAC address rule module
//!
//! Provides MAC address-based traffic routing rules.
//!
//! # Architecture
//!
//! - `rule`: MacRule, MacRuleSet definitions
//! - `matcher`: MAC matching logic with mask support
//! - `oui`: OUI vendor database for device identification

pub mod rule;
pub mod matcher;
pub mod oui;

pub use rule::{MacRule, MacRuleSet};
pub use matcher::{match_mac_with_mask, get_mac_by_ip};
pub use oui::OuiDatabase;
pub use rule::MacAddr;
