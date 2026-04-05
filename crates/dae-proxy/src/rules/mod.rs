//! Rules module
//!
//! This module provides rule matching types for routing decisions.
//!
//! # Structure
//!
//! - `types`: Basic rule type enums (RuleType, DomainRuleType)
//! - `domain`: Domain-based rule types (DomainRule)
//! - `ip`: IP CIDR and GeoIP rule types
//! - `process`: Process name rule types
//! - `dns`: DNS query type rule types
//! - `capability`: Node capability and tag rule types
//! - `builder`: RuleGroup, Rule, RuleWithAction, RuleMatchAction

pub mod builder;
pub mod capability;
pub mod dns;
pub mod domain;
pub mod ip;
pub mod process;
pub mod types;

// Re-export types for convenient access
pub use builder::{Rule, RuleGroup, RuleMatchAction, RuleWithAction};
pub use capability::{CapabilityRule, CapabilityType, NodeTagRule};
pub use dns::{DnsQueryType, DnsTypeRule};
pub use domain::DomainRule;
pub use ip::{GeoIpRule, IpCidrRule, IpNet};
pub use process::ProcessRule;
pub use types::{DomainRuleType, RuleType};
