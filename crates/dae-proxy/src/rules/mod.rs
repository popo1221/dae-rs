//! 规则模块
//!
//! 本模块提供用于路由决策的规则匹配类型。
//!
//! # 模块结构
//!
//! - `types`: 基础规则类型枚举（RuleType、DomainRuleType）
//! - `domain`: 基于域名的规则类型（DomainRule）
//! - `ip`: IP CIDR 和 GeoIP 规则类型
//! - `process`: 进程名规则类型
//! - `dns`: DNS 查询类型规则类型
//! - `capability`: 节点能力和标签规则类型
//! - `builder`: RuleGroup、Rule、RuleWithAction、RuleMatchAction

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
