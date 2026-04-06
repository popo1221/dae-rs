//! DNS 解析模块
//!
//! 提供基于 MAC 地址的 DNS 解析功能，根据客户端 MAC 地址选择不同的 DNS 服务器。
//!
//! # 架构设计
//!
//! - `mac_dns`: 基于 MAC 的 DNS 解析器，根据设备 MAC 地址路由 DNS 查询
//! - `loop_detection`: 上游和源循环检测，防止 DNS 解析循环

pub mod loop_detection;
pub mod mac_dns;

pub use loop_detection::{
    DnsLoopDetector, LoopDetectionConfig, LoopDetectionResult, NotifyingDnsLoopDetector,
};
pub use mac_dns::{
    DnsCacheEntry, DnsError, DnsResolution, MacDnsConfig, MacDnsResolver, MacDnsRule,
};
