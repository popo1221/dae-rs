//! DNS resolution module
//!
//! Provides MAC-based DNS resolution that selects DNS servers based on client MAC address.
//!
//! # Architecture
//!
//! - `mac_dns`: MAC-based DNS resolver that routes DNS queries based on device MAC address
//! - `loop_detection`: Upstream and source loop detection to prevent DNS loops

pub mod mac_dns;
pub mod loop_detection;

pub use mac_dns::{
    DnsCacheEntry, DnsError, DnsResolution, MacDnsConfig, MacDnsResolver, MacDnsRule,
};
pub use loop_detection::{
    DnsLoopDetector, LoopDetectionConfig, LoopDetectionResult, NotifyingDnsLoopDetector,
};
