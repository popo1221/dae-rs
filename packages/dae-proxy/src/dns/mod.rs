//! DNS resolution module
//!
//! Provides MAC-based DNS resolution that selects DNS servers based on client MAC address.
//!
//! # Architecture
//!
//! - `mac_dns`: MAC-based DNS resolver that routes DNS queries based on device MAC address

pub mod mac_dns;

pub use mac_dns::{
    MacDnsResolver, MacDnsConfig, MacDnsRule, DnsCacheEntry, DnsResolution, DnsError,
};
