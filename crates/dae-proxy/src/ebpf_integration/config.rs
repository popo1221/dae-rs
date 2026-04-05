//! eBPF Map Configuration
//!
//! Provides [`EbpfMapConfig`] with preset configurations for different deployment scenarios.

/// eBPF map size configuration
///
/// These constants define the maximum size and capacity hints for eBPF maps.
/// They are designed to handle high-concurrency scenarios while staying within
/// kernel memory limits (default 64MB RLIMIT_MEMLOCK).
#[derive(Debug, Clone, Copy)]
pub struct EbpfMapConfig {
    /// Maximum number of concurrent sessions
    pub max_sessions: u32,
    /// Maximum number of routing rules (CIDR entries)
    pub max_routes: u32,
    /// Maximum number of DNS cache entries
    pub max_dns_entries: u32,
    /// Maximum number of stat counters
    pub max_stats: u32,
    /// Session map inner HashMap capacity hint
    pub session_capacity: usize,
    /// Routing map inner HashMap capacity hint
    pub routing_capacity: usize,
    /// Stats map inner HashMap capacity hint
    pub stats_capacity: usize,
}

impl Default for EbpfMapConfig {
    /// Default map configuration optimized for desktop/laptop use cases
    ///
    /// - 65,536 max sessions (supports ~10k concurrent connections)
    /// - 16,384 routing rules (CIDR entries)
    /// - 8,192 DNS cache entries
    /// - 256 stat counters
    fn default() -> Self {
        Self {
            max_sessions: 65_536,
            max_routes: 16_384,
            max_dns_entries: 8_192,
            max_stats: 256,
            session_capacity: 16_384,
            routing_capacity: 4_096,
            stats_capacity: 64,
        }
    }
}

impl EbpfMapConfig {
    /// High-performance configuration for servers
    ///
    /// - 262,144 max sessions
    /// - 65,536 routing rules
    /// - 32,768 DNS cache entries
    pub fn high_performance() -> Self {
        Self {
            max_sessions: 262_144,
            max_routes: 65_536,
            max_dns_entries: 32_768,
            max_stats: 256,
            session_capacity: 65_536,
            routing_capacity: 16_384,
            stats_capacity: 64,
        }
    }

    /// Memory-constrained configuration for embedded/IoT devices
    ///
    /// - 4,096 max sessions
    /// - 1,024 routing rules
    /// - 512 DNS cache entries
    pub fn low_memory() -> Self {
        Self {
            max_sessions: 4_096,
            max_routes: 1_024,
            max_dns_entries: 512,
            max_stats: 64,
            session_capacity: 1_024,
            routing_capacity: 256,
            stats_capacity: 32,
        }
    }
}
