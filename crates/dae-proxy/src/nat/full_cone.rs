//! Full-Cone NAT implementation
//!
//! Implements Full-Cone NAT (also known as NAT1) where:
//! - Any external host can send packets to the internal host
//! - Once an internal client sends to an external host, that external host can reply
//! - No restrictions on external connections

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::sync::RwLock;
use tracing::{debug, info, warn};

/// External mapping entry
#[derive(Debug, Clone)]
pub struct NatMapping {
    /// Internal socket address
    pub internal: SocketAddr,
    /// External socket address (allocated by NAT)
    pub external: SocketAddr,
    /// When this mapping was created
    pub created_at: Instant,
    /// When this mapping expires
    pub expires_at: Instant,
    /// Allowed remote endpoints (empty = any for Full-Cone)
    pub allowed_remotes: Vec<SocketAddr>,
    /// Is this mapping still active
    pub is_active: bool,
}

impl NatMapping {
    /// Check if mapping is expired
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    /// Check if a remote is allowed to send to this mapping
    pub fn is_remote_allowed(&self, remote: SocketAddr) -> bool {
        // Full-Cone: any remote is allowed
        self.allowed_remotes.is_empty() || self.allowed_remotes.contains(&remote)
    }
}

/// Full-Cone NAT configuration
#[derive(Debug, Clone)]
pub struct FullConeNatConfig {
    /// External IP address to use
    pub external_ip: IpAddr,
    /// External port range start
    pub port_range_start: u16,
    /// External port range end
    pub port_range_end: u16,
    /// Mapping TTL (how long mappings stay active)
    pub mapping_ttl: Duration,
    /// Maximum number of simultaneous mappings
    pub max_mappings: usize,
}

impl Default for FullConeNatConfig {
    fn default() -> Self {
        Self {
            external_ip: "0.0.0.0".parse().unwrap(),
            port_range_start: 10000,
            port_range_end: 65535,
            mapping_ttl: Duration::from_secs(300), // 5 minutes
            max_mappings: 65535,
        }
    }
}

/// Full-Cone NAT mapper
pub struct FullConeNat {
    config: FullConeNatConfig,
    /// Mappings: internal SocketAddr -> NatMapping
    mappings: Arc<RwLock<HashMap<SocketAddr, NatMapping>>>,
    /// Reverse mappings: external SocketAddr -> NatMapping
    reverse_mappings: Arc<RwLock<HashMap<SocketAddr, SocketAddr>>>,
    /// Next available port
    next_port: Arc<RwLock<u16>>,
    /// Statistics
    stats: Arc<RwLock<NatStats>>,
}

/// NAT statistics
#[derive(Debug, Clone, Default)]
pub struct NatStats {
    /// Total mappings created
    pub mappings_created: u64,
    /// Total packets forwarded
    pub packets_forwarded: u64,
    /// Total packets dropped
    pub packets_dropped: u64,
    /// Active mappings
    pub active_mappings: usize,
}

impl FullConeNat {
    pub fn new(config: FullConeNatConfig) -> Self {
        let port_start = config.port_range_start;
        Self {
            config,
            mappings: Arc::new(RwLock::new(HashMap::new())),
            reverse_mappings: Arc::new(RwLock::new(HashMap::new())),
            next_port: Arc::new(RwLock::new(port_start)),
            stats: Arc::new(RwLock::new(NatStats::default())),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(FullConeNatConfig::default())
    }

    /// Create a new mapping for an internal endpoint
    /// Returns the external SocketAddr that was allocated
    pub fn create_mapping(&self, internal: SocketAddr) -> std::io::Result<SocketAddr> {
        let mut mappings = self.mappings.write().unwrap();
        let mut reverse_mappings = self.reverse_mappings.write().unwrap();
        let mut stats = self.stats.write().unwrap();

        // Check if we already have a mapping for this internal endpoint
        if let Some(existing) = mappings.get(&internal) {
            if !existing.is_expired() {
                debug!(
                    "Reusing existing NAT mapping for {} -> {}",
                    internal, existing.external
                );
                return Ok(existing.external);
            }
        }

        // Check max mappings
        if mappings.len() >= self.config.max_mappings {
            warn!(
                "NAT: max mappings {} reached, cannot create new mapping",
                self.config.max_mappings
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "NAT: max mappings reached",
            ));
        }

        // Allocate external port - inline to avoid deadlock (allocate_port needs reverse_mappings.read()
        // while we already hold reverse_mappings.write())
        let mut next_port = self.next_port.write().unwrap();
        let start = self.config.port_range_start;
        let end = self.config.port_range_end;
        let external_port = loop {
            let port = *next_port;
            let external = SocketAddr::new(self.config.external_ip, port);

            // Check if port is in use (we already hold reverse_mappings.write())
            if !reverse_mappings.contains_key(&external) {
                // Found available port
                *next_port = if port >= end { start } else { port + 1 };
                break port;
            }

            // Move to next port
            *next_port = if port >= end { start } else { port + 1 };

            // Check if we've tried all ports
            if *next_port == start {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "NAT: no available ports",
                ));
            }
        };

        // Create external address
        let external = SocketAddr::new(self.config.external_ip, external_port);

        // Create mapping
        let mapping = NatMapping {
            internal,
            external,
            created_at: Instant::now(),
            expires_at: Instant::now() + self.config.mapping_ttl,
            allowed_remotes: vec![], // Full-Cone: any remote
            is_active: true,
        };

        // Store mappings
        mappings.insert(internal, mapping.clone());
        reverse_mappings.insert(external, internal);

        // Update stats
        stats.mappings_created += 1;
        stats.active_mappings = mappings.len();

        info!(
            "NAT: created mapping {} -> {} (TTL: {:?})",
            internal, external, self.config.mapping_ttl
        );

        Ok(external)
    }

    /// Find the internal endpoint for an external address
    /// Returns None if no mapping exists
    pub fn find_internal(&self, external: SocketAddr) -> Option<SocketAddr> {
        let reverse = self.reverse_mappings.read().unwrap();
        reverse.get(&external).copied()
    }

    /// Get mapping for an internal address
    pub fn get_mapping(&self, internal: SocketAddr) -> Option<NatMapping> {
        let mappings = self.mappings.read().unwrap();
        mappings.get(&internal).cloned()
    }

    /// Check if an incoming packet from remote is allowed
    pub fn is_incoming_allowed(&self, external: SocketAddr, _remote: SocketAddr) -> bool {
        // Use reverse_mappings to check if we have a mapping for this external address
        // Full-Cone: any incoming is allowed if a mapping exists
        let reverse = self.reverse_mappings.read().unwrap();
        reverse.contains_key(&external)
    }

    /// Remove a mapping
    pub fn remove_mapping(&self, internal: SocketAddr) -> Option<NatMapping> {
        let mut mappings = self.mappings.write().unwrap();
        let mut reverse_mappings = self.reverse_mappings.write().unwrap();
        let mut stats = self.stats.write().unwrap();

        if let Some(mapping) = mappings.remove(&internal) {
            reverse_mappings.remove(&mapping.external);
            stats.active_mappings = mappings.len();
            info!("NAT: removed mapping {} -> {}", internal, mapping.external);
            Some(mapping)
        } else {
            None
        }
    }

    /// Clean up expired mappings
    pub fn cleanup_expired(&self) -> usize {
        let mut mappings = self.mappings.write().unwrap();
        let mut reverse_mappings = self.reverse_mappings.write().unwrap();
        let mut stats = self.stats.write().unwrap();

        let mut expired_count = 0;

        mappings.retain(|_internal, mapping| {
            if mapping.is_expired() {
                reverse_mappings.remove(&mapping.external);
                expired_count += 1;
                false
            } else {
                true
            }
        });

        stats.active_mappings = mappings.len();

        if expired_count > 0 {
            debug!("NAT: cleaned up {} expired mappings", expired_count);
        }

        expired_count
    }

    /// Get statistics
    pub fn get_stats(&self) -> NatStats {
        let stats = self.stats.read().unwrap();
        stats.clone()
    }

    /// Get all active mappings
    pub fn get_active_mappings(&self) -> Vec<NatMapping> {
        let mappings = self.mappings.read().unwrap();
        mappings
            .values()
            .filter(|m| !m.is_expired())
            .cloned()
            .collect()
    }
}

/// Full-Cone NAT handler for UDP
pub struct FullConeNatUdpHandler {
    nat: Arc<FullConeNat>,
}

impl FullConeNatUdpHandler {
    pub fn new(config: FullConeNatConfig) -> Self {
        Self {
            nat: Arc::new(FullConeNat::new(config)),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(FullConeNatConfig::default())
    }

    /// Handle outgoing UDP packet
    pub fn handle_outgoing(
        &self,
        internal: SocketAddr,
        _target: SocketAddr,
    ) -> std::io::Result<SocketAddr> {
        // Create mapping if not exists
        self.nat.create_mapping(internal)
    }

    /// Handle incoming UDP packet
    pub fn handle_incoming(&self, external: SocketAddr, from: SocketAddr) -> Option<SocketAddr> {
        // Full-Cone: any incoming is allowed if mapping exists
        if self.nat.is_incoming_allowed(external, from) {
            self.nat.find_internal(external)
        } else {
            None
        }
    }

    /// Get the NAT instance
    pub fn nat(&self) -> &Arc<FullConeNat> {
        &self.nat
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_cone_nat_config_default() {
        let config = FullConeNatConfig::default();
        assert_eq!(config.port_range_start, 10000);
        assert_eq!(config.port_range_end, 65535);
        assert_eq!(config.mapping_ttl, Duration::from_secs(300));
    }

    #[test]
    fn test_create_mapping() {
        let nat = FullConeNat::with_default_config();
        let internal: SocketAddr = "192.168.1.100:12345".parse().unwrap();

        let external = nat.create_mapping(internal).unwrap();
        // port() returns u16 which is always valid (0-65535)
        let _port = external.port();
    }

    #[test]
    fn test_find_internal() {
        let nat = FullConeNat::with_default_config();
        let internal: SocketAddr = "192.168.1.100:12345".parse().unwrap();

        let external = nat.create_mapping(internal).unwrap();
        let found_internal = nat.find_internal(external);

        assert_eq!(found_internal, Some(internal));
    }

    #[test]
    fn test_remove_mapping() {
        let nat = FullConeNat::with_default_config();
        let internal: SocketAddr = "192.168.1.100:12345".parse().unwrap();

        let external = nat.create_mapping(internal).unwrap();
        let removed = nat.remove_mapping(internal);

        assert!(removed.is_some());
        assert_eq!(nat.find_internal(external), None);
    }

    #[test]
    fn test_is_incoming_allowed() {
        let nat = FullConeNat::with_default_config();
        let internal: SocketAddr = "192.168.1.100:12345".parse().unwrap();

        let external = nat.create_mapping(internal).unwrap();
        let remote: SocketAddr = "8.8.8.8:53".parse().unwrap();

        // Full-Cone: any incoming is allowed
        assert!(nat.is_incoming_allowed(external, remote));
    }
}
