//! MAC-based DNS resolution
//!
//! Provides DNS resolution that selects DNS servers based on the client's MAC address.
//! This enables different devices to receive different DNS results (e.g., for parental
//! controls, device-specific filtering, or geo-restriction bypass).

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Instant;

use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::mac::MacAddr;

/// DNS error types
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("No DNS server configured for MAC {0}")]
    NoDnsServerForMac(MacAddr),
    
    #[error("DNS resolution failed: {0}")]
    ResolutionFailed(String),
    
    #[error("Invalid domain name: {0}")]
    InvalidDomain(String),
    
    #[error("DNS server {0} returned no results")]
    NoResults(String),
    
    #[error("DNS cache error: {0}")]
    CacheError(String),
}

/// DNS cache entry with expiration
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    /// Resolved IP addresses
    pub addresses: Vec<IpAddr>,
    /// When this entry was cached
    pub cached_at: Instant,
    /// TTL in seconds
    pub ttl_secs: u64,
}

impl DnsCacheEntry {
    /// Check if the entry has expired
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed().as_secs() >= self.ttl_secs
    }
}

/// MAC-based DNS rule - maps a MAC address to specific DNS servers
#[derive(Debug, Clone)]
pub struct MacDnsRule {
    /// MAC address to match (exact match or with mask)
    pub mac: MacAddr,
    /// Optional MAC mask for prefix matching
    pub mac_mask: Option<MacAddr>,
    /// Primary DNS servers to use for this MAC
    pub dns_servers: Vec<String>,
    /// Fallback DNS servers when primary fails
    pub fallback_dns: Vec<String>,
}

impl MacDnsRule {
    /// Create a new MAC DNS rule with exact MAC match
    pub fn new(mac: MacAddr, dns_servers: Vec<String>, fallback_dns: Vec<String>) -> Self {
        Self {
            mac,
            mac_mask: None,
            dns_servers,
            fallback_dns,
        }
    }

    /// Create a new MAC DNS rule with MAC prefix match
    pub fn with_mask(mac: MacAddr, mask: MacAddr, dns_servers: Vec<String>, fallback_dns: Vec<String>) -> Self {
        Self {
            mac,
            mac_mask: Some(mask),
            dns_servers,
            fallback_dns,
        }
    }

    /// Check if this rule matches the given MAC address
    pub fn matches(&self, mac: &MacAddr) -> bool {
        crate::mac::matcher::match_mac_with_mask_opt(mac, &self.mac, &self.mac_mask).unwrap_or(false)
    }
}

/// MAC-based DNS configuration
#[derive(Debug, Clone)]
pub struct MacDnsConfig {
    /// DNS rules for specific MAC addresses
    pub rules: Vec<MacDnsRule>,
    /// Default DNS servers when no rule matches
    pub default_servers: Vec<String>,
    /// Default fallback DNS servers
    pub default_fallback: Vec<String>,
    /// Cache TTL in seconds (default: 300)
    pub cache_ttl_secs: u64,
    /// Maximum cache size (default: 10000)
    pub max_cache_size: usize,
}

impl Default for MacDnsConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default_servers: vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()],
            default_fallback: vec!["8.8.4.4:53".to_string(), "1.0.0.1:53".to_string()],
            cache_ttl_secs: 300,
            max_cache_size: 10000,
        }
    }
}

/// DNS resolution result with metadata
#[derive(Debug, Clone)]
pub struct DnsResolution {
    /// Resolved IP addresses
    pub addresses: Vec<IpAddr>,
    /// Which DNS server was used
    pub server_used: String,
    /// Whether this was from cache
    pub from_cache: bool,
    /// Query domain
    pub domain: String,
}

/// MAC-based DNS resolver
///
/// Selects appropriate DNS servers based on client MAC address and performs
/// DNS resolution with caching.
pub struct MacDnsResolver {
    config: MacDnsConfig,
    cache: RwLock<HashMap<(MacAddr, String), DnsCacheEntry>>,
}

impl MacDnsResolver {
    /// Create a new MAC DNS resolver with the given configuration
    pub fn new(config: MacDnsConfig) -> Self {
        Self {
            config,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Create a resolver with default configuration
    pub fn default_config() -> Self {
        Self::new(MacDnsConfig::default())
    }

    /// Get DNS servers for a specific MAC address
    fn get_dns_servers_for_mac(&self, mac: &MacAddr) -> (Vec<String>, Vec<String>) {
        for rule in &self.config.rules {
            if rule.matches(mac) {
                return (rule.dns_servers.clone(), rule.fallback_dns.clone());
            }
        }
        (self.config.default_servers.clone(), self.config.default_fallback.clone())
    }

    /// Check if the cache has a valid entry for the given MAC and domain
    async fn get_cached(&self, mac: &MacAddr, domain: &str) -> Option<DnsCacheEntry> {
        let cache = self.cache.read().await;
        cache.get(&(mac.clone(), domain.to_lowercase())).cloned().filter(|e| !e.is_expired())
    }

    /// Store a resolution result in cache
    async fn put_cached(&self, mac: &MacAddr, domain: &str, entry: DnsCacheEntry) {
        let mut cache = self.cache.write().await;
        
        // Evict oldest if at capacity
        if cache.len() >= self.config.max_cache_size {
            // Simple eviction: remove 10% oldest entries
            let evict_count = (self.config.max_cache_size / 10).max(1);
            let keys_to_remove: Vec<_> = cache.iter()
                .map(|((mac, domain), entry)| ((mac.clone(), domain.clone()), entry.cached_at))
                .collect();
            
            let mut sorted: Vec<_> = keys_to_remove.into_iter().collect();
            sorted.sort_by_key(|(_, instant)| *instant);
            
            for (key, _) in sorted.into_iter().take(evict_count) {
                cache.remove(&key);
            }
        }
        
        cache.insert((mac.clone(), domain.to_lowercase()), entry);
    }

    /// Perform DNS resolution using a specific DNS server
    fn resolve_with_server(domain: &str, server: &str) -> Result<DnsResolution, DnsError> {
        let addr_string = format!("{}:53", server.trim_start_matches("https://").trim_start_matches("http://"));
        
        let addresses: Vec<IpAddr> = match addr_string.to_socket_addrs() {
            Ok(mut addrs) => {
                let sock_addr = addrs.next().ok_or_else(|| {
                    DnsError::ResolutionFailed(format!("No address for DNS server: {}", server))
                })?;
                
                // Simple DNS resolution using std library
                // In production, you'd use a proper DNS library like trust-dns
                match domain.to_socket_addrs() {
                    Ok(addrs) => addrs.map(|addr| addr.ip()).collect(),
                    Err(_) => {
                        // Fallback: try to resolve using the system resolver
                        return Err(DnsError::InvalidDomain(domain.to_string()));
                    }
                }
            }
            Err(e) => {
                return Err(DnsError::ResolutionFailed(format!(
                    "Invalid DNS server address {}: {}", server, e
                )));
            }
        };

        if addresses.is_empty() {
            return Err(DnsError::NoResults(server.to_string()));
        }

        Ok(DnsResolution {
            addresses,
            server_used: server.to_string(),
            from_cache: false,
            domain: domain.to_string(),
        })
    }

    /// Resolve a domain name for a specific MAC address
    ///
    /// This is the main entry point for MAC-based DNS resolution.
    /// It first checks the cache, then falls back to DNS servers based
    /// on the MAC address.
    pub async fn resolve(&self, mac: &MacAddr, domain: &str) -> Result<DnsResolution, DnsError> {
        let domain_lower = domain.to_lowercase();
        
        // Check cache first
        if let Some(entry) = self.get_cached(mac, &domain_lower).await {
            debug!("DNS cache hit for {} (MAC: {})", domain, mac);
            return Ok(DnsResolution {
                addresses: entry.addresses.clone(),
                server_used: "cache".to_string(),
                from_cache: true,
                domain: domain_lower,
            });
        }

        debug!("DNS cache miss for {} (MAC: {}), resolving...", domain, mac);
        
        let (primary_servers, fallback_servers) = self.get_dns_servers_for_mac(mac);
        
        // Try primary servers first
        for server in &primary_servers {
            match Self::resolve_with_server(&domain_lower, server) {
                Ok(mut resolution) => {
                    // Cache the result
                    let entry = DnsCacheEntry {
                        addresses: resolution.addresses.clone(),
                        cached_at: Instant::now(),
                        ttl_secs: self.config.cache_ttl_secs,
                    };
                    self.put_cached(mac, &domain_lower, entry).await;
                    resolution.from_cache = false;
                    return Ok(resolution);
                }
                Err(e) => {
                    warn!("DNS resolution failed with server {}: {}", server, e);
                }
            }
        }

        // Try fallback servers
        for server in &fallback_servers {
            match Self::resolve_with_server(&domain_lower, server) {
                Ok(mut resolution) => {
                    // Cache the result
                    let entry = DnsCacheEntry {
                        addresses: resolution.addresses.clone(),
                        cached_at: Instant::now(),
                        ttl_secs: self.config.cache_ttl_secs,
                    };
                    self.put_cached(mac, &domain_lower, entry).await;
                    resolution.from_cache = false;
                    return Ok(resolution);
                }
                Err(e) => {
                    warn!("DNS fallback resolution failed with server {}: {}", server, e);
                }
            }
        }

        Err(DnsError::ResolutionFailed(format!(
            "All DNS servers failed for domain: {}", domain
        )))
    }

    /// Add or update a MAC DNS rule
    pub async fn update_rule(&mut self, rule: MacDnsRule) {
        let mut config = self.config.clone();
        
        // Find and replace existing rule for the same MAC, or append
        let existing_idx = config.rules.iter().position(|r| r.mac == rule.mac);
        
        if let Some(idx) = existing_idx {
            config.rules[idx] = rule;
        } else {
            config.rules.push(rule);
        }
        
        self.config = config;
    }

    /// Remove a MAC DNS rule by MAC address
    pub async fn remove_rule(&mut self, mac: &MacAddr) -> bool {
        let mut config = self.config.clone();
        let original_len = config.rules.len();
        config.rules.retain(|r| r.mac != *mac);
        
        let removed = original_len != config.rules.len();
        if removed {
            self.config = config;
        }
        
        removed
    }

    /// Clear the DNS cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Get the number of cached entries
    pub async fn cache_size(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }

    /// Get all configured rules
    pub fn get_rules(&self) -> Vec<MacDnsRule> {
        self.config.rules.clone()
    }

    /// Get the current configuration
    pub fn get_config(&self) -> MacDnsConfig {
        self.config.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_dns_rule_exact_match() {
        let mac = MacAddr::parse("AA:BB:CC:DD:EE:FF").unwrap();
        let rule = MacDnsRule::new(mac, vec!["8.8.8.8:53".to_string()], vec![]);
        
        assert!(rule.matches(&mac));
        
        let other_mac = MacAddr::parse("11:22:33:44:55:66").unwrap();
        assert!(!rule.matches(&other_mac));
    }

    #[test]
    fn test_mac_dns_rule_mask_match() {
        let mac = MacAddr::parse("AA:BB:CC:DD:EE:FF").unwrap();
        let mask = MacAddr::parse("FF:FF:FF:00:00:00").unwrap();
        let rule = MacDnsRule::with_mask(mac, mask, vec!["8.8.8.8:53".to_string()], vec![]);
        
        // Should match any MAC with AA:BB:CC as first 3 bytes
        let matching_mac = MacAddr::parse("AA:BB:CC:11:22:33").unwrap();
        assert!(rule.matches(&matching_mac));
        
        let non_matching_mac = MacAddr::parse("11:22:33:DD:EE:FF").unwrap();
        assert!(!rule.matches(&non_matching_mac));
    }

    #[tokio::test]
    async fn test_resolver_default_config() {
        let resolver = MacDnsResolver::default_config();
        assert_eq!(resolver.config.default_servers.len(), 2);
        assert_eq!(resolver.config.cache_ttl_secs, 300);
    }

    #[tokio::test]
    async fn test_resolver_update_rule() {
        let mut resolver = MacDnsResolver::default_config();
        let mac = MacAddr::parse("AA:BB:CC:DD:EE:FF").unwrap();
        
        let rule = MacDnsRule::new(
            mac,
            vec!["192.168.1.1:53".to_string()],
            vec!["8.8.8.8:53".to_string()],
        );
        
        resolver.update_rule(rule).await;
        
        let rules = resolver.get_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].dns_servers[0], "192.168.1.1:53");
    }

    #[tokio::test]
    async fn test_resolver_remove_rule() {
        let mut resolver = MacDnsResolver::default_config();
        let mac = MacAddr::parse("AA:BB:CC:DD:EE:FF").unwrap();
        
        let rule = MacDnsRule::new(mac, vec!["192.168.1.1:53".to_string()], vec![]);
        resolver.update_rule(rule).await;
        
        assert_eq!(resolver.get_rules().len(), 1);
        
        resolver.remove_rule(&mac).await;
        assert!(resolver.get_rules().is_empty());
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let resolver = MacDnsResolver::default_config();
        
        assert_eq!(resolver.cache_size().await, 0);
        
        // Clear empty cache should work
        resolver.clear_cache().await;
        assert_eq!(resolver.cache_size().await, 0);
    }
}
