//! Subscription module for fetching and parsing node subscriptions
//!
//! Implements support for multiple subscription formats:
//! - SIP008 (Shadowsocks SIP008) subscription format
//! - Clash YAML subscription format
//! - Sing-Box JSON subscription format
//! - V2Ray/Xray URI subscriptions (vmess://, vless://, trojan://, ss://)
//! - Base64-encoded subscriptions
//!
//! # Subscription Format Examples
//!
//! ## SIP008 (JSON)
//! ```json
//! {
//!   "version": 1,
//!   "servers": [
//!     {
//!       "id": "server-1",
//!       "remarks": "My Server",
//!       "server": "example.com",
//!       "server_port": 8388,
//!       "password": "password",
//!       "method": "chacha20-ietf-poly1305"
//!     }
//!   ]
//! }
//! ```
//!
//! ## Clash YAML
//! ```yaml
//! proxies:
//!   - name: "香港节点"
//!     type: trojan
//!     server: hk.example.com
//!     port: 443
//!     password: xxxxx
//!     sni: example.com
//! ```
//!
//! ## Sing-Box JSON
//! ```json
//! {
//!   "outbounds": [
//!     {
//!       "type": "trojan",
//!       "tag": "香港",
//!       "server": "hk.example.com",
//!       "port": 443,
//!       "password": "xxxxx"
//!     }
//!   ]
//! }
//! ```
//!
//! ## URI Links
//! - `ss://method:password@server:port`
//! - `vmess://base64-json`
//! - `vless://uuid@server:port`
//! - `trojan://password@server:port`

// =============================================================================
// Submodules
// =============================================================================

pub mod clash;
pub mod encoding;
pub mod singbox;
pub mod sip008;
pub mod uri;

// =============================================================================
// Re-exports from submodules
// =============================================================================

pub use clash::{parse_clash_yaml, ClashProxy, ClashSubscription};
pub use encoding::{parse_base64_subscription, parse_uri_list};
pub use singbox::{
    parse_singbox_json, singbox_outbound_to_uri, SingBoxOutbound, SingBoxSubscription,
};
pub use sip008::{parse_sip008_subscription, Sip008Server, Sip008Subscription};
pub use uri::{uri_to_node_config, uris_to_node_configs, ProxyProtocol};

// =============================================================================
// Shared Types
// =============================================================================

use base64::Engine;
use std::time::Duration;

/// Subscription provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionType {
    /// SIP008 JSON format
    Sip008,
    /// Base64-encoded plain text with ss:// links
    Base64,
    /// Clash YAML format
    ClashYaml,
    /// Sing-Box JSON format
    SingBoxJson,
    /// Mixed format (auto-detect)
    Auto,
}

/// Subscription error types
#[derive(Debug, Clone)]
pub enum SubscriptionError {
    /// Network error when fetching subscription
    NetworkError(String),
    /// Parse error (invalid format)
    ParseError(String),
    /// Unsupported subscription format
    UnsupportedFormat,
    /// Authentication required
    AuthenticationRequired,
    /// URL parse error
    UrlParseError(String),
    /// URI scheme not supported
    UnsupportedUriScheme(String),
}

impl std::fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscriptionError::NetworkError(s) => write!(f, "Network error: {s}"),
            SubscriptionError::ParseError(s) => write!(f, "Parse error: {s}"),
            SubscriptionError::UnsupportedFormat => write!(f, "Unsupported subscription format"),
            SubscriptionError::AuthenticationRequired => write!(f, "Authentication required"),
            SubscriptionError::UrlParseError(s) => write!(f, "URL parse error: {s}"),
            SubscriptionError::UnsupportedUriScheme(s) => {
                write!(f, "Unsupported URI scheme: {s}")
            }
        }
    }
}

impl std::error::Error for SubscriptionError {}

/// Subscription update result
#[derive(Debug, Clone)]
pub struct SubscriptionUpdate {
    /// Tag/name of the subscription
    pub tag: Option<String>,
    /// Parsed server links
    pub links: Vec<String>,
    /// Bytes used (from SIP008 header)
    pub bytes_used: Option<u64>,
    /// Bytes remaining (from SIP008 header)
    pub bytes_remaining: Option<u64>,
    /// Whether the format was auto-detected
    pub format_detected: SubscriptionType,
}

/// Node configuration for dae-rs
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Node name
    pub name: String,
    /// Node type
    pub node_type: NodeType,
    /// Server address
    pub server: String,
    /// Server port
    pub port: u16,
    /// Encryption method (for Shadowsocks)
    pub method: Option<String>,
    /// Password (for Shadowsocks)
    pub password: Option<String>,
    /// UUID (for VMess, VLESS)
    pub uuid: Option<String>,
    /// Trojan password
    pub trojan_password: Option<String>,
    /// Security type (for VMess)
    pub security: Option<String>,
    /// TLS enabled
    pub tls: Option<bool>,
    /// TLS server name (SNI)
    pub tls_server_name: Option<String>,
    /// AEAD enabled (for VMess)
    pub aead: Option<bool>,
    /// Node capabilities
    pub capabilities: Option<NodeCapabilities>,
}

/// Node capabilities
#[derive(Debug, Clone)]
pub struct NodeCapabilities {
    /// Full-Cone NAT support
    pub fullcone: Option<bool>,
    /// UDP support
    pub udp: Option<bool>,
    /// V2Ray compatibility
    pub v2ray: Option<bool>,
}

/// Node type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Shadowsocks,
    Vless,
    Vmess,
    Trojan,
}

// =============================================================================
// Subscription Configuration
// =============================================================================

/// Subscription manager configuration
#[derive(Debug, Clone)]
pub struct SubscriptionConfig {
    /// Subscription URL
    pub url: String,
    /// Update interval
    pub update_interval: Duration,
    /// User agent for HTTP requests
    pub user_agent: String,
    /// TLS certificate verification.
    ///
    /// When `false`, TLS certificates are not verified (dangerous, not recommended).
    /// Applied automatically when using [`SubscriptionConfig::fetch_and_parse()`].
    pub verify_tls: bool,
    /// Timeout for requests
    pub timeout: Duration,
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            update_interval: Duration::from_secs(3600), // 1 hour
            user_agent: "dae-rs/0.1.0".to_string(),
            verify_tls: true,
            timeout: Duration::from_secs(30),
        }
    }
}

impl SubscriptionConfig {
    /// Create a new subscription config with URL
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            ..Default::default()
        }
    }

    /// Set update interval
    pub fn with_update_interval(mut self, interval: Duration) -> Self {
        self.update_interval = interval;
        self
    }

    /// Set custom user agent
    pub fn with_user_agent(mut self, user_agent: &str) -> Self {
        self.user_agent = user_agent.to_string();
        self
    }

    /// Disable TLS verification (not recommended)
    pub fn with_insecure_tls(mut self) -> Self {
        self.verify_tls = false;
        self
    }
}

impl SubscriptionConfig {
    /// Fetch and parse a subscription
    ///
    /// Makes an HTTP GET request to the subscription URL and parses
    /// the response. Respects `verify_tls` and `user_agent` settings.
    ///
    /// # Example
    /// ```ignore
    /// let config = SubscriptionConfig::new("https://example.com/sub");
    /// let update = config.fetch_and_parse().await?;
    /// ```
    pub async fn fetch_and_parse(&self) -> Result<SubscriptionUpdate, SubscriptionError> {
        let client = if self.verify_tls {
            reqwest::Client::builder()
                .user_agent(&self.user_agent)
                .timeout(self.timeout)
                .build()
                .map_err(|e| SubscriptionError::NetworkError(e.to_string()))?
        } else {
            reqwest::Client::builder()
                .user_agent(&self.user_agent)
                .timeout(self.timeout)
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| SubscriptionError::NetworkError(e.to_string()))?
        };

        let response = client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| SubscriptionError::NetworkError(e.to_string()))?;

        if response.status() == 401 {
            return Err(SubscriptionError::AuthenticationRequired);
        }

        if !response.status().is_success() {
            return Err(SubscriptionError::NetworkError(format!(
                "HTTP {}: {}",
                response.status().as_u16(),
                response.status().canonical_reason().unwrap_or("Unknown")
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| SubscriptionError::NetworkError(e.to_string()))?;

        let mut update = parse_subscription(&bytes)?;

        // Override detected tag with URL-based detection if not present
        if update.tag.is_none() {
            update.tag = extract_tag(&self.url, &bytes);
        }

        Ok(update)
    }

    /// Fetch raw subscription content (without parsing)
    pub async fn fetch_raw(&self) -> Result<Vec<u8>, SubscriptionError> {
        let client = if self.verify_tls {
            reqwest::Client::builder()
                .user_agent(&self.user_agent)
                .timeout(self.timeout)
                .build()
                .map_err(|e| SubscriptionError::NetworkError(e.to_string()))?
        } else {
            reqwest::Client::builder()
                .user_agent(&self.user_agent)
                .timeout(self.timeout)
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| SubscriptionError::NetworkError(e.to_string()))?
        };

        let response = client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| SubscriptionError::NetworkError(e.to_string()))?;

        if response.status() == 401 {
            return Err(SubscriptionError::AuthenticationRequired);
        }

        if !response.status().is_success() {
            return Err(SubscriptionError::NetworkError(format!(
                "HTTP {}: {}",
                response.status().as_u16(),
                response.status().canonical_reason().unwrap_or("Unknown")
            )));
        }

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| SubscriptionError::NetworkError(e.to_string()))
    }
}

// =============================================================================
// Auto-detection and Orchestration Functions
// =============================================================================

/// Auto-detect and parse subscription content
pub fn parse_subscription(content: &[u8]) -> Result<SubscriptionUpdate, SubscriptionError> {
    let content_str = String::from_utf8_lossy(content);
    let trimmed = content_str.trim();

    // Try to detect format based on content
    if trimmed.starts_with('{') {
        // Could be SIP008 or Sing-Box JSON
        if trimmed.contains("\"outbounds\"") {
            // Sing-Box JSON format
            if let Ok(links) = singbox::parse_singbox_json(&content_str) {
                if !links.is_empty() {
                    return Ok(SubscriptionUpdate {
                        tag: None,
                        links,
                        bytes_used: None,
                        bytes_remaining: None,
                        format_detected: SubscriptionType::SingBoxJson,
                    });
                }
            }
        }

        // Try SIP008
        if let Ok(update) = sip008::parse_sip008_subscription(content) {
            return Ok(update);
        }

        // If it starts with { but couldn't parse as SIP008, try as Sing-Box anyway
        if trimmed.contains("\"outbounds\"") || trimmed.contains("\"type\"") {
            if let Ok(links) = singbox::parse_singbox_json(&content_str) {
                if !links.is_empty() {
                    return Ok(SubscriptionUpdate {
                        tag: None,
                        links,
                        bytes_used: None,
                        bytes_remaining: None,
                        format_detected: SubscriptionType::SingBoxJson,
                    });
                }
            }
        }
    }

    if trimmed.starts_with("proxies:")
        || trimmed.starts_with("proxy-groups:")
        || trimmed.starts_with("proxy-providers:")
    {
        // Clash YAML format
        if let Ok(links) = clash::parse_clash_yaml(&content_str) {
            if !links.is_empty() {
                return Ok(SubscriptionUpdate {
                    tag: None,
                    links,
                    bytes_used: None,
                    bytes_remaining: None,
                    format_detected: SubscriptionType::ClashYaml,
                });
            }
        }
    }

    // Try as plain text URI list
    let links = encoding::parse_uri_list(&content_str)?;
    if !links.is_empty() {
        return Ok(SubscriptionUpdate {
            tag: None,
            links,
            bytes_used: None,
            bytes_remaining: None,
            format_detected: SubscriptionType::Base64,
        });
    }

    // Try base64 decoding
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(content) {
        let decoded_str = String::from_utf8_lossy(&decoded);
        let trimmed_decoded = decoded_str.trim();

        // Check decoded content
        if trimmed_decoded.starts_with('{') {
            // Try SIP008 on decoded
            if let Ok(update) = sip008::parse_sip008_subscription(&decoded) {
                return Ok(update);
            }
            // Try Sing-Box on decoded
            if let Ok(links) = singbox::parse_singbox_json(&decoded_str) {
                if !links.is_empty() {
                    return Ok(SubscriptionUpdate {
                        tag: None,
                        links,
                        bytes_used: None,
                        bytes_remaining: None,
                        format_detected: SubscriptionType::SingBoxJson,
                    });
                }
            }
        }

        if trimmed_decoded.starts_with("proxies:") {
            if let Ok(links) = clash::parse_clash_yaml(&decoded_str) {
                if !links.is_empty() {
                    return Ok(SubscriptionUpdate {
                        tag: None,
                        links,
                        bytes_used: None,
                        bytes_remaining: None,
                        format_detected: SubscriptionType::ClashYaml,
                    });
                }
            }
        }

        // Try URI list on decoded
        let links = encoding::parse_uri_list(&decoded_str)?;
        if !links.is_empty() {
            return Ok(SubscriptionUpdate {
                tag: None,
                links,
                bytes_used: None,
                bytes_remaining: None,
                format_detected: SubscriptionType::Base64,
            });
        }
    }

    Err(SubscriptionError::ParseError(
        "No valid proxy links found in subscription".to_string(),
    ))
}

/// Extract tag from subscription URL or content
pub fn extract_tag(url: &str, content: &[u8]) -> Option<String> {
    // Try to extract from URL fragment
    if let Some(frag) = url.split('#').nth(1) {
        let decoded = urlencoding::decode(frag).ok()?;
        if !decoded.is_empty() {
            return Some(decoded.to_string());
        }
    }

    // Try to extract from SIP008 content
    if let Ok(sip) = serde_json::from_slice::<sip008::Sip008Subscription>(content) {
        // Use first server's remarks as tag if no explicit tag
        if let Some(first) = sip.servers.first() {
            if let Some(ref remarks) = first.remarks {
                if !remarks.is_empty() {
                    return Some(remarks.clone());
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_subscription_auto_clash_yaml() {
        let yaml = r#"
proxies:
  - name: "Test"
    type: ss
    server: test.com
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: test123
"#;
        let result = parse_subscription(yaml.as_bytes());
        assert!(result.is_ok());
        let update = result.unwrap();
        assert_eq!(update.format_detected, SubscriptionType::ClashYaml);
    }

    #[test]
    fn test_parse_subscription_auto_singbox_json() {
        let json = r#"{
  "outbounds": [
    {"type": "trojan", "tag": "Test", "server": "test.com", "port": 443, "password": "test"}
  ]
}"#;
        let result = parse_subscription(json.as_bytes());
        assert!(result.is_ok());
        let update = result.unwrap();
        assert_eq!(update.format_detected, SubscriptionType::SingBoxJson);
    }

    #[test]
    fn test_parse_subscription_auto_sip008() {
        let content = br#"{"version": 1, "servers": []}"#;
        let result = parse_subscription(content);
        assert!(result.is_ok());
        let update = result.unwrap();
        assert_eq!(update.format_detected, SubscriptionType::Sip008);
    }

    #[test]
    fn test_subscription_config_defaults() {
        let config = SubscriptionConfig::default();
        assert_eq!(config.update_interval, Duration::from_secs(3600));
        assert!(config.verify_tls);
        assert_eq!(config.user_agent, "dae-rs/0.1.0");
    }

    #[test]
    fn test_subscription_config_builder() {
        let config = SubscriptionConfig::new("https://example.com/sub")
            .with_update_interval(Duration::from_secs(7200))
            .with_insecure_tls();

        assert_eq!(config.url, "https://example.com/sub");
        assert_eq!(config.update_interval, Duration::from_secs(7200));
        assert!(!config.verify_tls);
    }

    #[test]
    fn test_extract_tag_from_url() {
        let url = "https://example.com/sub#MyTag";
        let tag = extract_tag(url, b"");
        assert_eq!(tag, Some("MyTag".to_string()));
    }

    #[test]
    fn test_subscription_type_debug() {
        assert_eq!(format!("{:?}", SubscriptionType::Sip008), "Sip008");
        assert_eq!(format!("{:?}", SubscriptionType::Base64), "Base64");
        assert_eq!(format!("{:?}", SubscriptionType::ClashYaml), "ClashYaml");
        assert_eq!(
            format!("{:?}", SubscriptionType::SingBoxJson),
            "SingBoxJson"
        );
        assert_eq!(format!("{:?}", SubscriptionType::Auto), "Auto");
    }

    #[test]
    fn test_subscription_error_display() {
        let err = SubscriptionError::NetworkError("connection failed".to_string());
        assert!(format!("{}", err).contains("Network error"));

        let err = SubscriptionError::ParseError("invalid format".to_string());
        assert!(format!("{}", err).contains("Parse error"));

        let err = SubscriptionError::UnsupportedFormat;
        assert!(format!("{}", err).contains("Unsupported"));

        let err = SubscriptionError::UrlParseError("bad url".to_string());
        assert!(format!("{}", err).contains("URL parse error"));

        let err = SubscriptionError::UnsupportedUriScheme("xxx".to_string());
        assert!(format!("{}", err).contains("Unsupported URI scheme"));
    }

    #[test]
    fn test_parse_subscription_auto_base64_uri_list() {
        let raw = "ss://link1\nvmess://link2";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());

        let result = parse_subscription(encoded.as_bytes());
        assert!(result.is_ok());
        let update = result.unwrap();
        assert_eq!(update.links.len(), 2);
        assert_eq!(update.format_detected, SubscriptionType::Base64);
    }

    #[test]
    fn test_parse_subscription_auto_empty() {
        let content = b"   \n\n   ";
        let result = parse_subscription(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_subscription_auto_truly_empty_sip008() {
        let json = br#"{"version": 1, "servers": []}"#;
        let result = parse_subscription(json);
        assert!(result.is_ok());
        let update = result.unwrap();
        assert!(update.links.is_empty());
        assert_eq!(update.format_detected, SubscriptionType::Sip008);
    }

    #[test]
    fn test_extract_tag_from_sip008_content() {
        let json = br#"{
            "version": 1,
            "servers": [
                {"remarks": "First Server", "server": "1.1.1.1", "server_port": 443, "password": "x", "method": "aes-256-gcm"}
            ]
        }"#;
        let tag = extract_tag("", json);
        assert_eq!(tag, Some("First Server".to_string()));
    }

    #[test]
    fn test_extract_tag_priority_url_over_content() {
        let url = "https://example.com/sub#URLTag";
        let tag = extract_tag(url, b"something else");
        assert_eq!(tag, Some("URLTag".to_string()));
    }

    #[test]
    fn test_extract_tag_empty_url_fragment() {
        let url = "https://example.com/sub#";
        let tag = extract_tag(url, b"");
        assert!(tag.is_none());
    }

    #[test]
    fn test_node_config_debug() {
        let config = NodeConfig {
            name: "Test Node".to_string(),
            node_type: NodeType::Shadowsocks,
            server: "1.2.3.4".to_string(),
            port: 443,
            method: Some("aes-256-gcm".to_string()),
            password: Some("secret".to_string()),
            uuid: None,
            trojan_password: None,
            security: None,
            tls: Some(true),
            tls_server_name: Some("example.com".to_string()),
            aead: Some(true),
            capabilities: None,
        };
        let debug = format!("{:?}", config);
        assert!(debug.contains("Test Node"));
        assert!(debug.contains("Shadowsocks"));
    }

    #[test]
    fn test_node_capabilities() {
        let caps = NodeCapabilities {
            fullcone: Some(true),
            udp: Some(true),
            v2ray: Some(false),
        };
        let debug = format!("{:?}", caps);
        assert!(debug.contains("fullcone"));
    }

    #[test]
    fn test_subscription_update_debug() {
        let update = SubscriptionUpdate {
            tag: Some("MyTag".to_string()),
            links: vec!["ss://link1".to_string()],
            bytes_used: Some(1024),
            bytes_remaining: Some(2048),
            format_detected: SubscriptionType::ClashYaml,
        };
        let debug = format!("{:?}", update);
        assert!(debug.contains("MyTag"));
        assert!(debug.contains("1024"));
    }

    #[test]
    fn test_subscription_config_clone() {
        let config = SubscriptionConfig::new("https://example.com/sub")
            .with_update_interval(Duration::from_secs(7200))
            .with_insecure_tls();

        let cloned = config.clone();
        assert_eq!(cloned.url, config.url);
        assert_eq!(cloned.update_interval, config.update_interval);
        assert_eq!(cloned.verify_tls, config.verify_tls);
    }

    #[test]
    fn test_subscription_update_clone() {
        let update = SubscriptionUpdate {
            tag: None,
            links: vec!["ss://test".to_string()],
            bytes_used: None,
            bytes_remaining: None,
            format_detected: SubscriptionType::Base64,
        };
        let cloned = update.clone();
        assert_eq!(cloned.links.len(), 1);
        assert_eq!(cloned.format_detected, SubscriptionType::Base64);
    }

    #[test]
    fn test_subscription_config_new() {
        let config = SubscriptionConfig::new("https://example.com/subscription");
        assert_eq!(config.url, "https://example.com/subscription");
        assert_eq!(config.update_interval, Duration::from_secs(3600));
        assert!(config.verify_tls);
        assert_eq!(config.user_agent, "dae-rs/0.1.0");
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_subscription_config_builder_pattern() {
        let config = SubscriptionConfig::new("https://example.com/sub")
            .with_update_interval(Duration::from_secs(7200))
            .with_user_agent("CustomAgent/1.0")
            .with_insecure_tls();

        assert_eq!(config.url, "https://example.com/sub");
        assert_eq!(config.update_interval, Duration::from_secs(7200));
        assert_eq!(config.user_agent, "CustomAgent/1.0");
        assert!(
            !config.verify_tls,
            "with_insecure_tls should set verify_tls to false"
        );
    }

    #[test]
    fn test_subscription_config_default() {
        let config = SubscriptionConfig::default();
        assert!(config.url.is_empty());
        assert_eq!(config.update_interval, Duration::from_secs(3600));
        assert!(config.verify_tls);
        assert_eq!(config.user_agent, "dae-rs/0.1.0");
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_subscription_config_with_insecure_tls() {
        let config = SubscriptionConfig::new("http://insecure.example.com/sub").with_insecure_tls();
        assert!(!config.verify_tls);
    }

    #[test]
    fn test_subscription_config_update_interval() {
        let config = SubscriptionConfig::new("https://example.com/sub")
            .with_update_interval(Duration::from_secs(86400));
        assert_eq!(config.update_interval, Duration::from_secs(86400));
    }

    #[test]
    fn test_subscription_config_user_agent() {
        let config =
            SubscriptionConfig::new("https://example.com/sub").with_user_agent("Mozilla/5.0");
        assert_eq!(config.user_agent, "Mozilla/5.0");
    }
}
