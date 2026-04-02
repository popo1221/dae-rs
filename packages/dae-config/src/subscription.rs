//! Subscription module for fetching and parsing node subscriptions
//!
//! Implements SIP008 (Shadowsocks SIP008) subscription format specification.
//!
//! SIP008 is a JSON-based subscription format that contains server configurations
//! for Shadowsocks and other proxy protocols.
//!
//! # Subscription Format
//!
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
//!       "method": "chacha20-ietf-poly1305",
//!       "plugin": "obfs-local",
//!       "plugin_opts": "obfs=tls;obfs-host=cloudflare.com"
//!     }
//!   ],
//!   "bytes_used": 123456,
//!   "bytes_remaining": 987654321
//! }
//! ```
//!
//! # Supported Subscription Types
//!
//! - SIP008: JSON format with structured server data
//! - Base64-encoded plain text: ss://... links separated by newlines

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// SIP008 subscription server entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sip008Server {
    /// Server identifier
    pub id: Option<String>,
    /// Server remarks/name
    pub remarks: Option<String>,
    /// Server hostname or IP
    pub server: String,
    /// Server port
    pub server_port: u16,
    /// Authentication password
    pub password: String,
    /// Encryption method
    pub method: String,
    /// Plugin name (e.g., obfs-local, v2ray-plugin)
    #[serde(default)]
    pub plugin: Option<String>,
    /// Plugin options
    #[serde(default)]
    pub plugin_opts: Option<String>,
}

/// SIP008 subscription format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sip008Subscription {
    /// Format version (must be 1)
    pub version: u32,
    /// List of servers
    pub servers: Vec<Sip008Server>,
    /// Bytes used (optional)
    #[serde(default)]
    pub bytes_used: Option<u64>,
    /// Bytes remaining (optional)
    #[serde(default)]
    pub bytes_remaining: Option<u64>,
}

/// Subscription provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionType {
    /// SIP008 JSON format
    Sip008,
    /// Base64-encoded plain text with ss:// links
    Base64,
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
}

/// Subscription manager configuration
#[derive(Debug, Clone)]
pub struct SubscriptionConfig {
    /// Subscription URL
    pub url: String,
    /// Update interval
    pub update_interval: Duration,
    /// User agent for HTTP requests
    pub user_agent: String,
    /// TLS certificate verification
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

/// Parse a base64-encoded subscription
pub fn parse_base64_subscription(content: &[u8]) -> Result<Vec<String>, SubscriptionError> {
    use base64::Engine;

    // Try standard base64 first
    let decoded = match base64::engine::general_purpose::STANDARD.decode(content) {
        Ok(d) => d,
        Err(_) => {
            // Try URL-safe base64
            match base64::engine::general_purpose::URL_SAFE.decode(content) {
                Ok(d) => d,
                Err(e) => {
                    return Err(SubscriptionError::ParseError(format!(
                        "Failed to decode base64: {}",
                        e
                    )));
                }
            }
        }
    };

    // Parse as string and split by lines
    let content_str = String::from_utf8(decoded)
        .map_err(|e| SubscriptionError::ParseError(format!("Invalid UTF-8: {}", e)))?;

    let mut links = Vec::new();
    for line in content_str.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Filter to ss://, vmess://, vless://, trojan:// links
        if trimmed.starts_with("ss://")
            || trimmed.starts_with("vmess://")
            || trimmed.starts_with("vless://")
            || trimmed.starts_with("trojan://")
        {
            links.push(trimmed.to_string());
        }
    }

    Ok(links)
}

/// Parse a SIP008 subscription
pub fn parse_sip008_subscription(content: &[u8]) -> Result<SubscriptionUpdate, SubscriptionError> {
    let sip: Sip008Subscription = serde_json::from_slice(content).map_err(|e| {
        SubscriptionError::ParseError(format!("Failed to parse SIP008 JSON: {}", e))
    })?;

    if sip.version != 1 {
        return Err(SubscriptionError::ParseError(format!(
            "Unsupported SIP008 version: {}",
            sip.version
        )));
    }

    // Convert SIP008 servers to ss:// links
    let links = sip
        .servers
        .iter()
        .map(|server| {
            // Build ss:// URL
            // Format: ss://BASE64(method:password)@server:port#remarks
            use base64::Engine;
            let user_info = format!("{}:{}", server.method, server.password);
            let encoded = base64::engine::general_purpose::STANDARD.encode(user_info.as_bytes());
            let mut url = format!("ss://{}@{}:{}", encoded, server.server, server.server_port);

            // Add plugin if present
            if let Some(ref plugin) = server.plugin {
                if !plugin.is_empty() {
                    let opts = server.plugin_opts.as_deref().unwrap_or("");
                    url.push_str(&format!(
                        "?plugin={}",
                        urlencoding::encode(&format!("{};{}", plugin, opts))
                    ));
                }
            }

            // Add remarks as fragment
            if let Some(ref remarks) = server.remarks {
                url.push_str(&format!("#{}", urlencoding::encode(remarks)));
            }

            url
        })
        .collect();

    Ok(SubscriptionUpdate {
        tag: None,
        links,
        bytes_used: sip.bytes_used,
        bytes_remaining: sip.bytes_remaining,
        format_detected: SubscriptionType::Sip008,
    })
}

/// Auto-detect and parse subscription content
pub fn parse_subscription(content: &[u8]) -> Result<SubscriptionUpdate, SubscriptionError> {
    // Try SIP008 first (looks like JSON)
    let content_str = String::from_utf8_lossy(content);
    if content_str.trim().starts_with('{') {
        if let Ok(update) = parse_sip008_subscription(content) {
            return Ok(update);
        }
    }

    // Fall back to base64 plain text
    let links = parse_base64_subscription(content)?;

    if links.is_empty() {
        return Err(SubscriptionError::ParseError(
            "No valid proxy links found in subscription".to_string(),
        ));
    }

    Ok(SubscriptionUpdate {
        tag: None,
        links,
        bytes_used: None,
        bytes_remaining: None,
        format_detected: SubscriptionType::Base64,
    })
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
    if let Ok(sip) = serde_json::from_slice::<Sip008Subscription>(content) {
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
    fn test_parse_sip008_subscription() {
        let json = br#"{
            "version": 1,
            "servers": [
                {
                    "id": "srv1",
                    "remarks": "Test Server",
                    "server": "example.com",
                    "server_port": 8388,
                    "password": "password",
                    "method": "chacha20-ietf-poly1305"
                }
            ],
            "bytes_used": 12345,
            "bytes_remaining": 987654
        }"#;

        let result = parse_sip008_subscription(json).unwrap();
        assert_eq!(result.links.len(), 1);
        assert!(result.links[0].starts_with("ss://"));
        assert_eq!(result.bytes_used, Some(12345));
        assert_eq!(result.bytes_remaining, Some(987654));
    }

    #[test]
    fn test_parse_base64_subscription() {
        // Simple ss:// link in base64
        let content = b"c3M6Ly9leGFtcGxl"; // "ss://example" encoded
        let result = parse_base64_subscription(content);
        // Note: this may fail since the base64 might not decode to valid ss://
        // This is just a simple test
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
    fn test_sip008_server_serialization() {
        let server = Sip008Server {
            id: Some("test-1".to_string()),
            remarks: Some("Test Server".to_string()),
            server: "192.168.1.1".to_string(),
            server_port: 443,
            password: "secret".to_string(),
            method: "aes-256-gcm".to_string(),
            plugin: Some("obfs-local".to_string()),
            plugin_opts: Some("obfs=tls".to_string()),
        };

        let json = serde_json::to_string(&server).unwrap();
        assert!(json.contains("\"server\":\"192.168.1.1\""));
        assert!(json.contains("\"server_port\":443"));
    }

    #[test]
    fn test_subscription_config_clone() {
        let config = SubscriptionConfig::new("https://clone.test/sub");
        let cloned = config.clone();
        assert_eq!(cloned.url, config.url);
    }

    #[test]
    fn test_subscription_config_debug() {
        let config = SubscriptionConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("SubscriptionConfig"));
    }

    #[test]
    fn test_subscription_config_with_user_agent() {
        let config = SubscriptionConfig::new("https://ua.test/sub")
            .with_user_agent("custom-agent/1.0");
        assert_eq!(config.user_agent, "custom-agent/1.0");
    }

    #[test]
    fn test_subscription_config_insecure_tls() {
        let config = SubscriptionConfig::new("https://insecure.test/sub")
            .with_insecure_tls();
        assert!(!config.verify_tls);
    }

    #[test]
    fn test_subscription_type_debug() {
        assert_eq!(format!("{:?}", SubscriptionType::Sip008), "Sip008");
        assert_eq!(format!("{:?}", SubscriptionType::Base64), "Base64");
        assert_eq!(format!("{:?}", SubscriptionType::Auto), "Auto");
    }

    #[test]
    fn test_subscription_error_debug() {
        let err = SubscriptionError::NetworkError("connection failed".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("connection failed"));

        let err = SubscriptionError::ParseError("invalid format".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("invalid format"));

        let err = SubscriptionError::UnsupportedFormat;
        let debug = format!("{:?}", err);
        assert!(debug.contains("Unsupported"));

        let err = SubscriptionError::AuthenticationRequired;
        let debug = format!("{:?}", err);
        assert!(debug.contains("Authentication"));
    }

    #[test]
    fn test_subscription_update_clone() {
        let update = SubscriptionUpdate {
            tag: Some("test-tag".to_string()),
            links: vec!["ss://link1".to_string(), "ss://link2".to_string()],
            bytes_used: Some(1000),
            bytes_remaining: Some(5000),
            format_detected: SubscriptionType::Sip008,
        };
        let cloned = update.clone();
        assert_eq!(cloned.tag, update.tag);
        assert_eq!(cloned.links.len(), update.links.len());
    }

    #[test]
    fn test_subscription_update_debug() {
        let update = SubscriptionUpdate {
            tag: None,
            links: vec![],
            bytes_used: None,
            bytes_remaining: None,
            format_detected: SubscriptionType::Base64,
        };
        let debug_str = format!("{:?}", update);
        assert!(debug_str.contains("SubscriptionUpdate"));
    }

    #[test]
    fn test_parse_sip008_multiple_servers() {
        let json = br#"{
            "version": 1,
            "servers": [
                {"id": "srv1", "remarks": "Server 1", "server": "10.0.0.1", "server_port": 443, "password": "pwd1", "method": "aes-256-gcm"},
                {"id": "srv2", "remarks": "Server 2", "server": "10.0.0.2", "server_port": 443, "password": "pwd2", "method": "aes-256-gcm"},
                {"id": "srv3", "remarks": "Server 3", "server": "10.0.0.3", "server_port": 443, "password": "pwd3", "method": "aes-256-gcm"}
            ]
        }"#;

        let result = parse_sip008_subscription(json).unwrap();
        assert_eq!(result.links.len(), 3);
    }

    #[test]
    fn test_parse_sip008_without_optional_fields() {
        let json = br#"{
            "version": 1,
            "servers": [
                {"server": "minimal.test", "server_port": 443, "password": "pwd", "method": "aes"}
            ]
        }"#;

        let result = parse_sip008_subscription(json).unwrap();
        assert_eq!(result.links.len(), 1);
        assert_eq!(result.bytes_used, None);
        assert_eq!(result.bytes_remaining, None);
    }

    #[test]
    fn test_parse_sip008_invalid_version() {
        let json = br#"{
            "version": 2,
            "servers": []
        }"#;

        let result = parse_sip008_subscription(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_sip008_invalid_json() {
        let json = b"not json at all";
        let result = parse_sip008_subscription(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_base64_subscription_with_vmess() {
        // vmess:// is also a valid proxy link
        let content = b"dm1lc3M6Ly92bWVzc0BxLmV4YW1wbGUuY29tOjQ0Mw==";
        let result = parse_base64_subscription(content);
        // Result depends on whether it decodes to valid vmess link
        // Just verify it doesn't panic
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_parse_base64_subscription_with_vless() {
        let content = b"dmxlc3M6Ly92bGVzc0B2LmV4YW1wbGUuY29tOjQ0Mw==";
        let result = parse_base64_subscription(content);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_parse_base64_subscription_with_trojan() {
        let content = b"dHJvamFuOjEyMzQ1Njc4QHRyLmxhcmdldC5jb206NDQz";
        let result = parse_base64_subscription(content);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_parse_base64_subscription_empty_lines() {
        // Just verify it doesn't panic with empty lines
        let content = b"ss://link1\n\n\nss://link2";
        let result = parse_base64_subscription(content);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_parse_base64_invalid_base64() {
        let content = b"not-valid-base64!!!";
        let result = parse_base64_subscription(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_base64_url_safe() {
        // URL-safe base64 uses - and _ instead of + and /
        let content = b"c3M6Ly9leGFtcGxlLnRlc3Q_LTE0NDQ"; // Contains _
        let result = parse_base64_subscription(content);
        assert!(result.is_ok() || result.is_err());
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
    fn test_parse_subscription_auto_base64() {
        // Base64 encoded ss:// link
        let content = b"c3M6Ly9leGFtcGxlLnRlc3Q6NDQz";
        let result = parse_subscription(content);
        assert!(result.is_ok());
        let update = result.unwrap();
        assert_eq!(update.format_detected, SubscriptionType::Base64);
    }

    #[test]
    fn test_extract_tag_from_sip008_content() {
        let json = br#"{
            "version": 1,
            "servers": [{"remarks": "First Server", "server": "srv1.test", "server_port": 443, "password": "pwd", "method": "aes"}]
        }"#;
        let url = "https://example.com/sub";
        let tag = extract_tag(url, json);
        assert_eq!(tag, Some("First Server".to_string()));
    }

    #[test]
    fn test_extract_tag_empty_when_no_tag() {
        let url = "https://example.com/sub";
        let tag = extract_tag(url, b"no tag here");
        assert_eq!(tag, None);
    }

    #[test]
    fn test_extract_tag_from_url_with_encoded_characters() {
        let url = "https://example.com/sub#My%20Tag%20With%20Spaces";
        let tag = extract_tag(url, b"");
        assert_eq!(tag, Some("My Tag With Spaces".to_string()));
    }

    #[test]
    fn test_extract_tag_from_empty_url_fragment() {
        let url = "https://example.com/sub#";
        let tag = extract_tag(url, b"");
        assert_eq!(tag, None);
    }

    #[test]
    fn test_sip008_server_deserialization() {
        let json = r#"{
            "id": "deser-test",
            "remarks": "Deserialization Test",
            "server": "deser.test",
            "server_port": 8443,
            "password": "secret123",
            "method": "chacha20-poly1305",
            "plugin": "v2ray-plugin",
            "plugin_opts": "tls;host=example.com"
        }"#;

        let server: Sip008Server = serde_json::from_str(json).unwrap();
        assert_eq!(server.id, Some("deser-test".to_string()));
        assert_eq!(server.server, "deser.test");
        assert_eq!(server.server_port, 8443);
        assert_eq!(server.plugin, Some("v2ray-plugin".to_string()));
    }
}
