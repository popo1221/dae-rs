//! SIP008 subscription format parsing module
//!
//! SIP008 is a JSON-based subscription format for Shadowsocks servers.
//! Reference: https://github.com/shadowsocks/shadowsocks-org/wiki/SIP008

use base64::Engine;
use serde::{Deserialize, Serialize};

use super::{SubscriptionError, SubscriptionType, SubscriptionUpdate};

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

/// Parse a SIP008 subscription
pub fn parse_sip008_subscription(content: &[u8]) -> Result<SubscriptionUpdate, SubscriptionError> {
    let sip: Sip008Subscription = serde_json::from_slice(content)
        .map_err(|e| SubscriptionError::ParseError(format!("Failed to parse SIP008 JSON: {e}")))?;

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
            let user_info = format!("{}:{}", server.method, server.password);
            let encoded = base64::engine::general_purpose::STANDARD.encode(user_info.as_bytes());
            let mut url = format!("ss://{}@{}:{}", encoded, server.server, server.server_port);

            // Add plugin if present
            if let Some(ref plugin) = server.plugin {
                if !plugin.is_empty() {
                    let opts = server.plugin_opts.as_deref().unwrap_or("");
                    url.push_str(&format!(
                        "?plugin={}",
                        urlencoding::encode(&format!("{plugin};{opts}"))
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
    fn test_parse_sip008_invalid_version() {
        let json = br#"{
            "version": 2,
            "servers": []
        }"#;

        let result = parse_sip008_subscription(json);
        assert!(result.is_err());
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
    fn test_sip008_server_deserialization() {
        let json = r#"{
            "id": "srv-001",
            "remarks": "Test Server",
            "server": "test.example.com",
            "server_port": 8443,
            "password": "supersecret",
            "method": "chacha20-ietf-poly1305",
            "plugin": "v2ray-plugin",
            "plugin_opts": "tls;host=example.com"
        }"#;

        let server: Sip008Server = serde_json::from_str(json).unwrap();
        assert_eq!(server.id.as_deref(), Some("srv-001"));
        assert_eq!(server.remarks.as_deref(), Some("Test Server"));
        assert_eq!(server.server, "test.example.com");
        assert_eq!(server.server_port, 8443);
        assert_eq!(server.method, "chacha20-ietf-poly1305");
        assert_eq!(server.plugin.as_deref(), Some("v2ray-plugin"));
        assert_eq!(server.plugin_opts.as_deref(), Some("tls;host=example.com"));
    }

    #[test]
    fn test_sip008_server_minimal() {
        let json = r#"{
            "server": "1.2.3.4",
            "server_port": 443,
            "password": "pwd",
            "method": "aes-256-gcm"
        }"#;

        let server: Sip008Server = serde_json::from_str(json).unwrap();
        assert!(server.id.is_none());
        assert!(server.remarks.is_none());
        assert!(server.plugin.is_none());
        assert!(server.plugin_opts.is_none());
    }
}
