//! URI parsing module for proxy links
//!
//! Handles parsing of various proxy URI schemes:
//! - ss:// (Shadowsocks)
//! - vmess:// (VMess)
//! - vless:// (VLESS)
//! - trojan:// (Trojan)

use base64::Engine;
use serde::Deserialize;

pub use super::NodeType;
use super::{NodeConfig, SubscriptionError};

/// Proxy protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    Shadowsocks,
    VMess,
    VLESS,
    Trojan,
}

impl ProxyProtocol {
    /// Convert to NodeType
    pub fn to_node_type(&self) -> NodeType {
        match self {
            ProxyProtocol::Shadowsocks => NodeType::Shadowsocks,
            ProxyProtocol::VMess => NodeType::Vmess,
            ProxyProtocol::VLESS => NodeType::Vless,
            ProxyProtocol::Trojan => NodeType::Trojan,
        }
    }
}

/// Parse a single proxy URI and convert to NodeConfig
pub fn uri_to_node_config(uri: &str) -> Result<NodeConfig, SubscriptionError> {
    // Remove fragment (name) if present
    let (uri_without_fragment, name) = if let Some(pos) = uri.find('#') {
        let fragment = &uri[pos + 1..];
        let decoded_name = urlencoding::decode(fragment)
            .unwrap_or_default()
            .to_string();
        (&uri[..pos], Some(decoded_name))
    } else {
        (uri, None)
    };

    if uri_without_fragment.starts_with("ss://") {
        parse_ss_uri(uri_without_fragment, name)
    } else if uri_without_fragment.starts_with("vmess://") {
        parse_vmess_uri(uri_without_fragment, name)
    } else if uri_without_fragment.starts_with("vless://") {
        parse_vless_uri(uri_without_fragment, name)
    } else if uri_without_fragment.starts_with("trojan://") {
        parse_trojan_uri(uri_without_fragment, name)
    } else {
        Err(SubscriptionError::UnsupportedUriScheme(
            uri.chars().take(20).collect(),
        ))
    }
}

/// Parse Shadowsocks URI
fn parse_ss_uri(uri: &str, name: Option<String>) -> Result<NodeConfig, SubscriptionError> {
    let uri_str = uri
        .strip_prefix("ss://")
        .ok_or_else(|| SubscriptionError::ParseError("Invalid ss:// URI".to_string()))?;

    // Format: ss://BASE64(method:password)@server:port?plugin=...#name
    // Find the @ separator
    let at_pos = uri_str.find('@').ok_or_else(|| {
        SubscriptionError::ParseError("Invalid Shadowsocks URI: missing @".to_string())
    })?;

    let user_info = &uri_str[..at_pos];
    let server_part = &uri_str[at_pos + 1..];

    // Parse method:password from user_info (base64 encoded)
    let decoded_user_info = match base64::engine::general_purpose::STANDARD.decode(user_info) {
        Ok(decoded) => String::from_utf8(decoded)
            .map_err(|e| SubscriptionError::ParseError(format!("Invalid SS user info: {e}")))?,
        Err(_) => {
            // Try URL-safe base64
            match base64::engine::general_purpose::URL_SAFE.decode(user_info) {
                Ok(decoded) => String::from_utf8(decoded).map_err(|e| {
                    SubscriptionError::ParseError(format!("Invalid SS user info: {e}"))
                })?,
                Err(_) => {
                    // Treat as plain user:password
                    user_info.to_string()
                }
            }
        }
    };

    let parts: Vec<&str> = decoded_user_info.split(':').collect();
    if parts.len() != 2 {
        return Err(SubscriptionError::ParseError(
            "Invalid Shadowsocks URI: expected method:password".to_string(),
        ));
    }

    let method = parts[0].to_string();
    let password = parts[1].to_string();

    // Parse server:port from server_part
    // server_part is like "1.2.3.4:8388" or "1.2.3.4:8388?plugin=..."
    let (server, port_str) = server_part.split_once(':').ok_or_else(|| {
        SubscriptionError::ParseError("Invalid Shadowsocks URI: missing port".to_string())
    })?;

    // Handle query params if present (e.g., ?plugin=...)
    let _plugin_opts = if let Some(query_pos) = server_part.find('?') {
        let query = &server_part[query_pos + 1..];
        let mut plugin_type = None;
        let mut plugin_options = std::collections::HashMap::new();

        for param in query.split('&') {
            if let Some(plugin_value) = param.strip_prefix("plugin=") {
                // Decode base64 plugin value (already stripped "plugin=")
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(plugin_value)
                {
                    let decoded_str = String::from_utf8_lossy(&decoded);
                    // Parse plugin options (format: plugin-name;opt1=value1;opt2=value2)
                    for (i, opt) in decoded_str.split(';').enumerate() {
                        if i == 0 {
                            plugin_type = Some(opt.to_string());
                        } else if let Some((key, value)) = opt.split_once('=') {
                            plugin_options.insert(key.to_string(), value.to_string());
                        } else if !opt.is_empty() {
                            // Boolean flags like "tls", "server"
                            plugin_options.insert(opt.to_string(), "true".to_string());
                        }
                    }
                }
            }
        }
        plugin_type.map(|pt| (pt, plugin_options))
    } else {
        None
    };

    let port: u16 = port_str
        .split_once('?')
        .map(|(p, _)| p)
        .unwrap_or(port_str)
        .parse()
        .map_err(|e| SubscriptionError::ParseError(format!("Invalid port: {e}")))?;

    Ok(NodeConfig {
        name: name.unwrap_or_else(|| "Shadowsocks".to_string()),
        node_type: NodeType::Shadowsocks,
        server: server.to_string(),
        port,
        method: Some(method),
        password: Some(password),
        uuid: None,
        trojan_password: None,
        security: None,
        tls: None,
        tls_server_name: None,
        aead: None,
        capabilities: None,
    })
}

/// Parse VMess URI
fn parse_vmess_uri(uri: &str, name: Option<String>) -> Result<NodeConfig, SubscriptionError> {
    let uri_str = uri
        .strip_prefix("vmess://")
        .ok_or_else(|| SubscriptionError::ParseError("Invalid vmess:// URI".to_string()))?;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(uri_str.as_bytes())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(uri_str.as_bytes()))
        .map_err(|e| SubscriptionError::ParseError(format!("Invalid VMess base64: {e}")))?;

    let json_str = String::from_utf8(decoded)
        .map_err(|e| SubscriptionError::ParseError(format!("Invalid VMess JSON: {e}")))?;

    #[derive(Deserialize)]
    struct VmessJson {
        #[allow(dead_code)]
        v: Option<String>,
        ps: Option<String>,
        add: Option<String>,
        port: Option<u16>,
        id: Option<String>,
        net: Option<String>,
        #[serde(rename = "type")]
        #[allow(dead_code)]
        type_: Option<String>,
        host: Option<String>,
        #[allow(dead_code)]
        path: Option<String>,
        tls: Option<String>,
    }

    let vmess: VmessJson = serde_json::from_str(&json_str)
        .map_err(|e| SubscriptionError::ParseError(format!("Invalid VMess JSON structure: {e}")))?;

    let node_name = name.or(vmess.ps).unwrap_or_else(|| "VMess".to_string());
    let server = vmess.add.ok_or_else(|| {
        SubscriptionError::ParseError("VMess URI missing server address".to_string())
    })?;
    let port = vmess
        .port
        .ok_or_else(|| SubscriptionError::ParseError("VMess URI missing port".to_string()))?;
    let uuid = vmess
        .id
        .ok_or_else(|| SubscriptionError::ParseError("VMess URI missing id (UUID)".to_string()))?;

    let tls_enabled = vmess.tls.as_deref().map(|t| !t.is_empty()).unwrap_or(false);
    let tls_server_name = if tls_enabled {
        vmess.host.clone()
    } else {
        None
    };

    Ok(NodeConfig {
        name: node_name,
        node_type: NodeType::Vmess,
        server,
        port,
        method: None,
        password: None,
        uuid: Some(uuid),
        trojan_password: None,
        security: vmess.net,
        tls: Some(tls_enabled),
        tls_server_name,
        aead: Some(true), // VMess AEAD is standard now
        capabilities: None,
    })
}

/// Parse VLESS URI
fn parse_vless_uri(uri: &str, name: Option<String>) -> Result<NodeConfig, SubscriptionError> {
    let uri_str = uri
        .strip_prefix("vless://")
        .ok_or_else(|| SubscriptionError::ParseError("Invalid vless:// URI".to_string()))?;

    // Format: vless://uuid@server:port?params#name
    let (user_at_server, fragment) = if let Some(pos) = uri_str.find('#') {
        (&uri_str[..pos], Some(&uri_str[pos + 1..]))
    } else {
        (uri_str, None)
    };

    let (uuid_at_server, query) = if let Some(pos) = user_at_server.find('?') {
        (&user_at_server[..pos], Some(&user_at_server[pos + 1..]))
    } else {
        (user_at_server, None)
    };

    let uuid_at = uuid_at_server
        .find('@')
        .ok_or_else(|| SubscriptionError::ParseError("Invalid VLESS URI: missing @".to_string()))?;

    let uuid = &uuid_at_server[..uuid_at];
    let server_port = &uuid_at_server[uuid_at + 1..];

    let (server, port_str) = server_port.rsplit_once(':').ok_or_else(|| {
        SubscriptionError::ParseError("Invalid VLESS URI: missing port".to_string())
    })?;

    let port: u16 = port_str
        .parse()
        .map_err(|e| SubscriptionError::ParseError(format!("Invalid VLESS port: {e}")))?;

    // Parse query parameters
    let mut sni = None;
    let mut _flow = None;
    let mut _skip_verify = false;

    if let Some(query) = query {
        for param in query.split('&') {
            let param_decoded = urlencoding::decode(param).unwrap_or_default();
            if let Some(stripped) = param_decoded.strip_prefix("sni=") {
                sni = Some(stripped.to_string());
            } else if let Some(stripped) = param_decoded.strip_prefix("flow=") {
                _flow = Some(stripped.to_string());
            } else if param_decoded.contains("allowInsecure=1") {
                _skip_verify = true;
            }
        }
    }

    let node_name = name
        .or_else(|| fragment.and_then(|f| urlencoding::decode(f).ok().map(|s| s.to_string())))
        .unwrap_or_else(|| "VLESS".to_string());

    Ok(NodeConfig {
        name: node_name,
        node_type: NodeType::Vless,
        server: server.to_string(),
        port,
        method: None,
        password: None,
        uuid: Some(uuid.to_string()),
        trojan_password: None,
        security: None,
        tls: Some(true),
        tls_server_name: sni,
        aead: Some(true),
        capabilities: None,
    })
}

/// Parse Trojan URI
fn parse_trojan_uri(uri: &str, name: Option<String>) -> Result<NodeConfig, SubscriptionError> {
    let uri_str = uri
        .strip_prefix("trojan://")
        .ok_or_else(|| SubscriptionError::ParseError("Invalid trojan:// URI".to_string()))?;

    // Format: trojan://password@server:port?params#name
    let (user_at_server, fragment) = if let Some(pos) = uri_str.find('#') {
        (&uri_str[..pos], Some(&uri_str[pos + 1..]))
    } else {
        (uri_str, None)
    };

    let (password, server_port) = user_at_server.split_once('@').ok_or_else(|| {
        SubscriptionError::ParseError("Invalid Trojan URI: missing @".to_string())
    })?;

    let decoded_password = urlencoding::decode(password)
        .unwrap_or_default()
        .to_string();

    let (server, port_and_query) = server_port.rsplit_once(':').ok_or_else(|| {
        SubscriptionError::ParseError("Invalid Trojan URI: missing port".to_string())
    })?;

    // Handle query params if present
    let (port_str, _query) = port_and_query
        .split_once('?')
        .unwrap_or((port_and_query, ""));

    let port: u16 = port_str
        .parse()
        .map_err(|e| SubscriptionError::ParseError(format!("Invalid Trojan port: {e}")))?;

    // Parse query parameters
    let mut sni = None;
    let mut _skip_verify = false;

    if let Some(query_pos) = server_port.find('?') {
        let query = &server_port[query_pos + 1..];
        for param in query.split('&') {
            let param_decoded = urlencoding::decode(param).unwrap_or_default();
            if let Some(stripped) = param_decoded.strip_prefix("sni=") {
                sni = Some(stripped.to_string());
            } else if param_decoded.contains("allowInsecure=1") {
                _skip_verify = true;
            }
        }
    }

    let node_name = name
        .or_else(|| fragment.and_then(|f| urlencoding::decode(f).ok().map(|s| s.to_string())))
        .unwrap_or_else(|| "Trojan".to_string());

    Ok(NodeConfig {
        name: node_name,
        node_type: NodeType::Trojan,
        server: server.to_string(),
        port,
        method: None,
        password: None,
        uuid: None,
        trojan_password: Some(decoded_password),
        security: None,
        tls: Some(true),
        tls_server_name: sni,
        aead: None,
        capabilities: None,
    })
}

/// Convert URIs to NodeConfig list
pub fn uris_to_node_configs(uris: &[String]) -> Result<Vec<NodeConfig>, SubscriptionError> {
    let mut configs = Vec::new();
    for uri in uris {
        match uri_to_node_config(uri) {
            Ok(config) => configs.push(config),
            Err(e) => {
                // Log error but continue parsing other URIs
                eprintln!("Warning: Failed to parse URI '{uri}': {e}");
            }
        }
    }
    Ok(configs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uri_to_node_config_ss() {
        // ss://method:password@server:port#name
        // Use properly padded base64 encoding of "aes-256-gcm:password123"
        let user_info = "aes-256-gcm:password123";
        let encoded = base64::engine::general_purpose::STANDARD.encode(user_info.as_bytes());
        let uri = format!("ss://{}@1.2.3.4:8388#Test%20Server", encoded);
        let result = uri_to_node_config(&uri);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.node_type, NodeType::Shadowsocks);
        assert_eq!(config.server, "1.2.3.4");
        assert_eq!(config.port, 8388);
        assert_eq!(config.name, "Test Server");
    }

    #[test]
    fn test_uri_to_node_config_trojan() {
        // trojan://password@server:port#name
        let uri = "trojan://mypassword@1.2.3.4:443?sni=example.com#Trojan%20Server";
        let result = uri_to_node_config(uri);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.node_type, NodeType::Trojan);
        assert_eq!(config.server, "1.2.3.4");
        assert_eq!(config.port, 443);
        assert_eq!(config.trojan_password, Some("mypassword".to_string()));
    }

    #[test]
    fn test_uri_to_node_config_vmess() {
        // vmess://base64-json
        let vmess_json = serde_json::json!({
            "v": "2",
            "ps": "Test VMess",
            "add": "1.2.3.4",
            "port": 443,
            "id": "12345678-1234-1234-1234-123456789012",
            "net": "tcp",
            "type": "none",
            "host": "",
            "path": "",
            "tls": "tls"
        });
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(vmess_json.to_string().as_bytes());
        let uri = format!("vmess://{}", encoded);
        let result = uri_to_node_config(&uri);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.node_type, NodeType::Vmess);
        assert_eq!(config.server, "1.2.3.4");
        assert_eq!(config.port, 443);
    }

    #[test]
    fn test_uri_to_node_config_vless() {
        // vless://uuid@server:port?params#name
        let uri = "vless://12345678-1234-1234-1234-123456789012@1.2.3.4:443?sni=example.com#VLESS%20Server";
        let result = uri_to_node_config(uri);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.node_type, NodeType::Vless);
        assert_eq!(config.server, "1.2.3.4");
        assert_eq!(config.port, 443);
        assert_eq!(
            config.uuid,
            Some("12345678-1234-1234-1234-123456789012".to_string())
        );
    }

    #[test]
    fn test_uri_to_node_config_unsupported_scheme() {
        let result = uri_to_node_config("https://example.com");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SubscriptionError::UnsupportedUriScheme(_)
        ));
    }

    #[test]
    fn test_uri_to_node_config_ss_invalid_base64() {
        let uri = "ss://!!!invalid-base64!!!@1.2.3.4:8388#Test";
        let result = uri_to_node_config(uri);
        assert!(result.is_err());
    }

    #[test]
    fn test_uri_to_node_config_ss_plain_userinfo() {
        let uri = "ss://plain:text@1.2.3.4:8388#Test";
        let result = uri_to_node_config(uri);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.node_type, NodeType::Shadowsocks);
        assert_eq!(config.method.as_deref(), Some("plain"));
        assert_eq!(config.password.as_deref(), Some("text"));
    }

    #[test]
    fn test_uri_to_node_config_vmess_invalid_base64() {
        let uri = "vmess://!!!invalid!!!";
        let result = uri_to_node_config(uri);
        assert!(result.is_err());
    }

    #[test]
    fn test_uri_to_node_config_vmess_missing_server() {
        let json = serde_json::json!({
            "v": "2",
            "ps": "Test",
            "port": 443,
            "id": "12345678-1234-1234-1234-123456789012"
        });
        let encoded = base64::engine::general_purpose::STANDARD.encode(json.to_string().as_bytes());
        let uri = format!("vmess://{}", encoded);
        let result = uri_to_node_config(&uri);
        assert!(result.is_err());
    }

    #[test]
    fn test_uri_to_node_config_vless_invalid() {
        let uri = "vless://no-at-sign";
        let result = uri_to_node_config(uri);
        assert!(result.is_err());
    }

    #[test]
    fn test_uri_to_node_config_trojan_no_at() {
        let uri = "trojan://no-at-sign";
        let result = uri_to_node_config(uri);
        assert!(result.is_err());
    }

    #[test]
    fn test_uris_to_node_configs() {
        let user_info = "aes-256-gcm:password123";
        let encoded = base64::engine::general_purpose::STANDARD.encode(user_info.as_bytes());
        let ss_uri = format!("ss://{}@1.2.3.4:8388#Test1", encoded);
        let uris = vec![ss_uri, "trojan://mypassword@5.6.7.8:443#Test2".to_string()];
        let result = uris_to_node_configs(&uris);
        assert!(result.is_ok());
        let configs = result.unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].node_type, NodeType::Shadowsocks);
        assert_eq!(configs[1].node_type, NodeType::Trojan);
    }

    #[test]
    fn test_proxy_protocol_to_node_type() {
        assert_eq!(
            ProxyProtocol::Shadowsocks.to_node_type(),
            NodeType::Shadowsocks
        );
        assert_eq!(ProxyProtocol::VMess.to_node_type(), NodeType::Vmess);
        assert_eq!(ProxyProtocol::VLESS.to_node_type(), NodeType::Vless);
        assert_eq!(ProxyProtocol::Trojan.to_node_type(), NodeType::Trojan);
    }
}
