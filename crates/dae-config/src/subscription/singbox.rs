//! Sing-Box JSON subscription format parsing module
//!
//! Sing-Box is a universal proxy platform that uses JSON configuration files.
//! This module handles parsing Sing-Box subscription format.

use base64::Engine;
use serde::Deserialize;

use super::SubscriptionError;

/// Sing-Box outbound entry
#[derive(Debug, Clone, Deserialize)]
pub struct SingBoxOutbound {
    /// Outbound type
    #[serde(rename = "type")]
    pub type_: String,
    /// Tag/name
    pub tag: Option<String>,
    /// Server address
    pub server: Option<String>,
    /// Server port
    pub port: Option<u16>,
    /// Password (for Trojan, Shadowsocks)
    #[serde(default)]
    pub password: Option<String>,
    /// Method (for Shadowsocks)
    #[serde(default)]
    pub method: Option<String>,
    /// UUID (for VMess, VLESS)
    #[serde(default)]
    pub uuid: Option<String>,
    /// TLS server name
    #[serde(default, rename = "tls-server-name")]
    pub tls_server_name: Option<String>,
    /// Skip TLS certificate verification
    #[serde(default, rename = "skip-cert-verify")]
    pub skip_cert_verify: Option<bool>,
    /// Enable TLS
    #[serde(default)]
    pub tls: Option<bool>,
    /// VLESS flow
    #[serde(default)]
    pub flow: Option<String>,
    /// Network (for VMess)
    #[serde(default)]
    pub network: Option<String>,
    /// WebSocket path (for VMess)
    #[serde(default, rename = "ws-path")]
    pub ws_path: Option<String>,
    /// Multiplexing (for Sing-Box)
    #[serde(default)]
    pub multiplex: Option<serde_json::Value>,
}

/// Sing-Box subscription format
#[derive(Debug, Clone, Deserialize)]
pub struct SingBoxSubscription {
    /// Outbounds
    pub outbounds: Option<Vec<SingBoxOutbound>>,
}

/// Parse Sing-Box JSON subscription content
pub fn parse_singbox_json(content: &str) -> Result<Vec<String>, SubscriptionError> {
    let sub: SingBoxSubscription = serde_json::from_str(content).map_err(|e| {
        SubscriptionError::ParseError(format!("Failed to parse Sing-Box JSON: {e}"))
    })?;

    let outbounds = sub.outbounds.ok_or_else(|| {
        SubscriptionError::ParseError("No outbounds found in Sing-Box subscription".to_string())
    })?;

    let links: Vec<String> = outbounds
        .iter()
        .filter_map(singbox_outbound_to_uri)
        .collect();

    Ok(links)
}

/// Convert a Sing-Box outbound to URI format
pub fn singbox_outbound_to_uri(outbound: &SingBoxOutbound) -> Option<String> {
    let name = outbound.tag.as_deref()?;
    let name_encoded = urlencoding::encode(name);
    let server = outbound.server.as_deref()?;
    let port = outbound.port.unwrap_or(443);

    match outbound.type_.to_lowercase().as_str() {
        "trojan" => {
            let password = outbound.password.as_deref().unwrap_or("");
            let sni = outbound.tls_server_name.as_deref().unwrap_or("");
            let skip_verify = outbound.skip_cert_verify.unwrap_or(false);
            let mut uri = format!(
                "trojan://{}@{}:{}",
                urlencoding::encode(password),
                server,
                port
            );

            if !sni.is_empty() {
                uri.push_str(&format!("?sni={}", urlencoding::encode(sni)));
            }
            if skip_verify {
                uri.push_str("&allowInsecure=1");
            }

            uri.push_str(&format!("#{name_encoded}"));
            Some(uri)
        }
        "shadowsocks" => {
            let method = outbound
                .method
                .as_deref()
                .unwrap_or("chacha20-ietf-poly1305");
            let password = outbound.password.as_deref().unwrap_or("");
            let user_info = format!("{method}:{password}");
            let encoded = base64::engine::general_purpose::STANDARD.encode(user_info.as_bytes());
            let mut uri = format!("ss://{encoded}@{server}:{port}");
            uri.push_str(&format!("#{name_encoded}"));
            Some(uri)
        }
        "vmess" => {
            let uuid = outbound.uuid.as_deref().unwrap_or("");
            let sni = outbound.tls_server_name.as_deref().unwrap_or("");
            let network = outbound.network.as_deref().unwrap_or("tcp");
            let tls = outbound.tls.unwrap_or(false);

            #[derive(serde::Serialize)]
            struct VmessJson<'a> {
                v: &'a str,
                ps: &'a str,
                add: &'a str,
                port: u16,
                id: &'a str,
                net: &'a str,
                #[serde(rename = "type")]
                type_: &'a str,
                host: &'a str,
                path: &'a str,
                tls: &'a str,
            }

            let json = VmessJson {
                v: "2",
                ps: name,
                add: server,
                port,
                id: uuid,
                net: network,
                type_: "none",
                host: sni,
                path: "",
                tls: if tls { "tls" } else { "" },
            };

            let json_str = serde_json::to_string(&json).ok()?;
            let encoded = base64::engine::general_purpose::STANDARD.encode(json_str.as_bytes());
            Some(format!("vmess://{encoded}"))
        }
        "vless" => {
            let uuid = outbound.uuid.as_deref().unwrap_or("");
            let sni = outbound.tls_server_name.as_deref().unwrap_or("");
            let flow = outbound.flow.as_deref().unwrap_or("");
            let skip_verify = outbound.skip_cert_verify.unwrap_or(false);
            let mut uri = format!("vless://{uuid}@{server}:{port}");

            let mut params = Vec::new();
            if !sni.is_empty() {
                params.push(format!("sni={}", urlencoding::encode(sni)));
            }
            if !flow.is_empty() {
                params.push(format!("flow={}", urlencoding::encode(flow)));
            }
            if skip_verify {
                params.push("allowInsecure=1".to_string());
            }

            if !params.is_empty() {
                uri.push_str(&format!("?{}", params.join("&")));
            }

            uri.push_str(&format!("#{name_encoded}"));
            Some(uri)
        }
        _ => None, // Unsupported outbound type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_singbox_json_trojan() {
        let json = r#"{
  "outbounds": [
    {
      "type": "trojan",
      "tag": "香港",
      "server": "hk.example.com",
      "port": 443,
      "password": "xxxxx"
    }
  ]
}"#;
        let result = parse_singbox_json(json).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].starts_with("trojan://"));
    }

    #[test]
    fn test_parse_singbox_json_ss() {
        let json = r#"{
  "outbounds": [
    {
      "type": "shadowsocks",
      "tag": "日本",
      "server": "jp.example.com",
      "port": 8388,
      "method": "chacha20-ietf-poly1305",
      "password": "xxxxx"
    }
  ]
}"#;
        let result = parse_singbox_json(json).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].starts_with("ss://"));
    }

    #[test]
    fn test_parse_singbox_json_vless() {
        let json = r#"{
  "outbounds": [
    {
      "type": "vless",
      "tag": "美国",
      "server": "us.example.com",
      "port": 443,
      "uuid": "12345678-1234-1234-1234-123456789012",
      "flow": "xtls-rprx-vision"
    }
  ]
}"#;
        let result = parse_singbox_json(json).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].starts_with("vless://"));
    }

    #[test]
    fn test_parse_singbox_json_unsupported_outbound() {
        let json = r#"{
  "outbounds": [
    {"type": "wireguard", "tag": "Unsupported", "server": "test.com", "port": 443}
  ]
}"#;
        let result = parse_singbox_json(json).unwrap();
        assert!(result.is_empty());
    }
}
