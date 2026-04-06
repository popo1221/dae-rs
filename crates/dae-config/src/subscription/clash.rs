//! Clash YAML subscription format parsing module
//!
//! Clash is a rule-based proxy client that uses YAML configuration files.
//! This module handles parsing Clash subscription format.

use base64::Engine;
use serde::{Deserialize, Serialize};

use super::SubscriptionError;

/// Clash proxy item (singular)
#[derive(Debug, Clone, Deserialize)]
pub struct ClashProxy {
    /// Node name
    pub name: String,
    /// Node type
    #[serde(rename = "type")]
    pub type_: String,
    /// Server address
    pub server: String,
    /// Server port
    pub port: u16,
    /// Password (for Trojan, VMess, VLESS)
    #[serde(default)]
    pub password: Option<String>,
    /// Encryption method (for Shadowsocks)
    #[serde(default)]
    pub cipher: Option<String>,
    /// UUID (for VMess, VLESS)
    #[serde(default)]
    pub uuid: Option<String>,
    /// Alter ID (for VMess)
    #[serde(default, rename = "alterId")]
    pub alter_id: Option<u16>,
    /// Security type (for VMess)
    #[serde(default)]
    pub security: Option<String>,
    /// SNI/TLS server name
    #[serde(default)]
    pub sni: Option<String>,
    /// TLS server name (alias for sni)
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
    /// Network type (for VMess)
    #[serde(default)]
    pub network: Option<String>,
    /// WebSocket path (for VMess)
    #[serde(default, rename = "ws-path")]
    pub ws_path: Option<String>,
    /// WebSocket host (for VMess)
    #[serde(default, rename = "ws-headers")]
    pub ws_headers: Option<std::collections::HashMap<String, String>>,
    /// Plugin (for Shadowsocks)
    #[serde(default)]
    pub plugin: Option<String>,
    /// Plugin options (for Shadowsocks)
    #[serde(default, rename = "plugin-opts")]
    pub plugin_opts: Option<String>,
}

/// Clash subscription format
#[derive(Debug, Clone, Deserialize)]
pub struct ClashSubscription {
    /// Proxy servers
    pub proxies: Option<Vec<ClashProxy>>,
    /// Proxy groups (not directly used)
    #[serde(default, rename = "proxy-groups")]
    pub proxy_groups: Option<Vec<serde_json::Value>>,
}

/// Parse Clash YAML subscription content
pub fn parse_clash_yaml(content: &str) -> Result<Vec<String>, SubscriptionError> {
    let sub: ClashSubscription = serde_yaml::from_str(content)
        .map_err(|e| SubscriptionError::ParseError(format!("Failed to parse Clash YAML: {e}")))?;

    let proxies = sub.proxies.ok_or_else(|| {
        SubscriptionError::ParseError("No proxies found in Clash subscription".to_string())
    })?;

    let links: Vec<String> = proxies.iter().map(clash_proxy_to_uri).collect();

    Ok(links)
}

/// Convert a Clash proxy to URI format
pub fn clash_proxy_to_uri(proxy: &ClashProxy) -> String {
    let name_encoded = urlencoding::encode(&proxy.name);

    match proxy.type_.to_lowercase().as_str() {
        "ss" => {
            // Shadowsocks: ss://method:password@server:port
            let method = proxy.cipher.as_deref().unwrap_or("chacha20-ietf-poly1305");
            let password = proxy.password.as_deref().unwrap_or("");
            let user_info = format!("{method}:{password}");
            let encoded = base64::engine::general_purpose::STANDARD.encode(user_info.as_bytes());
            let mut uri = format!("ss://{encoded}@{}:{}", proxy.server, proxy.port);

            // Add plugin if present
            if let Some(ref plugin) = proxy.plugin {
                if !plugin.is_empty() {
                    let opts = proxy.plugin_opts.as_deref().unwrap_or("");
                    uri.push_str(&format!(
                        "?plugin={}",
                        urlencoding::encode(&format!("{plugin};{opts}"))
                    ));
                }
            }

            uri.push_str(&format!("#{name_encoded}"));
            uri
        }
        "trojan" => {
            // Trojan: trojan://password@server:port
            let password = proxy.password.as_deref().unwrap_or("");
            let sni = proxy
                .sni
                .as_deref()
                .or(proxy.tls_server_name.as_deref())
                .unwrap_or("");
            let skip_verify = proxy.skip_cert_verify.unwrap_or(false);
            let mut uri = format!(
                "trojan://{}@{}:{}",
                urlencoding::encode(password),
                proxy.server,
                proxy.port
            );

            if !sni.is_empty() {
                uri.push_str(&format!("?sni={}", urlencoding::encode(sni)));
            }
            if skip_verify {
                uri.push_str("&allowInsecure=1");
            }

            uri.push_str(&format!("#{name_encoded}"));
            uri
        }
        "vmess" => {
            // VMess: vmess://base64-json
            let uuid = proxy.uuid.as_deref().unwrap_or("");
            let _security = proxy.security.as_deref().unwrap_or("auto");
            let _alter_id = proxy.alter_id.unwrap_or(0);
            let sni = proxy
                .sni
                .as_deref()
                .or(proxy.tls_server_name.as_deref())
                .unwrap_or("");
            let network = proxy.network.as_deref().unwrap_or("tcp");
            let ws_path = proxy.ws_path.as_deref().unwrap_or("");
            let tls = proxy.tls.unwrap_or(false);

            #[derive(Serialize)]
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
                ps: &proxy.name,
                add: proxy.server.as_str(),
                port: proxy.port,
                id: uuid,
                net: network,
                type_: "none",
                host: sni,
                path: ws_path,
                tls: if tls { "tls" } else { "" },
            };

            let json_str = serde_json::to_string(&json).unwrap_or_default();
            let encoded = base64::engine::general_purpose::STANDARD.encode(json_str.as_bytes());
            format!("vmess://{encoded}")
        }
        "vless" => {
            // VLESS: vless://uuid@server:port?params#name
            let uuid = proxy.uuid.as_deref().unwrap_or("");
            let sni = proxy
                .sni
                .as_deref()
                .or(proxy.tls_server_name.as_deref())
                .unwrap_or("");
            let flow = proxy.flow.as_deref().unwrap_or("");
            let skip_verify = proxy.skip_cert_verify.unwrap_or(false);
            let mut uri = format!("vless://{}@{}:{}", uuid, proxy.server, proxy.port);

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
            uri
        }
        _ => {
            // Unsupported type, return empty or encode what we can
            format!("#Unsupported type: {}", proxy.type_)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_clash_yaml_trojan() {
        let yaml = r#"
proxies:
  - name: "香港节点"
    type: trojan
    server: hk.example.com
    port: 443
    password: mypassword
    sni: example.com
    skip-cert-verify: false
"#;
        let result = parse_clash_yaml(yaml).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].starts_with("trojan://"));
    }

    #[test]
    fn test_parse_clash_yaml_ss() {
        let yaml = r#"
proxies:
  - name: "日本节点"
    type: ss
    server: jp.example.com
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: mypassword
"#;
        let result = parse_clash_yaml(yaml).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].starts_with("ss://"));
    }

    #[test]
    fn test_parse_clash_yaml_vmess() {
        let yaml = r#"
proxies:
  - name: "美国节点"
    type: vmess
    server: us.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    alterId: 0
    cipher: auto
"#;
        let result = parse_clash_yaml(yaml).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].starts_with("vmess://"));
    }

    #[test]
    fn test_parse_clash_yaml_vless() {
        let yaml = r#"
proxies:
  - name: "台湾节点"
    type: vless
    server: tw.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    flow: xtls-rprx-vision
"#;
        let result = parse_clash_yaml(yaml).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].starts_with("vless://"));
    }

    #[test]
    fn test_parse_clash_yaml_unsupported_type() {
        let yaml = r#"
proxies:
  - name: "Unknown"
    type: unknown-type
    server: test.com
    port: 443
"#;
        let result = parse_clash_yaml(yaml);
        assert!(result.is_ok());
        let links = result.unwrap();
        assert!(links[0].starts_with("#Unsupported type:"));
    }

    #[test]
    fn test_clash_proxy_vmess_with_ws() {
        let yaml = r#"
proxies:
  - name: "WS VMess"
    type: vmess
    server: example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    alterId: 0
    cipher: auto
    network: ws
    ws-path: /v2
    ws-headers:
      Host: example.com
    tls: true
"#;
        let result = parse_clash_yaml(yaml).unwrap();
        assert_eq!(result.len(), 1);
        let uri = &result[0];
        assert!(uri.starts_with("vmess://"));
        let encoded = uri.strip_prefix("vmess://").unwrap();
        let decoded_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .unwrap();
        let decoded = String::from_utf8(decoded_bytes).unwrap();
        // The ws-path becomes "path" in the VMess JSON blob
        assert!(decoded.contains(r#""path":"/v2"#) || decoded.contains("/v2"));
    }

    #[test]
    fn test_clash_proxy_vless_with_flow() {
        // VLESS serialization DOES include flow parameter
        let yaml = r#"
proxies:
  - name: "XTLS VLESS"
    type: vless
    server: example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    flow: xtls-rprx-vision
"#;
        let result = parse_clash_yaml(yaml).unwrap();
        assert_eq!(result.len(), 1);
        let uri = &result[0];
        assert!(uri.starts_with("vless://"));
        assert!(uri.contains("flow="));
    }
}
