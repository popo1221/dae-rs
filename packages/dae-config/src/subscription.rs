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

use base64::Engine;
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
            SubscriptionError::NetworkError(s) => write!(f, "Network error: {}", s),
            SubscriptionError::ParseError(s) => write!(f, "Parse error: {}", s),
            SubscriptionError::UnsupportedFormat => write!(f, "Unsupported subscription format"),
            SubscriptionError::AuthenticationRequired => write!(f, "Authentication required"),
            SubscriptionError::UrlParseError(s) => write!(f, "URL parse error: {}", s),
            SubscriptionError::UnsupportedUriScheme(s) => {
                write!(f, "Unsupported URI scheme: {}", s)
            }
        }
    }
}

impl std::error::Error for SubscriptionError {}

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
    ///
    /// TODO (#63): This field is read by fetch logic but not yet applied to the
    /// HTTP client. Set to `false` to disable TLS verification (not recommended).
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

// =============================================================================
// Clap YAML Subscription Types
// =============================================================================

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

// =============================================================================
// Sing-Box JSON Subscription Types
// =============================================================================

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

// =============================================================================
// URI Parsing Types
// =============================================================================

/// Parsed proxy URI
#[derive(Debug, Clone)]
pub struct ParsedProxyUri {
    /// Protocol type
    pub protocol: ProxyProtocol,
    /// Server address
    pub server: String,
    /// Server port
    pub port: u16,
    /// Node name (from fragment)
    pub name: Option<String>,
    /// Method (for Shadowsocks)
    pub method: Option<String>,
    /// Password/secret
    pub password: Option<String>,
    /// UUID (for VMess, VLESS)
    pub uuid: Option<String>,
    /// Security (for VMess)
    pub security: Option<String>,
    /// TLS server name
    pub tls_server_name: Option<String>,
    /// TLS enabled
    pub tls: bool,
    /// VLESS flow
    pub flow: Option<String>,
    /// Additional plugin info
    pub plugin: Option<String>,
}

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

/// Node type enumeration (re-export from lib.rs)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Shadowsocks,
    Vless,
    Vmess,
    Trojan,
}

// =============================================================================
// Parsing Functions
// =============================================================================

/// Parse a base64-encoded subscription
pub fn parse_base64_subscription(content: &[u8]) -> Result<Vec<String>, SubscriptionError> {
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

    parse_uri_list(&content_str)
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

/// Parse Clash YAML subscription content
pub fn parse_clash_yaml(content: &str) -> Result<Vec<String>, SubscriptionError> {
    let sub: ClashSubscription = serde_yaml::from_str(content)
        .map_err(|e| SubscriptionError::ParseError(format!("Failed to parse Clash YAML: {}", e)))?;

    let proxies = sub.proxies.ok_or_else(|| {
        SubscriptionError::ParseError("No proxies found in Clash subscription".to_string())
    })?;

    let links: Vec<String> = proxies
        .iter()
        .map(|proxy| clash_proxy_to_uri(proxy))
        .collect();

    Ok(links)
}

/// Convert a Clash proxy to URI format
fn clash_proxy_to_uri(proxy: &ClashProxy) -> String {
    let name_encoded = urlencoding::encode(&proxy.name);

    match proxy.type_.to_lowercase().as_str() {
        "ss" => {
            // Shadowsocks: ss://method:password@server:port
            let method = proxy.cipher.as_deref().unwrap_or("chacha20-ietf-poly1305");
            let password = proxy.password.as_deref().unwrap_or("");
            let user_info = format!("{}:{}", method, password);
            let encoded = base64::engine::general_purpose::STANDARD.encode(user_info.as_bytes());
            let mut uri = format!("ss://{}@{}:{}", encoded, proxy.server, proxy.port);

            // Add plugin if present
            if let Some(ref plugin) = proxy.plugin {
                if !plugin.is_empty() {
                    let opts = proxy.plugin_opts.as_deref().unwrap_or("");
                    uri.push_str(&format!(
                        "?plugin={}",
                        urlencoding::encode(&format!("{};{}", plugin, opts))
                    ));
                }
            }

            uri.push_str(&format!("#{}", name_encoded));
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

            uri.push_str(&format!("#{}", name_encoded));
            uri
        }
        "vmess" => {
            // VMess: vmess://base64-json
            let uuid = proxy.uuid.as_deref().unwrap_or("");
            let security = proxy.security.as_deref().unwrap_or("auto");
            let alter_id = proxy.alter_id.unwrap_or(0);
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
            format!("vmess://{}", encoded)
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

            uri.push_str(&format!("#{}", name_encoded));
            uri
        }
        _ => {
            // Unsupported type, return empty or encode what we can
            format!("#Unsupported type: {}", proxy.type_)
        }
    }
}

/// Parse Sing-Box JSON subscription content
pub fn parse_singbox_json(content: &str) -> Result<Vec<String>, SubscriptionError> {
    let sub: SingBoxSubscription = serde_json::from_str(content).map_err(|e| {
        SubscriptionError::ParseError(format!("Failed to parse Sing-Box JSON: {}", e))
    })?;

    let outbounds = sub.outbounds.ok_or_else(|| {
        SubscriptionError::ParseError("No outbounds found in Sing-Box subscription".to_string())
    })?;

    let links: Vec<String> = outbounds
        .iter()
        .filter_map(|outbound| singbox_outbound_to_uri(outbound))
        .collect();

    Ok(links)
}

/// Convert a Sing-Box outbound to URI format
fn singbox_outbound_to_uri(outbound: &SingBoxOutbound) -> Option<String> {
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

            uri.push_str(&format!("#{}", name_encoded));
            Some(uri)
        }
        "shadowsocks" => {
            let method = outbound
                .method
                .as_deref()
                .unwrap_or("chacha20-ietf-poly1305");
            let password = outbound.password.as_deref().unwrap_or("");
            let user_info = format!("{}:{}", method, password);
            let encoded = base64::engine::general_purpose::STANDARD.encode(user_info.as_bytes());
            let mut uri = format!("ss://{}@{}:{}", encoded, server, port);
            uri.push_str(&format!("#{}", name_encoded));
            Some(uri)
        }
        "vmess" => {
            let uuid = outbound.uuid.as_deref().unwrap_or("");
            let sni = outbound.tls_server_name.as_deref().unwrap_or("");
            let network = outbound.network.as_deref().unwrap_or("tcp");
            let tls = outbound.tls.unwrap_or(false);

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
            Some(format!("vmess://{}", encoded))
        }
        "vless" => {
            let uuid = outbound.uuid.as_deref().unwrap_or("");
            let sni = outbound.tls_server_name.as_deref().unwrap_or("");
            let flow = outbound.flow.as_deref().unwrap_or("");
            let skip_verify = outbound.skip_cert_verify.unwrap_or(false);
            let mut uri = format!("vless://{}@{}:{}", uuid, server, port);

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

            uri.push_str(&format!("#{}", name_encoded));
            Some(uri)
        }
        _ => None, // Unsupported outbound type
    }
}

/// Parse URI list from content
pub fn parse_uri_list(content: &str) -> Result<Vec<String>, SubscriptionError> {
    let mut links = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Filter to valid proxy URIs
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
            .map_err(|e| SubscriptionError::ParseError(format!("Invalid SS user info: {}", e)))?,
        Err(_) => {
            // Try URL-safe base64
            match base64::engine::general_purpose::URL_SAFE.decode(user_info) {
                Ok(decoded) => String::from_utf8(decoded).map_err(|e| {
                    SubscriptionError::ParseError(format!("Invalid SS user info: {}", e))
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
    let _plugin = if let Some(query_pos) = server_part.find('?') {
        let query = &server_part[query_pos + 1..];
        for param in query.split('&') {
            if param.starts_with("plugin=") {
                // Could parse plugin options here if needed
            }
        }
        Some(query)
    } else {
        None
    };

    let port: u16 = port_str
        .split_once('?')
        .map(|(p, _)| p)
        .unwrap_or(port_str)
        .parse()
        .map_err(|e| SubscriptionError::ParseError(format!("Invalid port: {}", e)))?;

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
        .map_err(|e| SubscriptionError::ParseError(format!("Invalid VMess base64: {}", e)))?;

    let json_str = String::from_utf8(decoded)
        .map_err(|e| SubscriptionError::ParseError(format!("Invalid VMess JSON: {}", e)))?;

    #[derive(Deserialize)]
    struct VmessJson {
        v: Option<String>,
        ps: Option<String>,
        add: Option<String>,
        port: Option<u16>,
        id: Option<String>,
        net: Option<String>,
        #[serde(rename = "type")]
        type_: Option<String>,
        host: Option<String>,
        path: Option<String>,
        tls: Option<String>,
    }

    let vmess: VmessJson = serde_json::from_str(&json_str).map_err(|e| {
        SubscriptionError::ParseError(format!("Invalid VMess JSON structure: {}", e))
    })?;

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
        .map_err(|e| SubscriptionError::ParseError(format!("Invalid VLESS port: {}", e)))?;

    // Parse query parameters
    let mut sni = None;
    let mut flow = None;
    let mut skip_verify = false;

    if let Some(query) = query {
        for param in query.split('&') {
            let param_decoded = urlencoding::decode(param).unwrap_or_default();
            if param_decoded.starts_with("sni=") {
                sni = Some(param_decoded[4..].to_string());
            } else if param_decoded.starts_with("flow=") {
                flow = Some(param_decoded[5..].to_string());
            } else if param_decoded.contains("allowInsecure=1") {
                skip_verify = true;
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
        .map_err(|e| SubscriptionError::ParseError(format!("Invalid Trojan port: {}", e)))?;

    // Parse query parameters
    let mut sni = None;
    let mut skip_verify = false;

    if let Some(query_pos) = server_port.find('?') {
        let query = &server_port[query_pos + 1..];
        for param in query.split('&') {
            let param_decoded = urlencoding::decode(param).unwrap_or_default();
            if param_decoded.starts_with("sni=") {
                sni = Some(param_decoded[4..].to_string());
            } else if param_decoded.contains("allowInsecure=1") {
                skip_verify = true;
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
                eprintln!("Warning: Failed to parse URI '{}': {}", uri, e);
            }
        }
    }
    Ok(configs)
}

/// Auto-detect and parse subscription content
pub fn parse_subscription(content: &[u8]) -> Result<SubscriptionUpdate, SubscriptionError> {
    let content_str = String::from_utf8_lossy(content);
    let trimmed = content_str.trim();

    // Try to detect format based on content
    if trimmed.starts_with('{') {
        // Could be SIP008 or Sing-Box JSON
        if trimmed.contains("\"outbounds\"") {
            // Sing-Box JSON format
            if let Ok(links) = parse_singbox_json(&content_str) {
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
        if let Ok(update) = parse_sip008_subscription(content) {
            return Ok(update);
        }

        // If it starts with { but couldn't parse as SIP008, try as Sing-Box anyway
        if trimmed.contains("\"outbounds\"") || trimmed.contains("\"type\"") {
            if let Ok(links) = parse_singbox_json(&content_str) {
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
        if let Ok(links) = parse_clash_yaml(&content_str) {
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
    let links = parse_uri_list(&content_str)?;
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
            if let Ok(update) = parse_sip008_subscription(&decoded) {
                return Ok(update);
            }
            // Try Sing-Box on decoded
            if let Ok(links) = parse_singbox_json(&decoded_str) {
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
            if let Ok(links) = parse_clash_yaml(&decoded_str) {
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
        let links = parse_uri_list(&decoded_str)?;
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
    fn test_parse_uri_list() {
        let content = r#"
ss://example1
vmess://example2
vless://example3
trojan://example4
"#;
        let result = parse_uri_list(content).unwrap();
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_uri_to_node_config_ss() {
        // ss://method:password@server:port#name
        // Use properly padded base64 encoding of "aes-256-gcm:password123"
        use base64::Engine;
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
    fn test_parse_base64_subscription_empty_lines() {
        // Valid base64 encoded content with URI links and empty lines
        // "ss://link1\n\nss://link2" encoded
        use base64::Engine;
        let raw_content = b"ss://link1\n\nss://link2";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw_content);
        let content = encoded.as_bytes();
        let result = parse_base64_subscription(content);
        assert!(result.is_ok());
        let links = result.unwrap();
        assert_eq!(links.len(), 2);
    }

    #[test]
    fn test_parse_base64_invalid_base64() {
        let content = b"not-valid-base64!!!";
        let result = parse_base64_subscription(content);
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
    fn test_parse_sip008_invalid_version() {
        let json = br#"{
            "version": 2,
            "servers": []
        }"#;

        let result = parse_sip008_subscription(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_uris_to_node_configs() {
        use base64::Engine;
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
}
