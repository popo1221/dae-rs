//! dae-config library - Configuration parsing and validation for dae-rs

use serde::Deserialize;
use std::path::Path;

pub mod rules;
pub mod subscription;
pub mod tracking;
pub mod types;

pub use rules::{RuleConfig, RuleConfigItem, RuleGroupConfig};
pub use subscription::SubscriptionConfig;
pub use tracking::TrackingConfig;
pub use types::{ConfigError, LogLevel, NodeType};

/// Subscription entry for automatic node updates
#[derive(Debug, Clone, Deserialize)]
pub struct SubscriptionEntry {
    /// Subscription URL (required)
    pub url: String,
    /// Update interval in seconds (default: 3600 = 1 hour)
    #[serde(default = "default_subscription_interval")]
    pub update_interval_secs: u64,
    /// Enable TLS certificate verification (default: true)
    #[serde(default = "default_true")]
    pub verify_tls: bool,
    /// Custom user agent (optional, uses dae-rs default if not set)
    #[serde(default)]
    pub user_agent: Option<String>,
    /// Optional name/alias for this subscription
    #[serde(default)]
    pub name: Option<String>,
    /// Tags to apply to all nodes from this subscription
    /// Nodes fetched from this subscription will inherit these tags
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_subscription_interval() -> u64 {
    3600 // 1 hour
}

/// Main configuration structure for dae-rs
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Proxy configuration section
    #[serde(default)]
    pub proxy: ProxyConfig,
    /// Upstream nodes/proxy servers
    #[serde(default)]
    pub nodes: Vec<NodeConfig>,
    /// Subscription URLs for automatic node updates
    #[serde(default)]
    pub subscriptions: Vec<SubscriptionEntry>,
    /// Rules configuration
    #[serde(default)]
    pub rules: RulesConfig,
    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
    /// Transparent proxy configuration (TUN device)
    #[serde(default)]
    pub transparent_proxy: TransparentProxyConfig,
    /// Tracking/monitoring configuration
    #[serde(default)]
    pub tracking: TrackingConfig,
}

/// Proxy configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    /// SOCKS5 listen address
    #[serde(default = "default_socks5_listen")]
    pub socks5_listen: String,
    /// HTTP proxy listen address
    #[serde(default = "default_http_listen")]
    pub http_listen: String,
    /// TCP connection timeout in seconds
    #[serde(default = "default_tcp_timeout")]
    pub tcp_timeout: u64,
    /// UDP session timeout in seconds
    #[serde(default = "default_udp_timeout")]
    pub udp_timeout: u64,
    /// eBPF interface to attach
    #[serde(default = "default_ebpf_interface")]
    pub ebpf_interface: String,
    /// Enable eBPF integration
    #[serde(default = "default_true")]
    pub ebpf_enabled: bool,
    /// Control socket path
    #[serde(default = "default_control_socket")]
    pub control_socket: String,
    /// PID file path
    #[serde(default)]
    pub pid_file: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            socks5_listen: default_socks5_listen(),
            http_listen: default_http_listen(),
            tcp_timeout: default_tcp_timeout(),
            udp_timeout: default_udp_timeout(),
            ebpf_interface: default_ebpf_interface(),
            ebpf_enabled: true,
            control_socket: default_control_socket(),
            pid_file: None,
        }
    }
}

/// Transparent proxy configuration (TUN device)
#[derive(Debug, Clone, Deserialize)]
pub struct TransparentProxyConfig {
    /// Enable transparent proxy via TUN device
    #[serde(default)]
    pub enabled: bool,
    /// TUN interface name
    #[serde(default = "default_tun_interface")]
    pub tun_interface: String,
    /// TUN device IP address
    #[serde(default = "default_tun_ip")]
    pub tun_ip: String,
    /// TUN netmask
    #[serde(default = "default_tun_netmask")]
    pub tun_netmask: String,
    /// MTU for TUN device
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    /// DNS hijack server addresses (IPs to intercept DNS queries to)
    #[serde(default)]
    pub dns_hijack: Vec<String>,
    /// DNS upstream servers (for hijacked queries)
    #[serde(default)]
    pub dns_upstream: Vec<String>,
    /// TCP connection timeout in seconds
    #[serde(default = "default_tcp_timeout")]
    pub tcp_timeout: u64,
    /// UDP session timeout in seconds
    #[serde(default = "default_udp_timeout")]
    pub udp_timeout: u64,
    /// Enable automatic routing (setup routing rules automatically)
    #[serde(default = "default_true")]
    pub auto_route: bool,
}

impl Default for TransparentProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tun_interface: default_tun_interface(),
            tun_ip: default_tun_ip(),
            tun_netmask: default_tun_netmask(),
            mtu: default_mtu(),
            dns_hijack: default_dns_hijack(),
            dns_upstream: default_dns_upstream(),
            tcp_timeout: default_tcp_timeout(),
            udp_timeout: default_udp_timeout(),
            auto_route: default_auto_route(),
        }
    }
}

/// Rules configuration
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RulesConfig {
    /// External rules config file
    #[serde(default)]
    pub config_file: Option<String>,
    /// Inline rule groups (alternative to config_file)
    #[serde(default)]
    pub rule_groups: Vec<RuleGroupConfig>,
}

/// Logging configuration
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log file path (none for stdout)
    #[serde(default)]
    pub file: Option<String>,
    /// Enable structured logging
    #[serde(default = "default_true")]
    pub structured: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file: None,
            structured: true,
        }
    }
}

/// Node capabilities - detected features of a proxy node
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NodeCapabilities {
    /// Full-Cone NAT support (for VMess/VLESS)
    #[serde(default)]
    pub fullcone: Option<bool>,
    /// UDP protocol support
    #[serde(default)]
    pub udp: Option<bool>,
    /// V2Ray compatibility (for VMess/VLESS)
    #[serde(default)]
    pub v2ray: Option<bool>,
}

impl NodeCapabilities {
    /// Create new empty capabilities
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if fullcone is enabled (None means unknown/auto-detect)
    pub fn is_fullcone_enabled(&self) -> bool {
        self.fullcone.unwrap_or(false)
    }

    /// Check if UDP is supported (None means unknown/auto-detect)
    pub fn is_udp_supported(&self) -> bool {
        self.udp.unwrap_or(true) // Default to true if not specified
    }

    /// Check if V2Ray compatible (None means unknown/auto-detect)
    pub fn is_v2ray_compatible(&self) -> bool {
        self.v2ray.unwrap_or(true) // Default to true if not specified
    }
}

/// Upstream node/proxy server configuration
#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    /// Node name/identifier
    pub name: String,
    /// Node type
    #[serde(rename = "type")]
    pub node_type: NodeType,
    /// Server address (IP or domain)
    pub server: String,
    /// Server port
    pub port: u16,
    /// Shadowsocks specific: encryption method
    #[serde(default)]
    pub method: Option<String>,
    /// Shadowsocks specific: password
    #[serde(default)]
    pub password: Option<String>,
    /// VLESS/VMess specific: UUID
    #[serde(default)]
    pub uuid: Option<String>,
    /// Trojan specific: password
    #[serde(default)]
    pub trojan_password: Option<String>,
    /// VMess specific: security type
    #[serde(default)]
    pub security: Option<String>,
    /// Enable TLS
    #[serde(default)]
    pub tls: Option<bool>,
    /// TLS server name (SNI)
    #[serde(default)]
    pub tls_server_name: Option<String>,
    /// VLESS/VMess specific: enable AEAD
    #[serde(default)]
    pub aead: Option<bool>,
    /// Node capabilities (fullcone, udp, v2ray)
    #[serde(default)]
    pub capabilities: Option<NodeCapabilities>,
    /// Node tags/labels for grouping and rule matching
    /// Example: tags = ["hk", "proxy", "fullcone"]
    #[serde(default)]
    pub tags: Vec<String>,
}

impl NodeConfig {
    /// Get the display address (server:port)
    pub fn display_addr(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }
}

/// Legacy configuration structures (for backwards compatibility)
#[derive(Debug, Deserialize)]
pub struct LegacyConfig {
    pub global: GlobalConfig,
    pub proxy: Vec<ProxyLegacyConfig>,
    #[serde(default)]
    pub shadowsocks: Vec<ShadowsocksServerConfig>,
    #[serde(default)]
    pub vless: Vec<VlessServerConfig>,
    #[serde(default)]
    pub vmess: Vec<VmessServerConfig>,
    #[serde(default)]
    pub trojan: Vec<TrojanServerConfig>,
}

#[derive(Debug, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Deserialize)]
pub struct ProxyLegacyConfig {
    pub name: String,
    pub proto: String,
    pub addr: String,
}

/// Shadowsocks server/node configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ShadowsocksServerConfig {
    /// Server name/identifier
    pub name: String,
    /// Server address (IP or domain)
    pub addr: String,
    /// Server port
    pub port: u16,
    /// Encryption method (chacha20-ietf-poly1305, aes-256-gcm, aes-128-gcm)
    pub method: String,
    /// Password/key
    pub password: String,
    /// Enable OTA (One-Time Auth) - default false
    #[serde(default)]
    pub ota: bool,
}

/// Shadowsocks client configuration
#[derive(Debug, Clone)]
pub struct ShadowsocksClientConfig {
    /// Local listen address
    pub listen_addr: String,
    /// Server address
    pub server_addr: String,
    /// Server port
    pub server_port: u16,
    /// Encryption method
    pub method: String,
    /// Password
    pub password: String,
    /// Enable OTA
    pub ota: bool,
}

impl ShadowsocksClientConfig {
    /// Create from ShadowsocksServerConfig with local listen address
    pub fn from_server_config(listen_addr: &str, server: &ShadowsocksServerConfig) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            server_addr: server.addr.clone(),
            server_port: server.port,
            method: server.method.clone(),
            password: server.password.clone(),
            ota: server.ota,
        }
    }
}

/// VLESS server/node configuration
#[derive(Debug, Clone, Deserialize)]
pub struct VlessServerConfig {
    /// Server name/identifier
    pub name: String,
    /// Server address (IP or domain)
    pub addr: String,
    /// Server port
    pub port: u16,
    /// UUID for authentication
    pub uuid: String,
    /// TLS settings (optional)
    #[serde(default)]
    pub tls: Option<VlessTlsConfig>,
}

impl VlessServerConfig {
    /// Create a VlessServerConfig with minimal settings
    pub fn new(name: &str, addr: &str, port: u16, uuid: &str) -> Self {
        Self {
            name: name.to_string(),
            addr: addr.to_string(),
            port,
            uuid: uuid.to_string(),
            tls: None,
        }
    }
}

/// VLESS TLS configuration
#[derive(Debug, Clone, Deserialize)]
pub struct VlessTlsConfig {
    /// Enable TLS (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// TLS version
    #[serde(default = "default_tls_version")]
    pub version: String,
    /// Server name for SNI
    #[serde(default)]
    pub server_name: Option<String>,
    /// ALPN protocols
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
}

/// VLESS client configuration
#[derive(Debug, Clone)]
pub struct VlessClientConfig {
    /// Local listen address
    pub listen_addr: String,
    /// Server address
    pub server_addr: String,
    /// Server port
    pub server_port: u16,
    /// UUID
    pub uuid: String,
    /// TLS enabled
    pub tls_enabled: bool,
}

impl VlessClientConfig {
    /// Create from VlessServerConfig with local listen address
    pub fn from_server_config(listen_addr: &str, server: &VlessServerConfig) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            server_addr: server.addr.clone(),
            server_port: server.port,
            uuid: server.uuid.clone(),
            tls_enabled: server.tls.as_ref().map(|t| t.enabled).unwrap_or(true),
        }
    }
}

/// VMess server/node configuration
#[derive(Debug, Clone, Deserialize)]
pub struct VmessServerConfig {
    /// Server name/identifier
    pub name: String,
    /// Server address (IP or domain)
    pub addr: String,
    /// Server port
    pub port: u16,
    /// User ID (UUID)
    pub user_id: String,
    /// Security type (aes-128-gcm-aead, chacha20-poly1305-aead, etc.)
    #[serde(default = "default_vmess_security")]
    pub security: String,
    /// Enable AEAD (VMess-AEAD-2022)
    #[serde(default = "default_true")]
    pub enable_aead: bool,
}

impl VmessServerConfig {
    /// Create a VmessServerConfig with minimal settings
    pub fn new(name: &str, addr: &str, port: u16, user_id: &str) -> Self {
        Self {
            name: name.to_string(),
            addr: addr.to_string(),
            port,
            user_id: user_id.to_string(),
            security: "aes-128-gcm-aead".to_string(),
            enable_aead: true,
        }
    }
}

/// VMess client configuration
#[derive(Debug, Clone)]
pub struct VmessClientConfig {
    /// Local listen address
    pub listen_addr: String,
    /// Server address
    pub server_addr: String,
    /// Server port
    pub server_port: u16,
    /// User ID
    pub user_id: String,
    /// Security type
    pub security: String,
    /// Enable AEAD
    pub enable_aead: bool,
}

impl VmessClientConfig {
    /// Create from VmessServerConfig with local listen address
    pub fn from_server_config(listen_addr: &str, server: &VmessServerConfig) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            server_addr: server.addr.clone(),
            server_port: server.port,
            user_id: server.user_id.clone(),
            security: server.security.clone(),
            enable_aead: server.enable_aead,
        }
    }
}

/// Trojan server/node configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TrojanServerConfig {
    /// Server name/identifier
    pub name: String,
    /// Server address (IP or domain)
    pub addr: String,
    /// Server port
    pub port: u16,
    /// Password for authentication
    pub password: String,
    /// TLS settings (optional)
    #[serde(default)]
    pub tls: Option<TrojanTlsConfig>,
}

impl TrojanServerConfig {
    /// Create a TrojanServerConfig with minimal settings
    pub fn new(name: &str, addr: &str, port: u16, password: &str) -> Self {
        Self {
            name: name.to_string(),
            addr: addr.to_string(),
            port,
            password: password.to_string(),
            tls: None,
        }
    }
}

/// Trojan TLS configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TrojanTlsConfig {
    /// Enable TLS (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// TLS version
    #[serde(default = "default_tls_version")]
    pub version: String,
    /// Server name for SNI
    #[serde(default)]
    pub server_name: Option<String>,
    /// ALPN protocols
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
}

/// Trojan client configuration
#[derive(Debug, Clone)]
pub struct TrojanClientConfig {
    /// Local listen address
    pub listen_addr: String,
    /// Server address
    pub server_addr: String,
    /// Server port
    pub server_port: u16,
    /// Password
    pub password: String,
    /// TLS enabled
    pub tls_enabled: bool,
}

impl TrojanClientConfig {
    /// Create from TrojanServerConfig with local listen address
    pub fn from_server_config(listen_addr: &str, server: &TrojanServerConfig) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            server_addr: server.addr.clone(),
            server_port: server.port,
            password: server.password.clone(),
            tls_enabled: server.tls.as_ref().map(|t| t.enabled).unwrap_or(true),
        }
    }
}

// Default value helper functions
fn default_socks5_listen() -> String {
    "127.0.0.1:1080".to_string()
}

fn default_http_listen() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_tcp_timeout() -> u64 {
    60
}

fn default_udp_timeout() -> u64 {
    30
}

fn default_ebpf_interface() -> String {
    "eth0".to_string()
}

fn default_control_socket() -> String {
    "/var/run/dae/control.sock".to_string()
}

fn default_tun_interface() -> String {
    "dae0".to_string()
}

fn default_tun_ip() -> String {
    "10.0.0.1".to_string()
}

fn default_tun_netmask() -> String {
    "255.255.255.0".to_string()
}

fn default_mtu() -> u32 {
    1500
}

fn default_dns_hijack() -> Vec<String> {
    vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]
}

fn default_dns_upstream() -> Vec<String> {
    vec!["8.8.8.8:53".to_string(), "8.8.4.4:53".to_string()]
}

fn default_port() -> u16 {
    8080
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_true() -> bool {
    true
}

fn default_auto_route() -> bool {
    true
}

fn default_tls_version() -> String {
    "1.3".to_string()
}

fn default_vmess_security() -> String {
    "aes-128-gcm-aead".to_string()
}

impl Config {
    /// Load configuration from file (auto-detect format by extension)
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let path_lower = path.to_lowercase();

        // Detect format by file extension
        if path_lower.ends_with(".yaml") || path_lower.ends_with(".yml") {
            return Self::from_yaml_str(&content);
        }

        // TOML format (default)
        if let Ok(config) = toml::from_str::<Config>(&content) {
            return Ok(config);
        }

        // Try legacy TOML format
        if let Ok(config) = toml::from_str::<LegacyConfig>(&content) {
            return Self::from_legacy(config);
        }

        Err("Unable to parse configuration file".into())
    }

    /// Load configuration from YAML string
    pub fn from_yaml_str(content: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Try new format first
        if let Ok(config) = serde_yaml::from_str::<Config>(content) {
            return Ok(config);
        }

        Err("Unable to parse YAML configuration".into())
    }

    /// Load configuration from TOML string (auto-detect format)
    pub fn from_toml_str(content: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Try new format first
        if let Ok(config) = toml::from_str::<Config>(content) {
            return Ok(config);
        }

        // Try legacy format
        if let Ok(config) = toml::from_str::<LegacyConfig>(content) {
            return Self::from_legacy(config);
        }

        Err("Unable to parse configuration".into())
    }

    /// Convert legacy configuration to new format
    fn from_legacy(legacy: LegacyConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut nodes = Vec::new();

        // Convert shadowsocks servers to nodes
        for ss in legacy.shadowsocks {
            nodes.push(NodeConfig {
                name: ss.name,
                node_type: NodeType::Shadowsocks,
                server: ss.addr,
                port: ss.port,
                method: Some(ss.method),
                password: Some(ss.password),
                uuid: None,
                trojan_password: None,
                security: None,
                tls: None,
                tls_server_name: None,
                aead: Some(ss.ota),
                capabilities: None,
                tags: vec![],
            });
        }

        // Convert vless servers to nodes
        for vless in legacy.vless {
            nodes.push(NodeConfig {
                name: vless.name,
                node_type: NodeType::Vless,
                server: vless.addr,
                port: vless.port,
                method: None,
                password: None,
                uuid: Some(vless.uuid),
                trojan_password: None,
                security: None,
                tls: vless.tls.as_ref().map(|t| t.enabled),
                tls_server_name: vless.tls.and_then(|t| t.server_name),
                aead: None,
                capabilities: None,
                tags: vec![],
            });
        }

        // Convert vmess servers to nodes
        for vmess in legacy.vmess {
            nodes.push(NodeConfig {
                name: vmess.name,
                node_type: NodeType::Vmess,
                server: vmess.addr,
                port: vmess.port,
                method: None,
                password: None,
                uuid: Some(vmess.user_id),
                trojan_password: None,
                security: Some(vmess.security),
                tls: None,
                tls_server_name: None,
                aead: Some(vmess.enable_aead),
                capabilities: None,
                tags: vec![],
            });
        }

        // Convert trojan servers to nodes
        for trojan in legacy.trojan {
            nodes.push(NodeConfig {
                name: trojan.name,
                node_type: NodeType::Trojan,
                server: trojan.addr,
                port: trojan.port,
                method: None,
                password: None,
                uuid: None,
                trojan_password: Some(trojan.password),
                security: None,
                tls: trojan.tls.as_ref().map(|t| t.enabled),
                tls_server_name: trojan.tls.and_then(|t| t.server_name),
                aead: None,
                capabilities: None,
                tags: vec![],
            });
        }

        Ok(Config {
            proxy: ProxyConfig {
                socks5_listen: format!("127.0.0.1:{}", legacy.global.port),
                http_listen: default_http_listen(),
                tcp_timeout: default_tcp_timeout(),
                udp_timeout: default_udp_timeout(),
                ebpf_interface: default_ebpf_interface(),
                ebpf_enabled: true,
                control_socket: default_control_socket(),
                pid_file: None,
            },
            nodes,
            subscriptions: vec![],
            rules: RulesConfig::default(),
            logging: LoggingConfig {
                level: legacy.global.log_level,
                file: None,
                structured: true,
            },
            transparent_proxy: TransparentProxyConfig::default(),
            tracking: TrackingConfig::default(),
        })
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate proxy listen addresses
        self.validate_listen_addr("socks5_listen", &self.proxy.socks5_listen)?;
        self.validate_listen_addr("http_listen", &self.proxy.http_listen)?;

        // Validate timeouts
        if self.proxy.tcp_timeout == 0 {
            return Err(ConfigError::ValidationError(
                "tcp_timeout must be greater than 0".to_string(),
            ));
        }
        if self.proxy.udp_timeout == 0 {
            return Err(ConfigError::ValidationError(
                "udp_timeout must be greater than 0".to_string(),
            ));
        }

        // Validate eBPF interface
        if self.proxy.ebpf_interface.is_empty() {
            return Err(ConfigError::ValidationError(
                "ebpf_interface cannot be empty".to_string(),
            ));
        }

        // Validate nodes
        self.validate_nodes()?;

        // Validate subscriptions
        self.validate_subscriptions()?;

        // Validate rules
        self.validate_rules()?;

        Ok(())
    }

    /// Validate a listen address
    fn validate_listen_addr(&self, field: &str, addr: &str) -> Result<(), ConfigError> {
        // Check basic format
        if addr.is_empty() {
            return Err(ConfigError::MissingField(field.to_string()));
        }

        // Parse address
        match addr.parse::<std::net::SocketAddr>() {
            Ok(socket_addr) => {
                // Validate port
                if socket_addr.port() == 0 {
                    return Err(ConfigError::InvalidPort(0));
                }
                Ok(())
            }
            Err(_) => {
                // Try parsing as SocketAddrV4/V6 or with default port
                if addr.contains(':') {
                    return Err(ConfigError::InvalidAddress(format!(
                        "{addr}: invalid socket address format"
                    )));
                }
                // Try as hostname:port
                if !addr.contains(':') {
                    Err(ConfigError::InvalidAddress(format!(
                        "{addr}: missing port (expected format: host:port)"
                    )))
                } else {
                    Err(ConfigError::InvalidAddress(format!(
                        "{addr}: invalid address format"
                    )))
                }
            }
        }
    }

    /// Validate all node configurations
    fn validate_nodes(&self) -> Result<(), ConfigError> {
        for node in &self.nodes {
            // Validate port
            if node.port == 0 {
                return Err(ConfigError::InvalidNode(format!(
                    "Node '{}': port must be between 1 and 65535",
                    node.name
                )));
            }

            // Validate server address
            if node.server.is_empty() {
                return Err(ConfigError::InvalidNode(format!(
                    "Node '{}': server address is required",
                    node.name
                )));
            }

            // Validate type-specific fields
            match node.node_type {
                NodeType::Shadowsocks => {
                    if node.method.is_none() {
                        return Err(ConfigError::InvalidNode(format!(
                            "Node '{}': method is required for shadowsocks",
                            node.name
                        )));
                    }
                    if node.password.is_none() {
                        return Err(ConfigError::InvalidNode(format!(
                            "Node '{}': password is required for shadowsocks",
                            node.name
                        )));
                    }
                }
                NodeType::Vless => {
                    if node.uuid.is_none() || node.uuid.as_ref().unwrap().is_empty() {
                        return Err(ConfigError::InvalidNode(format!(
                            "Node '{}': uuid is required for vless",
                            node.name
                        )));
                    }
                }
                NodeType::Vmess => {
                    if node.uuid.is_none() || node.uuid.as_ref().unwrap().is_empty() {
                        return Err(ConfigError::InvalidNode(format!(
                            "Node '{}': uuid (user_id) is required for vmess",
                            node.name
                        )));
                    }
                }
                NodeType::Trojan => {
                    if node.trojan_password.is_none()
                        || node.trojan_password.as_ref().unwrap().is_empty()
                    {
                        return Err(ConfigError::InvalidNode(format!(
                            "Node '{}': password is required for trojan",
                            node.name
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate subscriptions configuration
    fn validate_subscriptions(&self) -> Result<(), ConfigError> {
        for sub in &self.subscriptions {
            // URL is required and must be valid
            if sub.url.is_empty() {
                return Err(ConfigError::InvalidSubscription(
                    "subscription URL cannot be empty".to_string(),
                ));
            }

            // Must be a valid URL (http or https)
            if !sub.url.starts_with("http://") && !sub.url.starts_with("https://") {
                return Err(ConfigError::InvalidSubscription(format!(
                    "subscription URL must start with http:// or https://: {}",
                    sub.url
                )));
            }

            // Update interval must be positive
            if sub.update_interval_secs == 0 {
                return Err(ConfigError::InvalidSubscription(
                    "subscription update_interval_secs must be greater than 0".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate rules configuration
    fn validate_rules(&self) -> Result<(), ConfigError> {
        // If config_file is specified, it must exist
        if let Some(ref config_file) = self.rules.config_file {
            if !Path::new(config_file).exists() {
                return Err(ConfigError::RuleFileNotFound(config_file.clone()));
            }

            // Try to parse the rules file
            if let Ok(content) = std::fs::read_to_string(config_file) {
                if let Err((_, errors)) = rules::parse_and_validate(&content) {
                    let error_strings: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
                    return Err(ConfigError::RuleFileParseError(format!(
                        "{}: {}",
                        config_file,
                        error_strings.join(", ")
                    )));
                }
            }
        }

        // If rule_groups are specified inline, validate them
        for group in &self.rules.rule_groups {
            if group.name.is_empty() {
                return Err(ConfigError::ValidationError(
                    "Rule group name cannot be empty".to_string(),
                ));
            }
            if group.rules.is_empty() {
                return Err(ConfigError::ValidationError(format!(
                    "Rule group '{}' has no rules",
                    group.name
                )));
            }
        }

        Ok(())
    }

    /// Find a node by name
    pub fn find_node(&self, name: &str) -> Option<&NodeConfig> {
        self.nodes.iter().find(|n| n.name == name)
    }

    /// Get all shadowsocks nodes
    pub fn shadowsocks_nodes(&self) -> Vec<&NodeConfig> {
        self.nodes
            .iter()
            .filter(|n| n.node_type == NodeType::Shadowsocks)
            .collect()
    }

    /// Get all vless nodes
    pub fn vless_nodes(&self) -> Vec<&NodeConfig> {
        self.nodes
            .iter()
            .filter(|n| n.node_type == NodeType::Vless)
            .collect()
    }

    /// Get all vmess nodes
    pub fn vmess_nodes(&self) -> Vec<&NodeConfig> {
        self.nodes
            .iter()
            .filter(|n| n.node_type == NodeType::Vmess)
            .collect()
    }

    /// Get all trojan nodes
    pub fn trojan_nodes(&self) -> Vec<&NodeConfig> {
        self.nodes
            .iter()
            .filter(|n| n.node_type == NodeType::Trojan)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config {
            proxy: ProxyConfig::default(),
            nodes: vec![],
            subscriptions: vec![],
            rules: RulesConfig::default(),
            logging: LoggingConfig::default(),
            transparent_proxy: TransparentProxyConfig::default(),
            tracking: TrackingConfig::default(),
        };
        assert_eq!(config.proxy.socks5_listen, "127.0.0.1:1080");
        assert_eq!(config.proxy.tcp_timeout, 60);
        assert!(!config.transparent_proxy.enabled);
        assert_eq!(config.transparent_proxy.tun_interface, "dae0");
        assert_eq!(config.transparent_proxy.tun_ip, "10.0.0.1");
        assert_eq!(config.transparent_proxy.mtu, 1500);
        assert!(config.subscriptions.is_empty());
    }

    #[test]
    fn test_node_type_from_str() {
        assert_eq!(
            "shadowsocks".parse::<NodeType>().unwrap(),
            NodeType::Shadowsocks
        );
        assert_eq!("vless".parse::<NodeType>().unwrap(), NodeType::Vless);
        assert_eq!("vmess".parse::<NodeType>().unwrap(), NodeType::Vmess);
        assert_eq!("trojan".parse::<NodeType>().unwrap(), NodeType::Trojan);
        assert_eq!("ss".parse::<NodeType>().unwrap(), NodeType::Shadowsocks);
    }

    #[test]
    fn test_node_config_display_addr() {
        let node = NodeConfig {
            name: "test".to_string(),
            node_type: NodeType::Shadowsocks,
            server: "1.2.3.4".to_string(),
            port: 8388,
            method: Some("chacha20-ietf-poly1305".to_string()),
            password: Some("password".to_string()),
            uuid: None,
            trojan_password: None,
            security: None,
            tls: None,
            tls_server_name: None,
            aead: None,
            capabilities: None,
            tags: vec![],
        };
        assert_eq!(node.display_addr(), "1.2.3.4:8388");
    }

    #[test]
    fn test_validate_valid_config() {
        let config = Config {
            proxy: ProxyConfig::default(),
            nodes: vec![NodeConfig {
                name: "test-ss".to_string(),
                node_type: NodeType::Shadowsocks,
                server: "1.2.3.4".to_string(),
                port: 8388,
                method: Some("chacha20-ietf-poly1305".to_string()),
                password: Some("password".to_string()),
                uuid: None,
                trojan_password: None,
                security: None,
                tls: None,
                tls_server_name: None,
                aead: None,
                capabilities: None,
                tags: vec![],
            }],
            subscriptions: vec![],
            rules: RulesConfig::default(),
            logging: LoggingConfig::default(),
            transparent_proxy: TransparentProxyConfig::default(),
            tracking: TrackingConfig::default(),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_port() {
        let config = Config {
            proxy: ProxyConfig::default(),
            nodes: vec![NodeConfig {
                name: "test-ss".to_string(),
                node_type: NodeType::Shadowsocks,
                server: "1.2.3.4".to_string(),
                port: 0, // Invalid port
                method: Some("chacha20-ietf-poly1305".to_string()),
                password: Some("password".to_string()),
                uuid: None,
                trojan_password: None,
                security: None,
                tls: None,
                tls_server_name: None,
                aead: None,
                capabilities: None,
                tags: vec![],
            }],
            subscriptions: vec![],
            rules: RulesConfig::default(),
            logging: LoggingConfig::default(),
            transparent_proxy: TransparentProxyConfig::default(),
            tracking: TrackingConfig::default(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_legacy_to_new_format() {
        let legacy = LegacyConfig {
            global: GlobalConfig {
                port: 8080,
                log_level: "debug".to_string(),
            },
            proxy: vec![],
            shadowsocks: vec![ShadowsocksServerConfig {
                name: "ss1".to_string(),
                addr: "1.2.3.4".to_string(),
                port: 8388,
                method: "chacha20-ietf-poly1305".to_string(),
                password: "password".to_string(),
                ota: false,
            }],
            vless: vec![VlessServerConfig::new(
                "vless1",
                "5.6.7.8",
                443,
                "uuid-1234",
            )],
            vmess: vec![],
            trojan: vec![],
        };

        let config = Config::from_legacy(legacy).unwrap();
        assert_eq!(config.proxy.socks5_listen, "127.0.0.1:8080");
        assert_eq!(config.nodes.len(), 2);
        assert_eq!(config.nodes[0].node_type, NodeType::Shadowsocks);
        assert_eq!(config.nodes[1].node_type, NodeType::Vless);
    }

    #[test]
    fn test_find_node() {
        let config = Config {
            proxy: ProxyConfig::default(),
            nodes: vec![
                NodeConfig {
                    name: "node1".to_string(),
                    node_type: NodeType::Shadowsocks,
                    server: "1.2.3.4".to_string(),
                    port: 8388,
                    method: Some("chacha20-ietf-poly1305".to_string()),
                    password: Some("password".to_string()),
                    uuid: None,
                    trojan_password: None,
                    security: None,
                    tls: None,
                    tls_server_name: None,
                    aead: None,
                    capabilities: None,
                    tags: vec![],
                },
                NodeConfig {
                    name: "node2".to_string(),
                    node_type: NodeType::Vless,
                    server: "5.6.7.8".to_string(),
                    port: 443,
                    method: None,
                    password: None,
                    uuid: Some("uuid-1234".to_string()),
                    trojan_password: None,
                    security: None,
                    tls: Some(true),
                    tls_server_name: None,
                    aead: None,
                    capabilities: None,
                    tags: vec![],
                },
            ],
            subscriptions: vec![],
            rules: RulesConfig::default(),
            logging: LoggingConfig::default(),
            transparent_proxy: TransparentProxyConfig::default(),
            tracking: TrackingConfig::default(),
        };

        assert!(config.find_node("node1").is_some());
        assert!(config.find_node("node2").is_some());
        assert!(config.find_node("node3").is_none());

        assert_eq!(config.shadowsocks_nodes().len(), 1);
        assert_eq!(config.vless_nodes().len(), 1);
        assert_eq!(config.vmess_nodes().len(), 0);
        assert_eq!(config.trojan_nodes().len(), 0);
    }

    #[test]
    fn test_validate_subscription_ok() {
        let config = Config {
            proxy: ProxyConfig::default(),
            nodes: vec![],
            subscriptions: vec![SubscriptionEntry {
                url: "https://example.com/sub".to_string(),
                update_interval_secs: 3600,
                verify_tls: true,
                user_agent: None,
                name: Some("my-sub".to_string()),
                tags: vec![],
            }],
            rules: RulesConfig::default(),
            logging: LoggingConfig::default(),
            transparent_proxy: TransparentProxyConfig::default(),
            tracking: TrackingConfig::default(),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_subscription_invalid_url() {
        let config = Config {
            proxy: ProxyConfig::default(),
            nodes: vec![],
            subscriptions: vec![SubscriptionEntry {
                url: "".to_string(), // Empty URL
                update_interval_secs: 3600,
                verify_tls: true,
                user_agent: None,
                name: None,
                tags: vec![],
            }],
            rules: RulesConfig::default(),
            logging: LoggingConfig::default(),
            transparent_proxy: TransparentProxyConfig::default(),
            tracking: TrackingConfig::default(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_subscription_bad_scheme() {
        let config = Config {
            proxy: ProxyConfig::default(),
            nodes: vec![],
            subscriptions: vec![SubscriptionEntry {
                url: "ftp://example.com/sub".to_string(), // Wrong scheme
                update_interval_secs: 3600,
                verify_tls: true,
                user_agent: None,
                name: None,
                tags: vec![],
            }],
            rules: RulesConfig::default(),
            logging: LoggingConfig::default(),
            transparent_proxy: TransparentProxyConfig::default(),
            tracking: TrackingConfig::default(),
        };
        assert!(config.validate().is_err());
    }
}
