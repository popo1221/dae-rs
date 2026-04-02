# 配置系统 - 功能描述

## 概述
dae-config 提供 dae-rs 的配置解析和验证，支持新旧两种配置格式。

## 配置格式

### 新格式 (推荐)
```toml
[proxy]
socks5_listen = "127.0.0.1:1080"
http_listen = "127.0.0.1:8080"
tcp_timeout = 60
udp_timeout = 30
ebpf_interface = "eth0"
ebpf_enabled = true

[[nodes]]
name = "trojan-1"
type = "trojan"
server = "example.com"
port = 443
trojan_password = "password123"

[[nodes]]
name = "ss-1"
type = "shadowsocks"
server = "1.2.3.4"
port = 8388
method = "chacha20-ietf-poly1305"
password = "password"

[rules]
config_file = "/etc/dae/rules.toml"

[logging]
level = "info"
file = "/var/log/dae/dae.log"
structured = true
```

### 旧格式 (兼容)
```toml
[global]
port = 8080
log_level = "info"

[[shadowsocks]]
name = "ss1"
addr = "1.2.3.4"
port = 8388
method = "chacha20-ietf-poly1305"
password = "password"
```

## 配置结构

### Config
主配置结构。
```rust
pub struct Config {
    pub proxy: ProxyConfig,
    pub nodes: Vec<NodeConfig>,
    pub rules: RulesConfig,
    pub logging: LoggingConfig,
}
```

### NodeConfig
节点配置。
```rust
pub struct NodeConfig {
    pub name: String,
    pub node_type: NodeType,
    pub server: String,
    pub port: u16,
    pub method: Option<String>,
    pub password: Option<String>,
    pub uuid: Option<String>,
    pub trojan_password: Option<String>,
    pub security: Option<String>,
    pub tls: Option<bool>,
    pub tls_server_name: Option<String>,
    pub aead: Option<bool>,
}
```

### NodeType
```rust
pub enum NodeType {
    Shadowsocks,
    Vless,
    Vmess,
    Trojan,
}
```

## 验证规则

### 必填字段
| 节点类型 | 必填字段 |
|----------|----------|
| Shadowsocks | method, password |
| Vless | uuid |
| Vmess | uuid |
| Trojan | trojan_password |

### 端口验证
- 端口范围: 1-65535
- 不能为 0

### 地址验证
- socks5_listen: 有效的 SocketAddr
- http_listen: 有效的 SocketAddr

## 配置解析

```rust
impl Config {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn Error>>
    pub fn from_toml_str(content: &str) -> Result<Self, Box<dyn Error>>
    pub fn validate(&self) -> Result<(), ConfigError>
}
```

### 错误类型
```rust
pub enum ConfigError {
    MissingField(String),
    InvalidPort(u16),
    InvalidAddress(String),
    InvalidNode(String),
    RuleFileNotFound(String),
    RuleFileParseError(String),
    ValidationError(String),
}
```

## 配置默认值

| 字段 | 默认值 |
|------|--------|
| socks5_listen | "127.0.0.1:1080" |
| http_listen | "127.0.0.1:8080" |
| tcp_timeout | 60 |
| udp_timeout | 30 |
| ebpf_interface | "eth0" |
| ebpf_enabled | true |
| control_socket | "/var/run/dae/control.sock" |
| log_level | "info" |
| structured | true |

## 安全性考虑

1. **密码保护**: 配置文件中的密码应设置适当权限 (chmod 600)
2. **TLS 验证**: 建议启用 TLS 验证防止中间人攻击
3. **节点认证**: 各协议有不同的认证机制，应选择强密码/UUID
4. **规则文件**: 外部规则文件应验证存在和格式正确
