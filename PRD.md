# dae-rs 产品需求文档 (PRD)

> **项目**: dae-rs - 高性能透明代理 Rust 实现  
> **版本**: 0.1.0  
> **更新**: 2026-04-03

---

## 一、项目概述

### 1.1 定位与目标

dae-rs 是一个用 Rust 实现的高性能透明代理项目，通过 Rust 的零成本抽象和内存安全保证，追求更好的性能。项目采用模块化架构，支持多种代理协议和规则引擎，可与 eBPF/XDP 子系统集成实现内核流量拦截。

### 1.2 技术架构

```
┌─────────────────────────────────────────────────────┐
│                      dae-cli                        │
│               (CLI 入口 & 配置加载)                   │
└──────────┬─────────────────────────┬────────────────┘
           │                         │
           ▼                         ▼
┌──────────────────┐      ┌──────────────────────────┐
│     dae-core     │      │        dae-proxy          │
│   (核心引擎)      │◄────►│   (用户空间代理核心)       │
└──────────────────┘      └────────────┬─────────────┘
           │                            │
           ▼                            ▼
┌──────────────────┐      ┌──────────────────────────┐
│   dae-ebpf/      │      │       dae-config          │
│   dae-xdp        │      │      (配置解析)            │
│ (内核流量拦截)    │      └──────────────────────────┘
└──────────────────┘

┌──────────────────┐
│     dae-api      │
│   (REST API)     │
└──────────────────┘
```

### 1.3 Crate 结构

| Crate | 描述 | 代码行数 |
|-------|------|----------|
| `dae-cli` | CLI 入口 | ~3,000 |
| `dae-core` | 核心引擎（基础类型） | ~500 |
| `dae-config` | 配置解析 | ~2,000 |
| `dae-proxy` | 代理核心（最大最复杂） | ~50,000 |
| `dae-api` | 独立 REST API 模块 | ~2,000 |
| `dae-ebpf-common` | eBPF 共享类型 | - |
| `dae-xdp` | XDP eBPF 程序 | - |
| `dae-ebpf` | 用户空间 eBPF 加载器 | - |
| `dae-ebpf-direct` | 直接模式 eBPF | - |

---

## 二、dae-proxy 核心代理模块

### 2.1 连接管理 (`connection`)

**功能描述**: 追踪单个 TCP/UDP 连接的状态和时间信息，提供连接生命周期管理。

**核心类型**:
```rust
// 连接状态
pub enum ConnectionState {
    New,      // 新连接，尚未建立
    Active,   // 连接活跃，正在传输数据
    Closing,  // 正在优雅关闭
    Closed,   // 已关闭
}

// 协议类型
pub enum Protocol {
    Tcp,
    Udp,
}

// 连接结构
pub struct Connection {
    pub src_addr: SocketAddr,      // 源地址
    pub dst_addr: SocketAddr,      // 目标地址
    pub protocol: Protocol,         // 协议类型
    pub state: ConnectionState,     // 连接状态
    pub created_at: Instant,        // 创建时间
    pub last_activity: Instant,     // 最后活跃时间
}
```

**配置参数**: 无（连接由 TCP/UDP 代理自动创建管理）

---

### 2.2 连接池 (`connection_pool`)

**功能描述**: 按 4-tuple（src_ip, dst_ip, src_port, dst_port, protocol）复用连接，支持 expiration 过期机制。

**核心 API**:
```rust
pub struct ConnectionPool { /* ... */ }

impl ConnectionPool {
    // 获取连接键对应的复用连接
    pub async fn get(&self, key: &ConnectionKey) -> Option<SharedConnection>;
    
    // 放入连接供后续复用
    pub async fn put(&self, key: ConnectionKey, conn: SharedConnection);
    
    // 清理过期连接
    pub async fn cleanup(&self);
}

// 连接键定义
pub struct ConnectionKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,  // 6=TCP, 17=UDP
}
```

**配置参数**:
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `max_idle_time` | Duration | 60s | 空闲连接最大保留时间 |
| `max_lifetime` | Duration | 300s | 连接最大生命周期 |

---

### 2.3 TCP 代理 (`tcp`)

**功能描述**: 使用 tokio 实现 TCP 双向拷贝转发，支持连接池复用。

**核心 API**:
```rust
pub struct TcpProxy { /* ... */ }

impl TcpProxy {
    pub fn new(config: TcpProxyConfig, connection_pool: SharedConnectionPool) -> Self;
    pub async fn serve(&self) -> Result<()>;
}

pub struct TcpProxyConfig {
    pub listen_addr: SocketAddr,           // 监听地址
    pub connection_timeout: Duration,     // 连接超时
    pub keepalive_interval: Duration,      // TCP keepalive 间隔
    pub inbound_buffer_size: usize,        // 入站缓冲区大小
    pub outbound_buffer_size: usize,       // 出站缓冲区大小
}
```

**配置参数**:
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `listen_addr` | SocketAddr | `127.0.0.1:1080` | 监听地址 |
| `connection_timeout` | Duration | 60s | 连接超时时间 |
| `keepalive_interval` | Duration | 30s | TCP keepalive 间隔 |
| `inbound_buffer_size` | usize | 32KB | 入站缓冲区 |
| `outbound_buffer_size` | usize | 32KB | 出站缓冲区 |

---

### 2.4 UDP 代理 (`udp`)

**功能描述**: UDP 转发实现，具有 NAT 语义，支持连接池和 session 追踪。

**核心 API**:
```rust
pub struct UdpProxy { /* ... */ }

impl UdpProxy {
    pub fn new(config: UdpProxyConfig, pool: SharedConnectionPool) -> Self;
    pub async fn serve(&self) -> Result<()>;
}

pub struct UdpProxyConfig {
    pub listen_addr: SocketAddr,
    pub session_timeout: Duration,
    pub max_packet_size: usize,
}
```

**配置参数**:
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `listen_addr` | SocketAddr | `127.0.0.1:1080` | 监听地址 |
| `session_timeout` | Duration | 30s | session 超时 |
| `max_packet_size` | usize | 65535 | 最大 UDP 包大小 |

---

### 2.5 协议分发器 (`protocol_dispatcher`)

**功能描述**: 根据首字节自动检测进入协议（SOCKS5/HTTP），路由到对应处理器。

**核心 API**:
```rust
// 协议检测
pub enum DetectedProtocol {
    Socks5,       // SOCKS5 (0x05)
    HttpConnect, // HTTP CONNECT
    HttpOther,   // 其他 HTTP 方法
    Unknown,
}

impl DetectedProtocol {
    pub fn detect(first_bytes: &[u8]) -> Self;
}

pub struct ProtocolDispatcher { /* ... */ }

impl ProtocolDispatcher {
    pub fn new(config: ProtocolDispatcherConfig) -> Self;
    pub async fn serve(&self) -> Result<()>;
}

pub struct ProtocolDispatcherConfig {
    pub socks5_addr: Option<SocketAddr>,  // None 禁用 SOCKS5
    pub http_addr: Option<SocketAddr>,    // None 禁用 HTTP
}
```

**配置参数**:
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `socks5_addr` | Option\<SocketAddr\> | `Some(127.0.0.1:1080)` | SOCKS5 监听地址 |
| `http_addr` | Option\<SocketAddr\> | `Some(127.0.0.1:8080)` | HTTP 代理监听地址 |

---

### 2.6 主代理协调器 (`proxy`)

**功能描述**: 协调所有 TCP/UDP 转发协议，集成 eBPF maps，是 dae-proxy 的主入口。

**核心 API**:
```rust
pub struct Proxy { /* ... */ }

impl Proxy {
    pub async fn run(&self) -> Result<()>;
    pub async fn shutdown(&self) -> Result<()>;
}

pub struct ProxyConfig {
    pub tcp: TcpProxyConfig,
    pub udp: UdpProxyConfig,
    pub ebpf: EbpfConfig,
    pub pool: ConnectionPoolConfig,
    pub xdp_object: PathBuf,           // XDP 对象文件路径
    pub xdp_interface: String,          // XDP 绑定的网卡名
    pub socks5_listen: Option<SocketAddr>,
    pub http_listen: Option<SocketAddr>,
    pub http_auth: Option<(String, String)>,  // 用户名/密码
    pub ss_listen: Option<SocketAddr>,
    pub ss_server: Option<SsServerConfig>,
    pub vless_listen: Option<SocketAddr>,
    pub vless_server: Option<VlessServerConfig>,
    pub vmess_listen: Option<SocketAddr>,
    pub vmess_server: Option<VmessServerConfig>,
    pub trojan_listen: Option<SocketAddr>,
    pub trojan_server: Option<TrojanServerConfig>,
    pub trojan_backends: Vec<TrojanServerConfig>,
}
```

---

## 三、代理协议实现

### 3.1 SOCKS5 (`socks5`)

**功能描述**: 实现 RFC 1928 SOCKS5 协议，支持用户名密码认证（RFC 1929）。

**核心 API**:
```rust
pub struct Socks5Handler { /* ... */ }

impl Socks5Handler {
    pub fn new() -> Self;
    pub async fn handle(&self, stream: TcpStream) -> Result<()>;
}

pub struct Socks5Server { /* ... */ }

impl Socks5Server {
    pub async fn serve(&self, listen_addr: SocketAddr) -> Result<()>;
}
```

**SOCKS5 地址类型**:
```rust
pub enum Socks5AddressType {
    Ipv4 = 1,      // IPv4
    Domain = 3,    // 域名
    Ipv6 = 4,      // IPv6
}

pub enum Socks5Command {
    Connect = 1,   // TCP CONNECT
    Bind = 2,      // TCP BIND
    UdpAssociate = 3,  // UDP 关联
}
```

**配置参数**:
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `listen_addr` | SocketAddr | `127.0.0.1:1080` | 监听地址 |
| `auth_required` | bool | `false` | 是否需要认证 |
| `username` | String | - | 用户名（可选） |
| `password` | String | - | 密码（可选） |

---

### 3.2 HTTP 代理 (`http_proxy`)

**功能描述**: 实现 HTTP 代理，支持 CONNECT 方法建立隧道，支持 Basic 认证。

**核心 API**:
```rust
pub struct HttpProxyHandler { /* ... */ }

pub struct HttpProxyServer { /* ... */ }

impl HttpProxyServer {
    pub async fn serve(&self, addr: SocketAddr, auth: Option<(String, String)>) -> Result<()>;
}
```

---

### 3.3 VLESS (`vless`)

**功能描述**: 实现 VLESS 协议，支持 VLESS + Reality 透明代理，是最重要的协议之一。

**核心 API**:
```rust
pub struct VlessHandler { /* ... */ }

pub struct VlessServer { /* ... */ }

// VLESS 配置结构
pub struct VlessServerConfig {
    pub listen_addr: SocketAddr,
    pub users: Vec<VlessUser>,
    pub tls: Option<VlessTlsConfig>,
    pub reality: Option<VlessRealityConfig>,
}

pub struct VlessUser {
    pub id: String,           // UUID
    pub flow: Option<String>, // フロー ( 空 / "xtls-rprx-vision" )
}

pub struct VlessTlsConfig {
    pub cert_file: String,
    pub key_file: String,
    pub alpn: Vec<String>,
}

pub struct VlessRealityConfig {
    pub reality: bool,
    pub short_id: String,      // 短 ID (8 hex)
    pub public_key: String,    // X25519 公钥
    pub server_name: String,   // SNI
}
```

**配置参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `listen_addr` | SocketAddr | 是 | 监听地址 |
| `users[].id` | String | 是 | 用户 UUID |
| `users[].flow` | Option\<String\> | 否 | フロー类型 |
| `tls.enabled` | bool | 否 | 是否启用 TLS |
| `tls.cert_file` | String | TLS 时必填 | 证书文件 |
| `tls.key_file` | String | TLS 时必填 | 私钥文件 |
| `reality.enabled` | bool | 否 | 是否启用 Reality |
| `reality.public_key` | String | Reality 时必填 | X25519 公钥 |
| `reality.short_id` | String | 否 | 短 ID（8位hex） |
| `reality.server_name` | String | Reality 时必填 | SNI |

---

### 3.4 VMess (`vmess`)

**功能描述**: 实现 VMess AEAD-2022 协议，支持VMess 标准的各种加密方式。

**核心 API**:
```rust
pub struct VmessHandler { /* ... */ }

pub struct VmessServer { /* ... */ }

pub struct VmessServerConfig {
    pub listen_addr: SocketAddr,
    pub users: Vec<VmessUser>,
    pub security: VmessSecurity,
}

pub enum VmessSecurity {
    AES_128_GCM,
    CHACHA20_POLY1305,
    NONE,
}

pub enum VmessAddressType {
    Ipv4 = 1,
    Domain = 2,
    Ipv6 = 3,
}

pub enum VmessCommand {
    Tcp = 1,
    Udp = 2,
}
```

**配置参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `listen_addr` | SocketAddr | 是 | 监听地址 |
| `users[].id` | String | 是 | 用户 UUID |
| `users[].alter_id` | u16 | 是 | 额外 ID（建议 0） |
| `security` | Enum | 是 | 加密方式 |

---

### 3.5 Trojan (`trojan_protocol`)

**功能描述**: 实现 Trojan 协议，支持 WebSocket 传输，支持多后端负载均衡。

**核心 API**:
```rust
// 模块结构 (Zed 风格拆分)
pub mod trojan_protocol {
    pub mod protocol;   // TrojanCommand, TrojanAddressType
    pub mod config;    // TrojanServerConfig, TrojanClientConfig
    pub mod handler;   // TrojanHandler
    pub mod server;    // TrojanServer
}

pub struct TrojanHandler { /* ... */ }

pub struct TrojanServer { /* ... */ }

impl TrojanServer {
    pub async fn serve(&self) -> Result<()>;
}

pub struct TrojanServerConfig {
    pub listen_addr: SocketAddr,
    pub password: String,
    pub tls: Option<TrojanTlsConfig>,
    pub backends: Vec<TrojanBackend>,  // 多后端支持
}

pub struct TrojanBackend {
    pub name: String,
    pub addr: SocketAddr,
    pub weight: u8,  // 权重（用于负载均衡）
}
```

**配置参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `listen_addr` | SocketAddr | 是 | 监听地址 |
| `password` | String | 是 | Trojan 密码 |
| `tls.enabled` | bool | 否 | 是否 TLS |
| `backends[].addr` | SocketAddr | 多后端时必填 | 后端地址 |
| `backends[].weight` | u8 | 否 | 权重（默认 1） |

---

### 3.6 Shadowsocks (`shadowsocks`)

**功能描述**: 实现 Shadowsocks 协议，支持 AEAD 加密（chacha20-ietf-poly1305、aes-128-gcm 等），支持 Simple Obfs 和 V2ray Plugin。

**核心 API**:
```rust
pub struct ShadowsocksHandler { /* ... */ }

pub struct ShadowsocksServer { /* ... */ }

pub enum SsCipherType {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
    CHACHA20_IETF_POLY1305,
}

pub struct SsServerConfig {
    pub addr: SocketAddr,
    pub password: String,
    pub method: SsCipherType,
}

// Shadowsocks + Simple Obfs
pub struct ObfsHttp { /* ... */ }
pub struct ObfsTls { /* ... */ }

// Shadowsocks + V2ray Plugin
pub struct V2rayPlugin { /* ... */ }
```

**配置参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `addr` | SocketAddr | 是 | 监听地址 |
| `password` | String | 是 | 密码 |
| `method` | Enum | 是 | 加密算法 |
| `obfs.enabled` | bool | 否 | 是否混淆 |
| `obfs.type` | Enum | 否 | `http` / `tls` |
| `plugin.enabled` | bool | 否 | 是否插件 |
| `plugin.path` | String | 否 | 插件路径 |
| `plugin.args` | String | 否 | 插件参数 |

---

### 3.7 TUIC (`tuic`)

**功能描述**: 实现 TUIC 协议（QUIC-based），高性能 UDP 代理。

**核心 API**:
```rust
pub struct TuicHandler { /* ... */ }
pub struct TuicServer { /* ... */ }
pub struct TuicConfig { /* ... */ }
```

---

### 3.8 Hysteria2 (`hysteria2`)

**功能描述**: 实现 Hysteria2 协议，基于 QUIC 的高性能代理。

**核心 API**:
```rust
pub struct Hysteria2Handler { /* ... */ }
pub struct Hysteria2Server { /* ... */ }
pub struct Hysteria2Config { /* ... */ }
```

---

### 3.9 Juicity (`juicity`)

**功能描述**: 实现 Juicity 协议，另一种 QUIC-based 代理协议。

**核心 API**:
```rust
pub struct JuicityHandler { /* ... */ }
pub struct JuicityServer { /* ... */ }

pub enum CongestionControl {
    Bbr,
    Cubic,
    NewReno,
}
```

---

### 3.10 AnyTLS / NaiveProxy (`anytls`, `naiveproxy`)

**功能描述**: AnyTLS 协议实现，NaiveProxy 混淆代理支持。

---

## 四、规则引擎

### 4.1 规则匹配 (`rules`)

**功能描述**: 提供多种规则类型用于流量匹配和路由决策。

**规则类型**:
```rust
pub enum RuleType {
    Domain,          // 精确域名
    DomainSuffix,    // 域名后缀 (.example.com)
    DomainKeyword,   // 域名关键词
    IpCidr,          // IP CIDR (IPv4/IPv6)
    GeoIp,           // GeoIP 国家码
    Process,         // 进程名（Linux）
    DnsType,         // DNS 查询类型
    Capability,      // 节点能力匹配
}

// 匹配动作
pub enum RuleMatchAction {
    Pass,   // 直通（不使用代理）
    Proxy,  // 代理
    Drop,   // 丢弃
    Direct, // 直连
}

// 规则结构
pub struct Rule {
    pub rule_type: RuleType,
    pub value: String,
    pub action: RuleMatchAction,
    pub comment: Option<String>,
}
```

**域名规则解析**:
- `"example.com"` → 精确匹配
- `".example.com"` → 后缀匹配
- `"keyword:google"` → 关键词匹配

---

### 4.2 规则引擎 (`rule_engine`)

**功能描述**: 用户空间规则匹配引擎，基于 PacketInfo 做最终路由决策。

**核心 API**:
```rust
pub struct RuleEngine { /* ... */ }

impl RuleEngine {
    // 匹配数据包
    pub async fn match_packet(&self, info: &PacketInfo) -> RuleAction;
    
    // 加载规则
    pub async fn load_rules(&self, rules: Vec<Rule>) -> Result<()>;
}

// 包信息
pub struct PacketInfo {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,                  // 6=TCP, 17=UDP
    pub destination_domain: Option<String>,
    pub geoip_country: Option<String>,
    pub process_name: Option<String>,
    pub dns_query_type: Option<u16>,
    pub is_outbound: bool,
    pub packet_size: usize,
}

pub enum RuleAction {
    Pass,    // 直通
    Proxy,   // 代理
    Drop,    // 丢弃
    Direct,  // 直连
}

pub struct RuleEngineConfig {
    pub geoip_enabled: bool,
    pub process_matching_enabled: bool,
    pub default_action: RuleAction,
    pub hot_reload_enabled: bool,
}
```

**配置参数**:
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `geoip_enabled` | bool | `true` | 是否启用 GeoIP |
| `process_matching_enabled` | bool | `true` | 是否启用进程匹配 |
| `default_action` | RuleAction | `Proxy` | 默认动作 |
| `hot_reload_enabled` | bool | `false` | 是否热重载 |

---

### 4.3 进程规则 (`process`)

**功能描述**: 基于进程名的规则匹配，识别流量对应的进程（Linux only）。

**核心 API**:
```rust
pub struct ProcessRuleSet { /* ... */ }

impl ProcessRuleSet {
    pub fn new() -> Self;
    pub fn add_rule(&mut self, process_name: &str, action: RuleAction);
    pub fn match_process(&self, name: &str) -> Option<RuleAction>;
}
```

---

### 4.4 MAC 地址规则 (`mac`)

**功能描述**: 基于 MAC 地址的规则匹配，使用 OUI 数据库识别设备厂商。

**核心 API**:
```rust
pub struct MacRuleSet { /* ... */ }

impl MacRuleSet {
    pub fn new(oui_db_path: &Path) -> Result<Self>;
    pub fn add_rule(&mut self, mac_prefix: &str, action: RuleAction);
    pub fn match_mac(&self, mac: &MacAddr) -> Option<RuleAction>;
}

pub struct MacAddr(pub [u8; 6]);
```

---

## 五、节点管理 (`node`)

### 5.1 概述

参考 Zed 编辑器的 Store 模式设计的节点管理模块，提供节点抽象、选择和健康检查。

**Zed 架构风格**:
| 模式 | dae-rs 应用 |
|------|-------------|
| `*Store` | `NodeStore` - 抽象接口 |
| `*Manager` | `NodeManager` - 生命周期管理 |
| `*Handle` | `NodeHandle` - 实体引用 |
| `*State` | `NodeState` - 不可变快照 |

### 5.2 核心 API

```rust
// 节点标识
pub struct NodeId(pub String);

// 节点能力
pub struct NodeCapabilities {
    pub fullcone: bool,  // 全锥 NAT 支持
    pub udp: bool,       // UDP 支持
    pub v2ray: bool,    // V2Ray 兼容
}

// 节点 trait
pub trait Node: Send + Sync {
    fn id(&self) -> &NodeId;
    fn name(&self) -> &str;
    fn capabilities(&self) -> NodeCapabilities;
    async fn test(&self) -> Result<LatencyMs>;
}

// 节点管理器 trait
pub trait NodeManager: Send + Sync {
    fn add_node(&self, node: Arc<dyn Node>) -> Result<()>;
    fn remove_node(&self, id: &NodeId) -> Result<()>;
    fn select_node(&self, policy: SelectionPolicy) -> Result<Arc<dyn Node>>;
    async fn health_check(&self) -> Vec<HealthCheckResult>;
}

// 节点选择策略
pub enum SelectionPolicy {
    Latency,      // 按延迟选择（最低延迟）
    RoundRobin,   // 轮询
    Random,       // 随机
    Priority(u8), // 优先级
}

// 健康检查
pub struct HealthCheckResult {
    pub node_id: NodeId,
    pub latency_ms: Option<u32>,
    pub online: bool,
    pub checked_at: SystemTime,
}
```

### 5.3 简单实现

```rust
pub struct SimpleNodeManager { /* ... */ }
pub struct SimpleNode { /* ... */ }
pub struct LatencyMonitor { /* ... */ }
```

---

## 六、协议抽象层 (`protocol`)

### 6.1 统一 Handler 接口 (Zed 风格)

**功能描述**: 所有协议处理器统一实现 `Handler` trait，支持注册和查找。

```rust
#[async_trait]
pub trait Handler: Send + Sync {
    type Config: HandlerConfig;
    
    fn name(&self) -> &'static str;
    fn protocol(&self) -> ProtocolType;
    fn config(&self) -> &Self::Config;
    
    async fn handle(&self, conn: Connection) -> Result<(), ProxyError>;
    async fn reload(&self, config: Self::Config) -> Result<(), ProxyError> { Ok(()) }
}

// 协议注册表
pub struct ProtocolRegistry { /* ... */ }

impl ProtocolRegistry {
    pub fn register<H: Handler>(&self, handler: Arc<H>) -> Result<()>;
    pub fn get(&self, protocol: ProtocolType) -> Option<Arc<dyn Handler>>;
    pub fn list(&self) -> Vec<ProtocolType>;
}
```

### 6.2 协议类型

```rust
pub enum ProtocolType {
    Socks4,
    Socks5,
    Http,
    Shadowsocks,
    Vless,
    Vmess,
    Trojan,
    Tuic,
    Juicity,
    Hysteria2,
}
```

---

## 七、传输层 (`transport`)

**功能描述**: 提供多种传输层协议的统一抽象。

### 7.1 传输层 Trait

```rust
#[async_trait]
pub trait Transport: Send + Sync + Debug {
    fn name(&self) -> &'static str;
    async fn dial(&self, addr: &str) -> std::io::Result<TcpStream>;
    async fn listen(&self, addr: &str) -> std::io::Result<tokio::net::TcpListener>;
    fn supports_udp(&self) -> bool { false }
}
```

### 7.2 传输类型

| 模块 | 类型 | 说明 |
|------|------|------|
| `tcp` | `TcpTransport` | 原始 TCP 连接 |
| `tls` | `TlsTransport` | TLS 传输（含 Reality 支持） |
| `ws` | `WsTransport` | WebSocket 传输 |
| `grpc` | `GrpcTransport` | gRPC 传输 |
| `httpupgrade` | `HttpUpgradeTransport` | HTTP Upgrade |
| `meek` | `MeekTransport` | 域前置（Meek） |

### 7.3 TLS 配置

```rust
pub struct TlsConfig {
    pub cert_file: String,
    pub key_file: String,
    pub alpn: Vec<String>,
    pub server_name: String,
}

// Reality 配置
pub struct RealityConfig {
    pub enabled: bool,
    pub public_key: String,
    pub short_id: String,
    pub server_name: String,
}
```

### 7.4 WebSocket 配置

```rust
pub struct WsConfig {
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub max_size: usize,
}
```

---

## 八、eBPF 集成 (`ebpf_integration`)

**功能描述**: 包装 eBPF maps（session、routing、stats），与内核 XDP 程序通信。

### 8.1 核心 API

```rust
pub struct EbpfMaps {
    pub sessions: Option<SessionMapHandle>,
    pub routing: Option<RoutingMapHandle>,
    pub stats: Option<StatsMapHandle>,
}

impl EbpfMaps {
    pub fn new() -> Self;
    pub fn is_initialized(&self) -> bool;
}

// Session Map
pub struct SessionMapHandle { /* ... */ }

impl SessionMapHandle {
    pub fn insert(&self, key: &ConnectionKey, value: &SessionEntry) -> Result<()>;
    pub fn lookup(&self, key: &ConnectionKey) -> Result<Option<SessionEntry>>;
    pub fn remove(&self, key: &ConnectionKey) -> Result<()>;
}

// Routing Map
pub struct RoutingMapHandle { /* ... */ }

impl RoutingMapHandle {
    pub fn insert(&self, key: &str, value: &RoutingEntry) -> Result<()>;
    pub fn lookup(&self, key: &str) -> Result<Option<RoutingEntry>>;
}

// Stats Map
pub struct StatsMapHandle { /* ... */ }

impl StatsMapHandle {
    pub fn inc_bytes_sent(&self, id: u32, bytes: u64) -> Result<()>;
    pub fn inc_bytes_recv(&self, id: u32, bytes: u64) -> Result<()>;
}
```

### 8.2 eBPF 配置

```rust
pub struct EbpfConfig {
    pub enabled: bool,
    pub xdp_object: PathBuf,
    pub xdp_interface: String,
}
```

**配置参数**:
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `false` | 是否启用 eBPF |
| `xdp_object` | PathBuf | `bpf/dae-xdp.o` | XDP 对象文件 |
| `xdp_interface` | String | `"eth0"` | 绑定的网卡 |

---

## 九、热重载 (`config`)

**功能描述**: 支持配置文件热重载，无需重启服务即可更新配置。

### 9.1 核心 API

```rust
pub trait HotReloadable {
    async fn reload(&mut self, config: Config) -> Result<()>;
}

pub enum ConfigEvent {
    Reloaded(Config),
    RulesChanged(Vec<Rule>),
    NodesChanged(Vec<Node>),
}

pub enum WatchEventKind {
    Modify,
    Remove,
    Create,
}
```

---

## 十、指标导出 (`metrics`)

**功能描述**: Prometheus 格式指标导出，支持指标收集和 HTTP API。

### 10.1 指标类型

| 指标名 | 类型 | 说明 |
|--------|------|------|
| `dae_connections_total` | Counter | 总连接数 |
| `dae_bytes_sent` | Counter | 发送字节 |
| `dae_bytes_received` | Counter | 接收字节 |
| `dae_active_connections` | Gauge | 活跃连接数 |
| `dae_node_latency` | Histogram | 节点延迟 |
| `dae_dns_resolution` | Counter | DNS 解析次数 |
| `dae_rule_match` | Counter | 规则匹配次数 |

### 10.2 核心 API

```rust
pub struct MetricsServer { /* ... */ }

impl MetricsServer {
    pub fn new(addr: SocketAddr) -> Self;
    pub async fn start(&self);
    pub async fn stop(&self);
}

// 指标操作函数
pub fn inc_connection(protocol: &str);
pub fn inc_bytes_sent(bytes: u64);
pub fn inc_bytes_received(bytes: u64);
pub fn inc_active_connections();
pub fn dec_active_connections();
pub fn set_node_latency(node_id: &str, latency_ms: u32);
pub fn observe_connection_duration(duration_secs: f64);
```

---

## 十一、控制接口 (`control`)

**功能描述**: Unix Domain Socket 控制接口，用于运行时管理（状态、重载、统计）。

### 11.1 命令类型

```rust
pub enum ControlCommand {
    Status,           // 获取代理状态
    Reload,           // 热重载配置
    Stats,            // 获取统计信息
    Shutdown,         // 优雅关闭
    TestNode(String), // 测试指定节点
    Version,          // 获取版本
    Help,             // 帮助信息
}
```

### 11.2 响应类型

```rust
pub enum ControlResponse {
    Ok(String),
    Error(String),
    Stats(ProxyStats),
    Status(ProxyStatus),
    TestResult(NodeTestResult),
    Version(String),
}

pub struct ProxyStatus {
    pub running: bool,
    pub uptime_secs: u64,
    pub tcp_connections: usize,
    pub udp_sessions: usize,
    pub rules_loaded: bool,
    pub rule_count: usize,
    pub nodes_configured: usize,
}

pub struct ProxyStats {
    pub total_connections: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub active_tcp_connections: usize,
    pub active_udp_sessions: usize,
    pub rules_hit: u64,
    pub nodes_tested: usize,
}
```

### 11.3 客户端 API

```rust
// 连接控制接口并发送命令
pub async fn connect_and_send(cmd: ControlCommand) -> Result<ControlResponse>;

// 获取状态
pub async fn connect_and_get_status() -> Result<ProxyStatus>;
```

---

## 十二、日志服务 (`logging`)

**功能描述**: 日志收集和分发服务。

```rust
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

pub struct LogMessage {
    pub level: LogLevel,
    pub message: String,
    pub timestamp: SystemTime,
}

pub struct LogService { /* ... */ }

impl LogService {
    pub fn new() -> Self;
    pub async fn connect(&self, path: &Path) -> Result<()>;
}
```

---

## 十三、dae-config 配置模块

### 13.1 概述

配置解析和验证模块，所有配置通过 TOML 文件加载。

### 13.2 节点配置

```rust
// 节点类型
pub enum NodeType {
    Shadowsocks,
    Vless,
    Vmess,
    Trojan,
}

// 节点配置
pub struct NodeConfig {
    pub name: String,
    pub node_type: NodeType,
    pub server: String,
    pub port: u16,
    pub password: Option<String>,
    pub method: Option<String>,
    // ... 其他协议特定字段
}
```

### 13.3 规则配置

```rust
pub struct RuleConfigItem {
    pub type: String,    // domain, domain-suffix, ip-cidr, geoip 等
    pub value: String,
    pub action: String,  // proxy, direct, drop
}

pub struct RuleGroupConfig {
    pub name: String,
    pub items: Vec<RuleConfigItem>,
}
```

### 13.4 日志配置

```rust
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}
```

---

## 十四、dae-api REST API 模块

### 14.1 概述

独立 REST API 服务器，提供 Web 管理界面和完整 CRUD 操作。

### 14.2 API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/nodes` | 节点列表 |
| GET | `/api/nodes/{id}` | 节点详情 |
| POST | `/api/nodes/test` | 测试节点连通性 |
| GET | `/api/rules` | 规则列表 |
| GET | `/api/config` | 当前配置 |
| PUT | `/api/config` | 更新配置 |
| GET | `/api/stats` | 统计信息 |
| GET | `/health` | 健康检查 |
| WS | `/ws` | WebSocket 实时推送 |

### 14.3 数据模型

```rust
pub struct NodeResponse {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub latency_ms: Option<u32>,
    pub status: NodeStatus,
}

pub struct RuleResponse {
    pub id: String,
    pub name: String,
    pub action: String,
    pub priority: u32,
}

pub struct StatsResponse {
    pub total_connections: u64,
    pub active_connections: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub uptime_secs: u64,
}
```

---

## 十五、dae-cli 命令行模块

### 15.1 命令列表

```bash
dae run --config config.toml    # 运行代理（主要命令）
dae status                      # 查看状态
dae validate --config config.toml  # 验证配置
dae reload                      # 热重载
dae shutdown                    # 停止代理
dae test --node <name>          # 测试节点
```

### 15.2 设计原则

- **配置驱动** - 所有协议配置在 TOML 文件中，CLI 只负责加载和运行
- **简洁命令** - 6 个核心子命令，覆盖所有运维场景
- **零协议 flags** - 移除所有协议特定的 CLI 参数

---

## 十六、配置文件结构

### 16.1 完整配置示例

```toml
[proxy]
socks5_listen = "127.0.0.1:1080"
http_listen = "127.0.0.1:8080"
ebpf_interface = "eth0"
ebpf_enabled = false
tcp_timeout = 60
udp_timeout = 30

[[nodes]]
name = "my-ss"
type = "shadowsocks"
server = "1.2.3.4"
port = 8388
method = "chacha20-ietf-poly1305"
password = "my-password"

[[nodes]]
name = "my-trojan"
type = "trojan"
server = "5.6.7.8"
port = 443
trojan_password = "password"

[rules]
default_action = "proxy"

[[rules.groups]]
name = " domestic"
rules = [
    "domain-suffix:.cn",
    "ip-cidr:10.0.0.0/8",
]

[[rules.groups]]
name = "block"
rules = [
    "domain:ads.example.com",
    "geoip:CN",
]

[log]
level = "info"
output = "stdout"

[api]
enabled = true
listen = "127.0.0.1:8081"
```

---

## 十七、dae-ebpf eBPF 模块

### 17.1 模块结构

| 模块 | 描述 |
|------|------|
| `dae-ebpf-common` | 共享 eBPF 类型（session、routing、stats） |
| `dae-xdp` | XDP eBPF 程序（内核数据面） |
| `dae-ebpf` | 用户空间 eBPF 加载器 |
| `dae-ebpf-direct` | 直接模式 eBPF |

### 17.2 eBPF Map 类型

- **Session Map**: 连接会话追踪
- **Routing Map**: 路由规则映射
- **Stats Map**: 流量统计

---

## 十八、模块依赖关系

```
dae-cli
├── dae-core
├── dae-proxy
├── dae-config
└── dae-api (optional)

dae-proxy
├── dae-core
├── dae-config
└── dae-ebpf-common

dae-api
└── (独立 HTTP 服务器)
```

---

## 十九、关键设计模式

| 模式 | 应用场景 |
|------|----------|
| **策略模式** | `SelectionPolicy` (Latency, RoundRobin, Random) |
| **观察者模式** | `HotReload` 配置观察 |
| **模板方法** | `RuleEngine::match_packet()` |
| **装饰器** | `ProtocolHandlerAdapter` 包装现有 Handler |
| **代理模式** | `ConnectionPool` 连接代理 |
| **建造者** | `ProcessRuleSetBuilder`, `RuleGroup` |
| **单例** | `METRICS_SERVER` 全局指标 |
| **Zed Store** | `NodeStore`, `NodeManager` 命名模式 |

---

## 二十、测试覆盖

| 类别 | 数量 |
|------|------|
| 单元测试 | 180+ |
| 集成测试 | 19 |
| **总计** | **199+** |

---

*文档生成时间: 2026-04-03*
