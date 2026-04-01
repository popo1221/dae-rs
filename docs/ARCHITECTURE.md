# dae-rs 架构优化设计

> 在实现新功能前，优化代码结构以确保可扩展性、可维护性和性能

---

## 1. 当前架构分析

### 1.1 现有结构

```
dae-proxy/src/
├── lib.rs              # 模块导出
├── connection.rs       # 连接定义
├── connection_pool.rs  # 连接池
├── tcp.rs             # TCP 代理
├── udp.rs             # UDP 代理
├── proxy.rs           # 主代理协调
├── ebpf_integration.rs # eBPF 集成
├── protocol_dispatcher.rs  # 协议分发
├── socks5.rs          # SOCKS5 协议
├── http_proxy.rs      # HTTP 代理
├── shadowsocks.rs     # Shadowsocks 协议
├── vless.rs           # VLESS 协议
├── vmess.rs           # VMess 协议
├── trojan.rs          # Trojan 协议
├── rules.rs           # 规则定义
├── rule_engine.rs     # 规则引擎
└── control.rs         # 控制接口
```

### 1.2 识别的问题

| 问题 | 影响 | 严重性 |
|------|------|--------|
| 协议模块扁平化，无层次划分 | 添加新协议需要修改多处 | 🔴 高 |
| 缺少 Transport 抽象层 | WebSocket/TLS 等传输层难以添加 | 🔴 高 |
| 规则引擎与 eBPF 耦合 | 难以独立测试和复用 | 🟡 中 |
| 节点管理缺失 | 无法实现自动切换/延迟测试 | 🔴 高 |
| DNS 处理分散 | 高级 DNS 功能难以实现 | 🟡 中 |
| 配置与业务逻辑耦合 | 配置变更影响核心逻辑 | 🟡 中 |

---

## 2. 目标架构设计

### 2.1 分层架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        应用层 (Application)                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐│
│  │  dae-cli   │  │ dae-config │  │ dae-health  │  │ dae-ui  ││
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      代理核心层 (Proxy Core)                      │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    ProxyCoordinator                         ││
│  │  - 节点选择策略                                              ││
│  │  - 流量调度                                                  ││
│  │  - 连接管理                                                  ││
│  └─────────────────────────────────────────────────────────────┘│
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   RuleEngine    │  │  NodeManager    │  │   DnsResolver   │ │
│  │   (规则引擎)    │  │   (节点管理)    │  │   (DNS 解析)    │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    协议层 (Protocol Layer)                        │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    ProtocolHandler                          ││
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐  ││
│  │  │  SOCKS5   │ │   HTTP    │ │    SS     │ │   VLESS   │  ││
│  │  └───────────┘ └───────────┘ └───────────┘ └───────────┘  ││
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐  ││
│  │  │  VMess    │ │  Trojan   │ │   Tuic    │ │  Hysteria2│  ││
│  │  └───────────┘ └───────────┘ └───────────┘ └───────────┘  ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                  Transport Layer                            ││
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────┐ ││
│  │  │   TCP   │ │   UDP   │ │   WS    │ │  TLS    │ │ gRPC  │ ││
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └───────┘ ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      数据平面层 (Data Plane)                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐│
│  │  eBPF/XDP  │  │  TUN/TAP    │  │  Raw Socket │  │ iptables│
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 核心抽象

#### 2.2.1 协议处理器 Trait

```rust
// packages/dae-proxy/src/protocol/mod.rs

/// 协议处理器 Trait - 所有协议实现必须实现此 Trait
pub trait ProtocolHandler: Send + Sync {
    /// 协议名称
    fn name(&self) -> &'static str;
    
    /// 处理入站连接
    async fn handle_inbound(
        &self,
        conn: Connection,
        ctx: &ProtocolContext,
    ) -> Result<(), ProxyError>;
    
    /// 处理出站连接
    async fn handle_outbound(
        &self,
        target: &TargetAddr,
        ctx: &ProtocolContext,
    ) -> Result<Connection, ProxyError>;
    
    /// 获取协议特定配置
    fn config(&self) -> &ProtocolConfig;
}

/// 协议上下文 - 包含请求相关的信息
pub struct ProtocolContext {
    pub rule_action: RuleAction,
    pub node_id: Option<String>,
    pub direct: bool,
    pub packet_info: PacketInfo,
}

/// 目标地址
pub enum TargetAddr {
    Domain(String, u16),
    Ip(std::net::IpAddr, u16),
    Unix(std::path::PathBuf),
}
```

#### 2.2.2 传输层 Trait

```rust
// packages/dae-proxy/src/transport/mod.rs

/// 传输层 Trait - 实现各种传输方式
pub trait Transport: Send + Sync {
    /// 传输类型名称
    fn name(&self) -> &'static str;
    
    /// 连接到远程地址
    async fn dial(&self, addr: &str) -> Result<TcpStream, io::Error>;
    
    /// 监听本地端口
    async fn listen(&self, addr: &str) -> Result<Incoming, io::Error>;
    
    /// 是否支持 UDP
    fn supports_udp(&self) -> bool {
        false
    }
}

/// TCP 传输 (默认)
pub struct TcpTransport;

/// WebSocket 传输
pub struct WsTransport {
    pub path: String,
    pub headers: HashMap<String, String>,
    pub tls: bool,
}

/// TLS 传输
pub struct TlsTransport {
    pub alpn: Vec<String>,
    pub fingerprint: String,  // for Reality
}

/// gRPC 传输
pub struct GrpcTransport {
    pub service_name: String,
}
```

#### 2.2.3 节点管理器 Trait

```rust
// packages/dae-proxy/src/node/mod.rs

/// 节点 Trait - 所有节点类型实现此 Trait
pub trait Node: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn protocol(&self) -> ProtocolType;
    
    /// 测试延迟
    async fn ping(&self) -> Result<Duration, NodeError>;
    
    /// 获取链接
    async fn connect(&self) -> Result<Arc<dyn OutboundHandler>, NodeError>;
    
    /// 健康检查
    async fn health_check(&self) -> NodeHealth;
}

/// 节点健康状态
#[derive(Debug, Clone)]
pub enum NodeHealth {
    Healthy,
    Degraded(u32),  // latency in ms
    Unhealthy(String),
}

/// 节点管理器 - 负责节点选择、健康检查、自动切换
pub trait NodeManager: Send + Sync {
    /// 按策略选择节点
    async fn select_node(&self, policy: &SelectionPolicy) -> Option<Arc<dyn Node>>;
    
    /// 标记节点不可用
    async fn mark_unavailable(&self, node_id: &str);
    
    /// 获取所有可用节点
    async fn available_nodes(&self) -> Vec<Arc<dyn Node>>;
    
    /// 执行延迟测试
    async fn run_latency_test(&self) -> HashMap<String, Duration>;
}
```

#### 2.2.4 规则引擎扩展

```rust
// packages/dae-proxy/src/rules/mod.rs

/// 扩展规则类型
#[derive(Debug, Clone)]
pub enum RuleType {
    // 现有规则
    Domain(DomainRule),
    IpCidr(IpCidrRule),
    GeoIp(GeoIpRule),
    Process(ProcessRule),
    DnsType(DnsTypeRule),
    
    // 新增规则
    ProcessName(String),           // 按进程名分流
    MacAddress([u8; 6]),          // 按 MAC 地址分流
    Port(u16),                     // 按端口分流
    Invert(Box<RuleType>),        // 反向匹配
    And(Vec<RuleType>),            // 逻辑与
    Or(Vec<RuleType>),             // 逻辑或
}

/// 规则动作扩展
#[derive(Debug, Clone, Copy)]
pub enum RuleAction {
    Proxy,        // 代理
    Direct,       // 直连 (新)
    Block,        // 阻止
    MustDirect,   // 强制直连 (新) - Real Direct
}

/// 规则匹配结果
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub matched: bool,
    pub action: RuleAction,
    pub node_selector: Option<String>,  // 可指定特定节点
    pub latency_target: Option<Duration>, // 延迟目标
}
```

---

## 3. 目录结构优化

### 3.1 重组后的结构

```
packages/dae-proxy/src/
├── lib.rs                 # 模块导出
├── main.rs               # 可执行入口
│
├── core/                 # 核心抽象 (新增)
│   ├── mod.rs
│   ├── error.rs          # 统一错误类型
│   ├── context.rs        # 请求上下文
│   └── result.rs         # Result 类型别名
│
├── protocol/             # 协议层 (重构)
│   ├── mod.rs           # ProtocolHandler trait
│   ├── socks5/
│   │   ├── mod.rs
│   │   └── handler.rs
│   ├── http/
│   │   ├── mod.rs
│   │   └── handler.rs
│   ├── shadowsocks/
│   │   ├── mod.rs
│   │   └── handler.rs
│   ├── vless/
│   │   ├── mod.rs
│   │   └── handler.rs
│   ├── vmess/
│   │   ├── mod.rs
│   │   └── handler.rs
│   ├── trojan/
│   │   ├── mod.rs
│   │   └── handler.rs
│   ├── tuic/            # 新增
│   │   ├── mod.rs
│   │   └── handler.rs
│   ├── hysteria2/       # 新增
│   │   ├── mod.rs
│   │   └── handler.rs
│   └── juicity/         # 新增
│       ├── mod.rs
│       └── handler.rs
│
├── transport/           # 传输层 (新增)
│   ├── mod.rs           # Transport trait
│   ├── tcp.rs
│   ├── ws.rs            # WebSocket
│   ├── tls.rs           # TLS / Reality
│   └── grpc.rs          # gRPC
│
├── routing/             # 路由层 (重构)
│   ├── mod.rs
│   ├── rule_engine.rs   # 规则引擎
│   ├── rules/           # 规则定义
│   │   ├── mod.rs
│   │   ├── domain.rs
│   │   ├── ipcidr.rs
│   │   ├── geoip.rs
│   │   ├── process.rs   # 进程名规则
│   │   ├── mac.rs       # MAC 地址规则
│   │   └── composite.rs # 组合规则
│   └── matcher.rs       # 匹配器
│
├── node/               # 节点管理 (新增)
│   ├── mod.rs
│   ├── node.rs         # Node trait
│   ├── manager.rs       # NodeManager
│   ├── selector.rs      # 节点选择策略
│   ├── health.rs        # 健康检查
│   └── lat_test.rs     # 延迟测试
│
├── dns/                # DNS 处理 (新增)
│   ├── mod.rs
│   ├── resolver.rs     # DNS 解析器
│   ├── upstream.rs      # 上游 DNS
│   └── routing.rs       # DNS 路由
│
├── data_plane/         # 数据平面 (重构)
│   ├── mod.rs
│   ├── connection.rs
│   ├── connection_pool.rs
│   ├── tcp.rs
│   ├── udp.rs
│   └── ebpf/          # eBPF 集成
│       ├── mod.rs
│       └── maps.rs
│
├── control/            # 控制接口
│   └── control.rs
│
└── config/             # 配置 (移动)
    └── config.rs
```

---

## 4. 新增模块设计

### 4.1 Transport 模块

```rust
// packages/dae-proxy/src/transport/mod.rs

use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// 传输层 Trait
#[async_trait]
pub trait Transport: Send + Sync + Debug {
    fn name(&self) -> &'static str;
    
    /// 连接到地址
    async fn dial(&self, addr: &str) -> io::Result<TcpStream>;
    
    /// 监听地址
    async fn listen(&self, addr: &str) -> io::Result<Incoming>;
    
    /// 是否支持 UDP
    fn supports_udp(&self) -> bool {
        false
    }
}

/// WebSocket 传输
#[derive(Debug)]
pub struct WsTransport {
    pub path: String,
    pub host: String,
    pub tls: bool,
}

#[async_trait]
impl Transport for WsTransport {
    fn name(&self) -> &'static str {
        "websocket"
    }
    
    async fn dial(&self, addr: &str) -> io::Result<TcpStream> {
        // 实现 WebSocket 握手
    }
    
    async fn listen(&self, addr: &str) -> io::Result<Incoming> {
        // 实现 WebSocket 服务器
    }
    
    fn supports_udp(&self) -> bool {
        false
    }
}

/// TLS 传输 (支持 Reality)
#[derive(Debug)]
pub struct TlsTransport {
    pub alpn: Vec<String>,
    pub server_name: String,
    pub reality: Option<RealityConfig>,
}
```

### 4.2 Node 模块

```rust
// packages/dae-proxy/src/node/mod.rs

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

/// 节点 Trait
#[async_trait]
pub trait Node: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn protocol(&self) -> &'static str;
    
    /// 测试延迟 (ms)
    async fn ping(&self) -> Result<u32, NodeError>;
    
    /// 获取出站处理器
    async fn outbound(&self) -> Result<Arc<dyn OutboundHandler>, NodeError>;
}

/// 节点管理器
#[async_trait]
pub trait NodeManager: Send + Sync {
    /// 选择节点
    async fn select(&self, policy: &SelectionPolicy) -> Option<Arc<dyn Node>>;
    
    /// 更新延迟
    async fn update_latency(&self, node_id: &str, latency: u32);
    
    /// 获取所有节点
    async fn all_nodes(&self) -> Vec<Arc<dyn Node>>;
    
    /// 标记节点离线
    async fn set_offline(&self, node_id: &str);
}

/// 选择策略
#[derive(Debug, Clone)]
pub enum SelectionPolicy {
    /// 最低延迟
    LowestLatency,
    /// 随机
    Random,
    /// 指定节点
    Specific(String),
    /// 负载均衡
    RoundRobin,
}
```

### 4.3 Process 分流模块

```rust
// packages/dae-proxy/src/routing/rules/process.rs

use std::collections::HashMap;
use std::sync::RwLock;

/// 进程名缓存
pub struct ProcessCache {
    cache: RwLock<HashMap<u32, String>>,  // PID -> Process Name
    max_size: usize,
}

impl ProcessCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            max_size,
        }
    }
    
    /// 获取进程名 (通过 PID)
    pub fn get_name(&self, pid: u32) -> Option<String> {
        let cache = self.cache.read().unwrap();
        cache.get(&pid).cloned()
    }
    
    /// 通过 socket 获取进程名
    pub fn get_by_socket(&self, fd: i32) -> Option<String> {
        // 通过 /proc/{pid}/fd/{fd} 获取
    }
}

/// 进程名规则
#[derive(Debug, Clone)]
pub struct ProcessRule {
    pub pattern: String,
    pub match_type: ProcessMatchType,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Copy)]
pub enum ProcessMatchType {
    Exact,      // 精确匹配
    Prefix,     // 前缀匹配
    Contains,   // 包含匹配
    Regex,      // 正则匹配
}
```

---

## 5. 实施计划

### Phase A: 架构重构 (1-2天)

| 步骤 | 内容 | 优先级 |
|------|------|--------|
| A1 | 创建 `core/` 模块 - 统一错误类型、Context | 🔴 |
| A2 | 创建 `transport/` 模块 - Transport trait 定义 | 🔴 |
| A3 | 创建 `node/` 模块 - Node/NodeManager trait | 🔴 |
| A4 | 创建 `protocol/` 目录结构 - 协议抽象层 | 🔴 |
| A5 | 创建 `routing/rules/process.rs` - 进程规则 | 🟡 |
| A6 | 创建 `routing/rules/mac.rs` - MAC 规则 | 🟡 |

### Phase B: 核心功能实现 (按优先级)

| 步骤 | 功能 | 依赖 | 优先级 |
|------|------|------|--------|
| B1 | Real Direct (must_direct) | A1-A6 | 🔴 |
| B2 | Process Name 分流 | A5 | 🔴 |
| B3 | WebSocket 传输层 | A2 | 🟡 |
| B4 | TLS/Reality 传输层 | A2 | 🟡 |
| B5 | 节点管理器 + 延迟测试 | A3 | 🟡 |
| B6 | Tuic v5 协议 | A2, B5 | 🟢 |
| B7 | Juicity 协议 | A2, B5 | 🟢 |
| B8 | Hysteria2 协议 | A2, B5 | 🟢 |
| B9 | MAC 地址分流 | A6 | 🟢 |
| B10 | 高级 DNS 解析 | - | 🟢 |

---

## 6. 迁移策略

### 6.1 向后兼容

- 保持现有 `lib.rs` 导出不变
- 旧模块通过新模块间接调用
- 渐进式重构，不破坏现有 API

### 6.2 配置兼容

```toml
# 新配置格式 (向后兼容旧格式)
[routing]
must_direct = ["ipcidr(192.168.0.0/16)"]
pname(chrome) = "proxy"

[nodes]
[[nodes.proxies]]
name = "test"
type = "ss"
# ...

[node_policy]
selection = "lowest_latency"
health_check_interval = 30
```

---

## 7. 测试策略

### 7.1 单元测试

```bash
# 运行协议层测试
cargo test -p dae-proxy protocol::
cargo test -p dae-proxy transport::
cargo test -p dae-proxy routing::

# 运行节点管理测试
cargo test -p dae-proxy node::
```

### 7.2 集成测试

```bash
# 运行完整流程测试
cargo test -p dae-proxy --test integration

# 测试 Real Direct 功能
cargo test -p dae-proxy --test real_direct
```

---

*文档版本: v1.0*
*创建日期: 2026-04-02*
