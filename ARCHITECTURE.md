# dae-rs 代码架构文档

> 版本: 0.1.0
> 更新: 2026-04-02

## 一、整体架构

dae-rs 是一个高性能透明代理，采用模块化 Rust 代码架构。

### 1.1 Crate 结构

```
dae-rs/
├── packages/
│   ├── dae-cli/           # CLI 入口和 REST API
│   ├── dae-api/       # 独立 REST API 模块
│   ├── dae-core/          # 核心引擎（基础类型）
│   ├── dae-config/        # 配置解析
│   ├── dae-proxy/        # 代理核心（最大最复杂）
│   └── dae-ebpf/          # eBPF 相关
│       ├── dae-xdp/       # XDP eBPF 程序
│       ├── dae-ebpf/      # 用户空间 eBPF 加载器
│       ├── dae-ebpf-common/# 共享 eBPF 类型
│       └── dae-ebpf-direct/# 直接模式 eBPF
├── benches/               # 性能测试
└── Cargo.toml            # workspace 配置
```

### 1.2 依赖关系

```
dae-cli
├── dae-core
├── dae-proxy
└── dae-config

dae-proxy
├── dae-core
└── dae-config
```

---

## 二、dae-proxy 模块详解

### 2.1 目录结构

```
packages/dae-proxy/src/
├── lib.rs                 # 库入口，导出所有公共类型
│
├── 核心模块
│   ├── proxy.rs          # 主代理协调器（19KB）
│   ├── connection.rs      # 连接跟踪
│   ├── connection_pool.rs # 连接池
│   ├── tcp.rs            # TCP 转发
│   ├── udp.rs            # UDP 转发
│   ├── control.rs        # 控制平面 API
│   └── protocol_dispatcher.rs # 协议分发
│
├── 协议实现
│   ├── socks5.rs         # SOCKS5 协议（27KB）
│   ├── http_proxy.rs     # HTTP 代理
│   ├── shadowsocks.rs    # Shadowsocks（18KB）
│   ├── trojan_protocol/  # Trojan 协议（Zed 风格拆分）
│   │   ├── mod.rs
│   │   ├── protocol.rs   # 协议类型
│   │   ├── config.rs    # 配置
│   │   ├── handler.rs    # 处理器
│   │   └── server.rs    # 服务器
│   ├── vless.rs          # VLESS 协议（20KB）
│   ├── vmess.rs          # VMess 协议（19KB）
│   ├── hysteria2/        # Hysteria2 协议
│   ├── juicity/          # Juicity 协议
│   └── tuic/             # TUIC 协议
│
├── 规则引擎
│   ├── rules.rs          # 规则定义（17KB）
│   ├── rule_engine.rs    # 规则匹配引擎（16KB）
│   ├── process/         # 进程规则
│   └── mac/             # MAC 地址规则
│
├── 节点管理 (Zed 风格)
│   ├── node/
│   │   ├── mod.rs
│   │   ├── node.rs      # Node trait
│   │   ├── manager.rs   # NodeManager trait
│   │   ├── selector.rs  # NodeSelector
│   │   ├── health.rs     # 健康检查
│   │   ├── simple.rs     # 简单实现
│   │   └── store.rs     # Zed 风格 Store 类型
│
├── 协议抽象层 (Zed 风格)
│   ├── protocol/
│   │   ├── mod.rs        # ProtocolType 枚举
│   │   ├── handler.rs    # ProtocolRegistry
│   │   ├── simple_handler.rs    # Handler trait
│   │   └── unified_handler.rs   # 统一 Handler
│   │   ├── socks5/
│   │   ├── http/
│   │   ├── shadowsocks/
│   │   └── vless/
│
├── eBPF 集成
│   ├── ebpf_integration.rs # eBPF 映射包装器
│   └── config/            # eBPF 配置
│
├── DNS
│   └── dns/
│       └── mac_dns.rs     # MAC-based DNS
│
├── 传输层
│   └── transport/
│       ├── ws.rs          # WebSocket
│       ├── tls.rs         # TLS
│       └── grpc.rs        # gRPC
│
├── 指标
│   └── metrics/
│       └── prometheus.rs  # Prometheus 导出
│
└── 辅助模块
    ├── core/              # 核心类型
    └── config/            # 热重载配置
```

---

## 三、Zed 架构风格应用

参考 Zed 的架构设计，dae-rs 采用了以下模式：

### 3.1 命名规范

| Zed 模式 | dae-rs 应用 |
|----------|-------------|
| `*Store` | `NodeStore` - 抽象接口 |
| `*Manager` | `NodeManager` - 生命周期管理 |
| `*Handle` | `NodeHandle` - 实体引用 |
| `*State` | `NodeState` - 不可变快照 |

### 3.2 Handler Trait 统一

```rust
// 统一 Handler 接口（Zed 风格）
#[async_trait]
pub trait Handler: Send + Sync {
    type Config: HandlerConfig;
    
    fn name(&self) -> &'static str;
    fn protocol(&self) -> ProtocolType;
    fn config(&self) -> &Self::Config;
    
    async fn handle(&self, conn: Connection) -> Result<(), ProxyError>;
    async fn reload(&self, config: Self::Config) -> Result<(), ProxyError> { Ok(()) }
}
```

### 3.3 模块拆分示例 (trojan_protocol)

```
trojan.rs (632行)
    ↓ 重构
trojan_protocol/
├── mod.rs       # 主入口，重新导出
├── protocol.rs  # TrojanCommand, TrojanAddressType, TrojanTargetAddress
├── config.rs    # TrojanServerConfig, TrojanClientConfig, TrojanTlsConfig
├── handler.rs  # TrojanHandler (多后端 round-robin)
└── server.rs   # TrojanServer
```

---

## 四、核心类型

### 4.1 连接管理

| 类型 | 说明 |
|------|------|
| `Connection` | 单个连接 |
| `ConnectionPool` | 连接池，按 4-tuple 复用 |
| `ConnectionKey` | 连接标识 (src_ip, dst_ip, src_port, dst_port, protocol) |

### 4.2 协议类型

```rust
pub enum ProtocolType {
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

### 4.3 规则引擎

```rust
// 规则匹配动作
pub enum RuleMatchAction {
    Pass,    // 直通
    Proxy,   // 代理
    Drop,    // 丢弃
    Direct,  // 直连
}

// 规则类型
pub enum RuleType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    IpCidr,
    GeoIp,
    Process,
    Mac,
}
```

---

## 五、配置结构

### 5.1 ProxyConfig

```rust
pub struct ProxyConfig {
    pub tcp: TcpProxyConfig,
    pub udp: UdpProxyConfig,
    pub trojan: Option<TrojanClientConfig>,
    pub trojan_backends: Vec<TrojanServerConfig>,
    // ...
}
```

### 5.2 规则配置

```rust
pub struct RuleEngineConfig {
    pub geoip_enabled: bool,
    pub process_matching_enabled: bool,
    pub default_action: RuleAction,
    pub hot_reload_enabled: bool,
}
```

---

## 六、热重载支持

```rust
// 配置观察者模式
pub trait HotReloadable {
    async fn reload(&mut self, config: Config) -> Result<()>;
}

// 配置事件
pub enum ConfigEvent {
    Reloaded(Config),
    RulesChanged(Vec<Rule>),
    NodesChanged(Vec<Node>),
}
```

---

## 七、指标导出

Prometheus 格式指标：

| 指标 | 类型 | 说明 |
|------|------|------|
| `dae_connections_total` | Counter | 总连接数 |
| `dae_bytes_sent` | Counter | 发送字节 |
| `dae_bytes_received` | Counter | 接收字节 |
| `dae_active_connections` | Gauge | 活跃连接 |
| `dae_node_latency` | Histogram | 节点延迟 |

---

## 八、测试覆盖

```
Tests: 180 lib + 19 integration = 199 tests ✅
Warnings: 0 ✅
```

### 8.1 测试文件

| 文件 | 测试数 |
|------|--------|
| integration_tests.rs | 19 |
| trojan_protocol/ | 5 |
| rules.rs | 15+ |
| vmess.rs | 8 |
| vless.rs | 5 |
| control.rs | 1 |

---

## 九、代码统计

| 模块 | 文件数 | 代码行数 |
|------|--------|----------|
| dae-proxy | 77 | ~50,000 |
| dae-cli | 1 | ~3,000 |
| dae-config | 3 | ~2,000 |
| dae-core | 2 | ~500 |
| dae-ebpf | 4 | ~10,000 |
| **总计** | ~90 | ~65,000 |

---

## 十、架构演进历史

| 版本 | 变更 |
|------|------|
| v0.1.0 | 初始版本，支持 Trojan 多后端 |
| - | trojan.rs 拆分为 trojan_protocol/ |
| - | 新增统一 Handler trait |
| - | Node 模块添加 Zed 风格 Store |
| - | 修复 CI workflow 和 clippy 警告 |

---

## 十一、设计模式

### 11.1 行为型

- **策略模式**: `SelectionPolicy` (Latency, RoundRobin, Random)
- **观察者模式**: `HotReload` 配置观察
- **模板方法**: `RuleEngine::match_packet()`

### 11.2 结构型

- **装饰器**: `ProtocolHandlerAdapter` 包装现有 Handler
- **代理模式**: `ConnectionPool` 连接代理

### 11.3 创建型

- **建造者**: `ProcessRuleSetBuilder`, `RuleGroup`
- **单例**: `METRICS_SERVER` 全局指标

---

## 十二、未来优化方向

1. **P0**: socks5.rs 拆分（类似 trojan_protocol）
2. **P1**: 统一所有协议到 Handler trait
3. **P2**: 错误处理统一（类似 anyhow/thiserror）
4. **P3**: 引入 `Entity` 模式替代 `Arc<RwLock<>>`

---

_文档生成时间: 2026-04-02_

---

## 十三、dae-api 独立模块

### 13.1 概述

从 dae-cli 中拆分的独立 REST API 模块，提供完整的 Web API 接口。

### 13.2 模块结构

```
packages/dae-api/src/
├── lib.rs              # 库入口
├── server.rs           # Axum 服务器
├── models.rs          # API 数据模型
├── websocket.rs       # WebSocket 支持
├── dashboard.html     # 内置 Dashboard
└── routes/
    ├── mod.rs         # 路由导出
    ├── nodes.rs      # 节点管理 API
    ├── rules.rs       # 规则管理 API
    ├── config.rs      # 配置 API
    └── stats.rs       # 统计 API
```

### 13.3 特性

| 特性 | 说明 |
|------|------|
| RESTful API | 完整的 CRUD 操作 |
| WebSocket | 实时数据推送 |
| CORS | 跨域支持 |
| Prometheus | 指标导出 |

### 13.4 使用方式

```bash
# 构建带 API 的 CLI
cargo build --features api

# API 默认不集成，减小二进制大小
```

### 13.5 API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/nodes | 节点列表 |
| GET | /api/nodes/{id} | 节点详情 |
| POST | /api/nodes/test | 测试节点 |
| GET | /api/rules | 规则列表 |
| GET | /api/config | 当前配置 |
| PUT | /api/config | 更新配置 |
| GET | /api/stats | 统计信息 |
| GET | /health | 健康检查 |

