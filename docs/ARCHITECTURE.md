# 内部架构设计

## 架构概览

dae-rs 采用模块化架构，核心设计理念：

1. **零成本抽象**: 使用 Rust trait 和泛型，无运行时开销
2. **异步优先**: 全面使用 Tokio 异步运行时
3. **内存安全**: 利用 Rust 所有权系统，无 GC 停顿
4. **可扩展性**: 插件式协议和传输层支持

```
┌─────────────────────────────────────────────────────────────┐
│                        dae-cli                               │
│    run │ status │ validate │ reload │ shutdown │ test      │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
┌─────────────────────┐       ┌─────────────────────┐
│     dae-config      │       │      dae-core       │
│  - 配置解析           │       │  - 引擎抽象          │
│  - 订阅格式          │       │  - 生命周期          │
│  - 规则验证          │       │                     │
└─────────┬───────────┘       └──────────┬──────────┘
          │                              │
          └──────────────┬───────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                       dae-proxy                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  协议调度层 (Protocol Dispatcher)      │   │
│  │         自动检测 → 协议 Handler → 连接管理             │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  TCP 代理     │  │  UDP 代理     │  │  连接池       │     │
│  │  (双向复制)   │  │  (NAT 语义)   │  │  (4-tuple)   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                 协议实现 (Handlers)                   │   │
│  │  VLESS │ VMess │ SS │ Trojan │ TUIC │ H2 │ Juicity  │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                 传输层 (Transport)                    │   │
│  │     TCP │ TLS │ WebSocket │ gRPC │ Meek             │   │
│  └─────────────────────────────────────────────────────┘   │
└──────────────────────────┬────────────────────────────────┘
                           │
┌──────────────────────────┼────────────────────────────────┐
│                    dae-ebpf                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   dae-xdp    │  │  dae-ebpf    │  │ dae-ebpf-dir │     │
│  │  (XDP 模式)  │  │ (TC hooks)   │  │  (Sockmap)   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                           │                                │
│                    eBPF Maps                              │
│           Session │ Routing │ Stats │ Config               │
└────────────────────────────────────────────────────────────┘
```

## 连接池设计

### 4-Tuple 连接键

```rust
pub struct ConnectionKey {
    pub src_ip: CompactIp,      // 源 IP (IPv6 支持)
    pub dst_ip: CompactIp,      // 目标 IP
    pub src_port: u16,          // 源端口
    pub dst_port: u16,          // 目标端口
    pub protocol: IpProtocol,   // TCP/UDP
}
```

### CompactIp - IPv6 高效存储

```rust
pub struct CompactIp(u128);

impl CompactIp {
    // IPv4 映射到 IPv6
    // 2001::xxxx:xxxx 格式
    pub fn from_ipv4(v4: Ipv4Addr) -> Self;
    pub fn from_ipv6(v6: Ipv6Addr) -> Self;
}
```

### 连接池参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `idle_timeout` | 60s | 空闲连接超时 |
| `max_lifetime` | 300s | 最大生命周期 |
| `pool_size` | 无限制 | 最大连接数 |
| `gc_interval` | 30s | 垃圾回收间隔 |

### 连接复用流程

```
Client Request 1 ──┐
                   ├──▶ Connection Pool ──▶ Server (连接复用)
Client Request 2 ──┘
                   │
Client Request 3 ──┴──▶ Connection Pool ──▶ Server (新建连接)
```

## eBPF 集成

### 架构模式

dae-rs 支持三种 eBPF 集成模式：

| 模式 | 模块 | 性能 | 兼容性 |
|------|------|------|--------|
| **XDP** | dae-xdp | 最高 | 需要驱动支持 |
| **TC** | dae-ebpf | 高 | 广泛支持 |
| **Sockmap** | dae-ebpf-direct | 中 | 特定场景 |

### eBPF Maps

```
┌─────────────────────────────────────────┐
│              eBPF Maps                  │
├─────────────────────────────────────────┤
│  Session Map: 连接状态跟踪               │
│  Routing Map: 路由规则                   │
│  Stats Map: 流量统计                     │
│  Config Map: 内核配置                    │
└─────────────────────────────────────────┘
```

### In-Memory Stub

eBPF 内核部分为最小化代码，通过 userspace stub 通信：

```rust
// dae-proxy 端
pub struct EbpfSessionHandle {
    map_fd: Arc<Fd>,
}

impl EbpfSessionHandle {
    pub async fn get_session(&self, key: &SessionKey) -> Option<Session>;
    pub async fn update_session(&self, key: &SessionKey, session: &Session);
}
```

## 规则引擎

### 规则匹配顺序

```
数据包
  │
  ▼
┌──────────────────┐
│ Priority (优先级) │ ◀─── 数字越小优先级越高
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Rule Type Match  │ ◀─── 按类型逐一匹配
│ - domain         │
│ - domain-suffix  │
│ - domain-keyword │
│ - geoip          │
│ - ipcidr         │
│ - process        │
│ - dnstype        │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Action         │ ◀─── proxy / direct / drop
└──────────────────┘
```

### 规则类型实现

| 类型 | 算法 | 性能 |
|------|------|------|
| `domain` | Exact match | O(1) |
| `domain-suffix` | Radix tree | O(log n) |
| `domain-keyword` | Substring search | O(n) |
| `ipcidr` | Longest prefix match | O(log n) |
| `geoip` | Bitmap lookup | O(1) |
| `process` | Hash set | O(1) |

### 规则组配置

```rust
pub struct RuleGroup {
    pub name: String,
    pub rules: Vec<Rule>,
    pub first_match: bool,      // 首次匹配后停止
    pub default_action: Action,
}

pub enum RuleMatchAction {
    Pass,
    Proxy(NodeSelector),
    Direct,
    Drop,
}
```

## DNS 解析管道

### DNS 解析流程

```
应用 DNS 查询
      │
      ▼
┌──────────────────┐
│  DNS 劫持检测     │ ◀─── 检查 dns_hijack 配置
└────────┬─────────┘
         │
    ┌────┴────┐
    ▼         ▼
  匹配    不匹配
    │         │
    ▼         │
┌──────────┐  │
│ 本地解析  │  │
│          │  │
│ 规则引擎  │  │
│ 决定走向  │  │
└────┬─────┘  │
     │        │
     └────┬───┘
          ▼
   ┌──────────────┐
   │   规则匹配    │
   │  proxy/direct│
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │  DNS 上游     │
   │ (分流/直连)   │
   └──────────────┘
```

### DNS 缓存

```rust
pub struct DnsCache {
    cache: RwLock<HashMap<String, DnsRecord>>,
    ttl: Duration,
}

impl DnsCache {
    pub fn get(&self, domain: &str) -> Option<Vec<IpAddr>>;
    pub fn set(&self, domain: &str, addrs: Vec<IpAddr>);
}
```

### DNS 上游选择

```toml
[transparent_proxy]
# 代理上游 (用于海外解析)
dns_upstream_proxy = ["https://1.1.1.1/dns-query"]

# 直连上游 (用于国内解析)
dns_upstream_direct = ["https://dns.google/dns-query"]
```

## 节点管理

### Zed-Style Store 模式

dae-rs 节点管理采用 Zed 编辑器的 Store 模式：

```
┌─────────────────────────────────────────┐
│             NodeStore (Trait)           │
│  - select_node()                        │
│  - add_node()                           │
│  - remove_node()                        │
│  - update_node()                        │
└─────────────────────────────────────────┘
         ▲
         │ implements
         │
┌────────┴────────────────────────────────┐
│          NodeManager (Impl)             │
│  - NodeStore Trait 实现                 │
│  - 生命周期管理                          │
│  - 健康检查                              │
└─────────────────────────────────────────┘
```

### 节点选择策略

| 策略 | 说明 | 适用场景 |
|------|------|----------|
| `Latency` | 最低延迟优先 | 实时应用 |
| `RoundRobin` | 轮询 | 负载均衡 |
| `Random` | 随机选择 | 无状态服务 |
| `Priority` | 固定优先级 | 主备切换 |

### 一致性哈希

```rust
pub struct ConsistentHash {
    ring: Arc<RwLock<BTreeMap<u64, NodeId>>>,
    nodes: Arc<RwLock<HashMap<NodeId, Node>>>,
    virtual_nodes: usize,  // 虚拟节点数
}

impl ConsistentHash {
    pub fn select(&self, key: &[u8]) -> Option<NodeId>;
}
```

### 粘性会话 (Sticky Sessions)

```rust
pub struct StickyConfig {
    enabled: bool,
    session_timeout: Duration,
    session_key: SessionKeyType,  // srcip / userid / custom
}
```

## 数据流架构

### TCP 数据流

```
Client                      dae-rs                     Server
  │                           │                           │
  │──── TCP SYN ─────────────▶│──── TCP SYN ─────────────▶│
  │                           │                           │
  │◀─── TCP SYN-ACK ─────────│◀─── TCP SYN-ACK ──────────│
  │                           │                           │
  │──── TCP ACK ─────────────▶│──── TCP ACK ──────────────▶│
  │                           │                           │
  │──── Protocol ────────────▶│                           │
  │    (首字节检测)            │                           │
  │                           │                           │
  │──── Application ─────────▶│──── Application ─────────▶│
  │    Data                   │    Data                   │
  │◀─── Response ────────────│◀─── Response ─────────────│
  │                           │                           │
```

### UDP 数据流 (NAT 语义)

```
Client                      dae-rs                     Server
  │                           │                           │
  │──── UDP Packet ─────────▶│                           │
  │    (创建 NAT 映射)         │                           │
  │                           │──── UDP Packet ──────────▶│
  │                           │                           │
  │◀─── UDP Response ─────────│◀─── UDP Response ─────────│
  │    (通过 NAT 映射转发)     │                           │
  │                           │                           │
  │     ... 任意数量 UDP ...   │                           │
  │                           │                           │
```

### 代理链数据流

```
Client → Proxy1(Camo) → Proxy2(TLS) → Proxy3 → Target
         │                │             │
      WebRTC           端到端         原始
      伪装              TLS           TCP
```

## 错误处理

### 错误类型层次

```rust
pub enum Error {
    /// 连接错误
    Connection(ConnectionError),
    /// 协议错误
    Protocol(ProtocolError),
    /// 超时错误
    Timeout(TimeoutError),
    /// eBPF 错误
    Ebpf(EbpfError),
    /// 配置错误
    Config(ConfigError),
}
```

### 重试策略

```rust
pub struct RetryConfig {
    pub max_retries: u32,        // 最大重试次数
    pub initial_delay: Duration, // 初始延迟
    pub max_delay: Duration,    // 最大延迟
    pub backoff: Backoff,       // 退避算法
}
```

## 性能优化

### 连接池优化

- 使用 `Arc<ConnectionPool>` 共享
- 读写分离 (`RwLock`)
- 无锁数据结构 (`AtomicU64`)

### 内存优化

- 对象池 (`bumpalo`)
- slab 分配器
- 零拷贝解析

### I/O 优化

- io_uring 支持 (Linux 5.6+)
- TCP_NODELAY
- SO_KEEPALIVE
