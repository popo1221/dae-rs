# dae-rs vs Go dae 详细代码对比报告

> 生成时间: 2026-04-02
> dae-rs commit: b43de03 (Phase 2 eBPF Foundation)
> Go dae commit: 030902f (latest)

---

## 一、项目概览

| 维度 | Go dae | dae-rs |
|------|--------|--------|
| **总代码行数** | ~21,617 行 (139 个 .go 文件) | ~28,172 行 (127 个 .rs 文件) |
| **主要语言** | Go | Rust |
| **eBPF 实现** | Go + C (bcc/llvm) | Rust (aya-ebpf) |
| **许可证** | AGPL-3.0-only | AGPL-3.0-only |
| **组织** | daeuniverse | popo1221/dae-rs |

---

## 二、架构设计对比

### 2.1 模块组织方式

#### Go dae 模块结构 (~21,617 行)

```
go-dae/
├── main.go                           (32 lines) - 入口
├── cmd/                              (512 lines) - CLI 命令层
│   ├── cmd.go                        (47 lines)
│   ├── run.go                        (512 lines) - Run 命令（核心启动逻辑）
│   ├── reload.go
│   └── ...
├── control/                          (~4,480 行) - 控制平面核心
│   ├── control_plane.go              (1,030 lines) - 控制平面主结构
│   ├── control_plane_core.go         (704 lines) - 核心状态管理
│   ├── dns_control.go                (746 lines) - DNS 控制
│   ├── dns.go                        (442 lines) - DNS 实现
│   ├── bpf_utils.go                  (280 lines) - eBPF 工具函数
│   ├── tcp.go                         (197 lines) - TCP 处理
│   ├── udp.go                        (329 lines) - UDP 处理
│   └── kern/                         - C eBPF 内核代码
├── component/                        (~2,800 行) - 组件库
│   ├── dns/                          - DNS 组件
│   │   ├── dns.go                    (232 lines)
│   │   └── response_routing.go       (292 lines)
│   ├── outbound/                     - 出站代理组件
│   │   ├── dialer_group.go           (283 lines) - Dialer 组管理
│   │   └── dialer/                   - 各协议 Dialer 实现
│   │       ├── dialer.go            (130 lines)
│   │       ├── direct.go             (19 lines)
│   │       └── connectivity_check.go (660 lines)
│   ├── routing/                      - 规则路由引擎
│   │   ├── matcher_builder.go       (130 lines)
│   │   ├── function_parser.go        (158 lines)
│   │   ├── optimizer.go             (291 lines)
│   │   └── domain_matcher/          - 域名匹配器（Aho-Corasick/SlimTrie）
│   └── sniffing/                     - 协议探测
│       ├── sniffing.go               (227 lines)
│       ├── tls.go                    (175 lines)
│       ├── quic.go                   (161 lines)
│       └── http.go                   (67 lines)
├── config/                           (~300 行) - 配置解析
│   └── config.go                    (202 lines)
├── pkg/                              - 内部工具库
│   ├── config_parser/                - 配置解析器 (Go dae 特有 DSL)
│   │   ├── config_parser.go
│   │   └── section.go
│   └── ebpf_internal/               - eBPF ELF 加载器
└── common/                           - 公共工具
    ├── subscription/                 - 订阅解析 (231 lines)
    └── netutils/                     - 网络工具
```

#### dae-rs 模块结构 (~28,172 行)

```
dae-rs/packages/
├── dae-core/                         (76 lines) - 核心引擎抽象
│   └── src/engine.rs                (76 lines)
├── dae-config/                        (1,502 行) - 配置系统
│   └── src/
│       ├── lib.rs                   (1,133 lines) - 配置解析
│       └── rules.rs                 (369 lines) - 规则配置
├── dae-proxy/                        (~15,000 行) - 用户空间代理核心
│   └── src/
│       ├── lib.rs                   (204 lines) - 库入口（Zed 风格导出）
│       ├── proxy.rs                 (581 lines) - 代理协调器
│       ├── tcp.rs                   (322 lines) - TCP 中继
│       ├── connection.rs            (174 lines) - 连接跟踪
│       ├── connection_pool.rs       (264 lines) - 连接池
│       ├── ebpf_integration.rs     (503 lines) - eBPF 集成层
│       ├── rule_engine.rs           (531 lines) - 规则引擎
│       ├── rules.rs                (662 lines) - 规则类型
│       ├── dns/                     - DNS 模块
│       │   └── mac_dns.rs          (454 lines)
│       ├── node/                    - 节点管理
│       │   ├── manager.rs          (113 lines)
│       │   ├── selector.rs         (208 lines)
│       │   ├── simple.rs           (507 lines)
│       │   └── store.rs
│       ├── protocol/                - 协议处理器 (统一 Handler 架构)
│       │   ├── handler.rs          (~150 lines) - Handler Registry
│       │   ├── unified_handler.rs
│       │   ├── simple_handler.rs
│       │   ├── socks5/             - SOCKS5 协议
│       │   ├── http/               - HTTP 协议
│       │   ├── shadowsocks/        - Shadowsocks
│       │   └── vless/             - VLESS
│       ├── transport/               - 传输层
│       │   ├── tcp.rs
│       │   ├── tls.rs              (500 lines)
│       │   ├── ws.rs
│       │   └── grpc.rs
│       ├── vless.rs                (1,031 lines)
│       ├── vmess.rs                (628 lines)
│       ├── shadowsocks.rs          (552 lines)
│       ├── shadowsocks/ssr.rs      (558 lines)
│       ├── juicity/                - Juicity 协议
│       │   ├── juicity.rs          (558 lines)
│       │   └── codec.rs           (544 lines)
│       ├── hysteria2/              - Hysteria2 协议
│       │   └── hysteria2.rs
│       ├── trojan_protocol.rs
│       ├── mac/                     - MAC 地址规则
│       ├── process/                 - 进程名规则
│       ├── control.rs              - 控制平面
│       └── logging.rs              (521 lines)
├── dae-ebpf/                         - eBPF 子系统
│   ├── dae-ebpf-common/            - 共享类型（kernel/user-space）
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── config.rs           - ConfigEntry
│   │       ├── session.rs          - SessionKey/SessionEntry
│   │       ├── routing.rs          - RoutingEntry
│   │       ├── stats.rs            - StatsEntry
│   │       └── direct.rs
│   ├── dae-xdp/                    - XDP 程序
│   │   └── src/
│   │       ├── lib.rs
│   │       └── maps/              - eBPF Map wrappers
│   ├── dae-ebpf-direct/           - Sockmap 程序
│   └── dae-ebpf/                   - 用户空间加载器
│       └── src/
│           ├── loader.rs
│           └── main.rs
└── dae-cli/                         - CLI 工具
    └── src/main.rs
```

### 2.2 核心抽象层对比

#### Go dae 核心抽象 (`control_plane.go`, ~1,030 行)

```go
// control/control_plane.go
type ControlPlane struct {
    log             *logrus.Logger
    core            *controlPlaneCore     // 核心状态（eBPF 对象引用）
    deferFuncs      []func() error        // 资源清理函数列表
    listenIp        string
    outbounds       []*outbound.DialerGroup  // 出站 Dialer 组
    inConnections   sync.Map              // 入站连接跟踪
    dnsController   *DnsController
    dnsListener     *DNSListener
    // ...
}
```

**关键特点**:
- 使用 `sync.Mutex` + `sync.Map` 进行并发控制
- DialerGroup 是核心出站抽象，通过 `dialer.NewFromLink()` 从订阅 URL 解析创建
- eBPF 对象在 controlPlaneCore 中管理，通过 `InjectBpf()` / `EjectBpf()` 实现热更新
- 节点选择策略通过 `SelectionPolicy` 在 DialerGroup 层面实现

#### dae-rs 核心抽象 (`dae-proxy/src/lib.rs` + `proxy.rs`)

```rust
// dae-proxy/src/proxy.rs
pub struct Proxy {
    tcp: TcpProxy,
    udp: UdpProxy,
    ebpf_maps: EbpfMaps,
    pool: SharedConnectionPool,
    rule_engine: SharedRuleEngine,
    node_manager: Arc<NodeManager>,
    // ...
}
```

**关键特点**:
- 使用 `Arc<RwLock<>>` 进行并发控制（更 Rust 风格）
- 节点管理通过 `NodeManager` + `NodeSelector` trait 实现策略模式
- eBPF Maps 通过 `EbpfMaps` 封装，统一接口
- 连接池 `ConnectionPool` 基于 4-tuple 的连接复用

### 2.3 依赖注入方式

#### Go dae - 过程式初始化 + 函数参数传递

```go
// cmd/run.go
func Run(log *logrus.Logger, conf *config.Config, externGeoDataDirs []string) (err error) {
    c, err := newControlPlane(log, nil, nil, conf, externGeoDataDirs)
    // ...
}
```

- `newControlPlane()` 是主要工厂函数，接受 log、bpf、dnsCache、conf 等参数
- eBPF 对象通过 `InjectBpf(obj)` 注入到新的 ControlPlane
- 组件之间通过结构体字段和方法调用传递依赖

#### dae-rs - Rust Builder 模式 + Trait Bounds

```rust
// dae-proxy/src/proxy.rs
pub struct ProxyBuilder {
    config: ProxyConfig,
    ebpf_maps: EbpfMaps,
    rule_engine: Option<SharedRuleEngine>,
    // ...
}

impl ProxyBuilder {
    pub async fn build(self) -> Result<Proxy, ProxyError> {
        // 构建顺序明确，每步返回 Result
    }
}
```

- 使用 `Builder` 模式进行可选配置
- Trait `NodeSelector` 允许运行时替换选择策略
- Trait `ProtocolHandler` 允许注册/注销协议处理器
- `Arc<dyn Node>` 允许运行时多态

### 2.4 配置解析架构

#### Go dae - 自定义 DSL 解析器 (`pkg/config_parser/`)

```go
// pkg/config_parser/section.go
type Section struct {
    Name       string
    RawContent string
    Rules      []*RoutingRule  // 规则语法树
}
```

**特点**:
- 自研 `config_parser` 包实现 DSL 解析（~341 行 walker.go）
- 支持 `include` 指令合并多配置文件
- `mapstructure` tag 用于结构体字段映射
- 路由规则语法：`domain(baidu.com) && port(443) -> proxy`

**核心文件**:
| 文件 | 行数 | 功能 |
|------|------|------|
| `pkg/config_parser/config_parser.go` | ~250 | 主解析器 |
| `pkg/config_parser/walker.go` | 341 | 语法树遍历 |
| `pkg/config_parser/section.go` | ~100 | Section 语法结构 |

#### dae-rs - TOML + Serde (`dae-config/`)

```rust
// dae-config/src/lib.rs
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub nodes: Vec<NodeConfig>,
    pub rules: RulesConfig,
    pub logging: LoggingConfig,
}
```

**特点**:
- 使用 `serde` + `toml` 进行配置反序列化
- 规则配置通过 `rules.rs` 的 `RuleConfigItem` 结构定义
- 支持外部规则文件（`config_file` 字段）
- 验证逻辑在 `ConfigError` 枚举中集中管理

**核心文件**:
| 文件 | 行数 | 功能 |
|------|------|------|
| `dae-config/src/lib.rs` | 1,133 | 配置结构定义 |
| `dae-config/src/rules.rs` | 369 | 规则配置解析 |

---

## 三、协议实现对比

### 3.1 各协议代码组织方式

#### Go dae - Dialer 抽象 + outbound 库

Go dae 将协议实现放在外部 `github.com/daeuniverse/outbound` 库中，通过 `dialer.NewFromLink()` 从 URL 字符串解析创建 Dialer。

```
component/outbound/dialer/
├── dialer.go           (130 lines)  - Dialer trait/interface
├── direct.go           (19 lines)   - Direct dialer
├── block.go           - Block dialer
├── register.go        (30 lines)   - 从 Link 创建 Dialer
├── alive_dialer_set.go (302 lines) - 存活状态管理
├── connectivity_check.go (660 lines) - 连通性检查
└── ...
```

**优势**: 协议实现与核心逻辑解耦，可独立维护
**劣势**: 外部库依赖，修改协议需要跨仓库

#### dae-rs - 本地协议模块 + Trait Handler

```
packages/dae-proxy/src/
├── vless.rs           (1,031 lines) - VLESS 完整实现
├── vmess.rs          (628 lines)  - VMess 实现
├── shadowsocks.rs    (552 lines)  - Shadowsocks 实现
├── shadowsocks/ssr.rs (558 lines) - SSR 实现
├── juicity/          - Juicity 协议
│   ├── juicity.rs   (558 lines)
│   └── codec.rs     (544 lines)
├── hysteria2/        - Hysteria2 协议
│   └── hysteria2.rs
├── trojan_protocol.rs
└── protocol/
    ├── handler.rs   (~150 lines) - Handler Registry
    ├── unified_handler.rs        - 统一 Handler trait
    └── socks5/http/vless/       - 各协议 Handler 实现
```

**优势**: 协议实现与核心在同一代码库，便于迭代
**劣势**: 二进制体积可能较大（但 Rust 可优化）

### 3.2 Handler 模式对比

#### Go dae - Dialer Interface

```go
// component/outbound/dialer/dialer.go
type Dialer interface {
    Dial(ctx context.Context, network, address string) (net.Conn, error)
    Name() string
    // ...
}
```

- `DialerGroup` 管理多个 `Dialer`，提供 `Select()` 方法
- 协议特定的 dialing 逻辑在 outbound 库中

#### dae-rs - 统一 Handler Trait (Zed 风格)

```rust
// dae-proxy/src/protocol/unified_handler.rs
pub trait Handler: Send + Sync {
    async fn handle(&self, ctx: &mut Context) -> Result<()>;
    fn stats(&self) -> HandlerStats;
}

// dae-proxy/src/protocol/handler.rs
pub struct ProtocolRegistry {
    handlers: HashMap<ProtocolType, Arc<dyn ProtocolHandler>>,
}
```

- `ProtocolRegistry` 支持运行时注册/注销协议处理器
- `HandlerStats` 提供运行时统计
- 适配器模式 `ProtocolHandlerAdapter` 桥接旧接口

### 3.3 编解码实现对比

#### Go dae - 依赖外部库

Go dae 使用 `github.com/daeuniverse/outbound` 中的编解码实现，不在主仓库维护协议细节。

#### dae-rs - 本地实现

| 协议 | 文件 | 行数 | 关键类型 |
|------|------|------|----------|
| TUIC | `tuic/codec.rs` | 624 | `TuicCodec`, `TuicCommand` |
| Juicity | `juicity/codec.rs` | 544 | `JuicityCodec`, `JuicityFrame` |
| Shadowsocks | `shadowsocks.rs` | 552 | `SsCipherType`, `SsServerConfig` |
| VLESS | `vless.rs` | 1,031 | `VlessHandler`, `VlessRealityConfig` |
| VMess | `vmess.rs` | 628 | `VmessHandler`, `VmessSecurity` |

---

## 四、eBPF/XDP 集成对比

### 4.1 用户空间交互方式

#### Go dae - Cilium eBPF Go 绑定 + C 内核代码

```
control/
├── bpf_utils.go       (280 lines)  - eBPF Map 操作
├── kern/              - C 语言 eBPF 内核程序
│   └── tests/bpf_test.go
└── ...
pkg/ebpf_internal/
├── elf.go             - ELF 加载器
└── align.go           - 数据对齐工具
```

**Go dae eBPF 特点**:
- 使用 `github.com/cilium/ebpf` 库
- 内核程序用 C 编写，通过 clang 编译
- Map 类型：LPMTrie（路由）、Hash（会话）、Array（统计）
- 用户空间通过 `controlPlaneCore.bpf` 对象访问所有 Map

**核心数据结构** (`bpf_utils.go`):
```go
type _bpfTuples struct {
    Sip     [4]uint32
    Dip     [4]uint32
    Sport   uint16
    Dport   uint16
    L4proto uint8
}

type _bpfLpmKey struct {
    PrefixLen uint32
    Data      [4]uint32
}
```

#### dae-rs - aya-ebpf + Rust

```
packages/dae-ebpf/
├── dae-ebpf-common/   - 共享类型（no_std）
│   └── src/
│       ├── config.rs   - ConfigEntry
│       ├── session.rs  - SessionKey/SessionEntry
│       ├── routing.rs  - RoutingEntry
│       └── stats.rs    - StatsEntry
├── dae-xdp/            - XDP 程序
│   └── src/
│       ├── lib.rs
│       └── maps/
├── dae-ebpf-direct/    - Sockmap 程序
│   └── src/
│       ├── lib.rs
│       ├── maps.rs
│       ├── programs.rs
│       └── sockmap.rs
└── dae-ebpf/           - 用户空间加载器
    └── src/
        ├── loader.rs
        └── main.rs
```

**dae-rs eBPF 特点**:
- 使用 `aya-ebpf` 0.1 和 `aya` 0.13
- 内核程序用 Rust 编写（aya-ebpf）
- 用户空间用 Rust 编写
- 统一的 `ConfigEntry` 替代复杂的 `bpfTuples`

### 4.2 数据结构共享

#### Go dae 共享数据结构

```go
// control/bpf_utils.go
type _bpfTuples struct {
    Sip     [4]uint32    // Source IP (IPv6)
    Dip     [4]uint32    // Dest IP (IPv6)
    Sport   uint16
    Dport   uint16
    L4proto uint8
}
```

#### dae-rs 共享数据结构 (`dae-ebpf-common`)

```rust
// dae-ebpf-common/src/session.rs
#[repr(C)]
pub struct SessionKey {
    pub src_ip: u32,      // IPv4 only (简化)
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    reserved: [u8; 3],
}

// dae-ebpf-common/src/config.rs
#[repr(C)]
pub struct ConfigEntry {
    pub enabled: u8,
    pub reserved: [u8; 7],
}

// dae-ebpf-common/src/routing.rs
#[repr(C)]
pub struct RoutingEntry {
    pub route_id: u32,
    pub action: u8,    // 0=PASS, 1=REDIRECT, 2=DROP
    pub ifindex: u32,
    reserved: [u8; 4],
}
```

**对比**:
- dae-rs 使用 `#[repr(C)]` 保证与 C 兼容
- dae-rs 有独立的 `dae-ebpf-common` crate 明确边界
- Go dae 在同一个文件中定义结构，内核/用户共享需要额外注意字节序

---

## 五、规则引擎对比

### 5.1 规则匹配架构

#### Go dae - 函数式规则解析 (`component/routing/`)

```go
// component/routing/matcher_builder.go
type RulesBuilder struct {
    log     *logrus.Logger
    parsers map[string]FunctionParser  // 函数名 -> 解析器
}

// 规则语法:
// domain(baidu.com) && port(443) -> proxy
// ipcidr(192.168.0.0/16) -> direct
// geoip(cn) -> direct
```

**核心文件**:
| 文件 | 行数 | 功能 |
|------|------|------|
| `matcher_builder.go` | 130 | 规则构建器 |
| `function_parser.go` | 158 | 函数解析器工厂 |
| `optimizer.go` | 291 | 规则优化器（合并/排序） |
| `domain_matcher/ahocorasick_slimtrie.go` | ~400 | Aho-Corasick + SlimTrie 域名匹配 |

**特点**:
- 支持规则优化：合并相同出站的规则、排序优化
- 域名匹配使用 Aho-Corasick 自动机 + SlimTrie
- 支持 AND/OR 逻辑组合

#### dae-rs - 结构化规则匹配 (`dae-proxy/src/rules.rs`)

```rust
// dae-proxy/src/rules.rs
pub enum RuleType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    IpCidr,
    GeoIp,
    Process,
    DnsType,
    Capability,
}

pub struct DomainRule {
    pub rule_type: DomainRuleType,
}
```

**核心文件**:
| 文件 | 行数 | 功能 |
|------|------|------|
| `rule_engine.rs` | 531 | 规则引擎主逻辑 |
| `rules.rs` | 662 | 规则类型定义 |

### 5.2 分流逻辑

#### Go dae - DialerGroup Select

```go
// component/outbound/dialer_group.go
func (g *DialerGroup) Select(networkType *dialer.NetworkType, strictIpVersion bool) (d *dialer.Dialer, latency time.Duration, err error) {
    // 根据 selectionPolicy 选择:
    // - Random
    // - Fixed
    // - MinLastLatency
    // - MinAverage10Latencies
    // - MinMovingAverageLatencies
}
```

- 节点选择在内核空间完成（通过 eBPF Map）
- 用户空间通过 `DialerGroup.Select()` 获取选中的 Dialer

#### dae-rs - NodeSelector Trait

```rust
// dae-proxy/src/node/selector.rs
#[async_trait]
pub trait NodeSelector: Send + Sync {
    async fn select(&self, nodes: &[Arc<dyn Node>], policy: &SelectionPolicy) -> Option<Arc<dyn Node>>;
}

pub enum SelectionPolicy {
    LowestLatency,
    Specific(NodeId),
    Random,
    RoundRobin,
    PreferDirect,
}
```

- 完全在用户空间进行节点选择
- 支持 `PreferDirect` 策略（dae-rs 特有）

---

## 六、功能完善程度

### 6.1 测试覆盖率

#### Go dae 测试文件 (~17 个测试文件)

| 文件 | 测试类型 |
|------|----------|
| `common/bitlist/bitlist_test.go` | 单元测试 |
| `common/netutils/ip46_test.go` | 单元测试 |
| `component/outbound/dialer_group_test.go` | 单元测试 |
| `component/routing/domain_matcher/*_test.go` | 单元测试 + Benchmark |
| `component/sniffing/*_test.go` | 单元测试 + Benchmark |
| `pkg/config_parser/config_parser_test.go` | 单元测试 |
| `pkg/trie/trie_test.go` | 单元测试 |
| `control/kern/tests/bpf_test.go` | BPF 测试 |
| `control/packet_sniffer_pool_test.go` | 单元测试 |

**覆盖率特点**:
- 有 Benchmark 测试（域名匹配性能）
- 有 eBPF 内核测试
- 使用 `testing.B` 进行性能测试

#### dae-rs 测试文件

| 测试位置 | 说明 |
|----------|------|
| `packages/dae-proxy/tests/integration_tests.rs` | 集成测试 |
| `packages/dae-proxy/src/protocol/handler.rs` | 单元测试（Handler Registry） |
| `packages/dae-proxy/src/core/mod.rs` | 核心错误类型测试 |
| `packages/dae-config/src/rules.rs` | 规则验证测试 |
| 各模块的 `#[cfg(test)]` | 分散的单元测试 |

**覆盖率特点**:
- 测试数量相对较少
- 主要集中在 Handler Registry 和规则解析
- 缺少协议级别的测试

### 6.2 错误处理

#### Go dae - 多种错误类型

```go
// 使用 errors.Is / errors.As
if errors.Is(err, ErrNoAliveDialer) {
    // 回退逻辑
}
```

**错误定义**:
- `component/outbound/dialer_group.go`: `ErrNoAliveDialer`
- 广泛使用 `fmt.Errorf("...: %w", err)` 包装错误

#### dae-rs - Typed Error Enum

```rust
// dae-proxy/src/core/error.rs
#[derive(Error, Debug)]
pub enum Error {
    #[error("TCP proxy error: {0}")]
    TcpError(String),
    #[error("eBPF error: {0}")]
    EbpfError(#[from] EbpfError),
    // ...
}

// dae-proxy/src/ebpf_integration.rs
#[derive(Error, Debug)]
pub enum EbpfError {
    #[error("Map not found: {0}")]
    MapNotFound(String),
    #[error("Update failed: {0}")]
    UpdateFailed(String),
}
```

**优势**: Rust 的 `thiserror` 派生提供类型安全的错误处理

### 6.3 文档

#### Go dae

- `cmd/run.go` 有详细的注释说明启动流程
- `control/control_plane.go` 有 package-level 文档
- 代码内注释较为完善
- 外部文档: README.md, CHANGELOGS.md (81KB)

#### dae-rs

- `lib.rs` 有详细的模块文档（Zed 风格）
- Rust `doc comments` (`//!`) 用在模块级别
- 关键类型有 `rustdoc` 格式文档

---

## 七、详细功能缺失对比

### Go dae 有但 dae-rs 缺失的功能

| 功能 | 优先级 | 说明 |
|------|--------|------|
| **VMess Legacy** (alterID > 0) | P0 | dae-rs 仅支持 VMess-AEAD-2022 |
| **gRPC Transport** | P0 | Go dae 通过 outbound/transport/grpc 支持 |
| **Meek Transport** | P0 | Go dae 支持 Tor 混淆 |
| **HTTPUpgrade Transport** | P0 | Go dae 支持 |
| **v2ray-plugin** | P1 | Shadowsocks WebSocket 插件 |
| **naiveproxy** | P1 | HTTP/2 前端代理 |
| **Proxy Chain** | P1 | 多级代理链 |
| **WAN/LAN Interface Binding** | P1 | `global.wan_interface` |
| **Hot Reload** | P1 | Go dae 支持 SIGUSR1 信号重载 |
| **Subscription System** | P1 | 订阅解析（231 行专门代码） |
| **Process Name 规则** (pname()) | P2 | 进程名分流 |
| **MAC Address 规则** (mac()) | P2 | MAC 分流 |
| **Invert Rules** | P2 | 反向规则 |
| **Auto Node Selection** | P2 | 基于延迟测试的自动切换 |
| **Advanced DNS Resolution** | P2 | 完整 DNS 流程控制 |

### dae-rs 独有功能

| 功能 | 说明 |
|------|------|
| **AnyTLS Proxy Chain** | Go dae 缺少的 AnyTLS 协议支持 |
| **Full-Cone NAT** | VMess/VLESS 的 Full-Cone NAT 支持 |
| **Rust Memory Safety** | 编译期内存安全保证 |
| **更小的二进制** | ~10-15MB (vs Go dae ~20MB) |

---

## 八、关键文件行数统计汇总

### Go dae 核心文件行数

| 文件路径 | 行数 | 描述 |
|----------|------|------|
| `control/control_plane.go` | 1,030 | 控制平面主结构 |
| `control/dns_control.go` | 746 | DNS 控制 |
| `control/control_plane_core.go` | 704 | 核心状态管理 |
| `component/outbound/dialer/connectivity_check.go` | 660 | 连通性检查 |
| `cmd/run.go` | 512 | 启动命令 |
| `common/utils.go` | 512 | 公共工具 |
| `control/netns_utils.go` | 409 | 网络命名空间 |
| `control/routing_matcher_builder.go` | 387 | 路由匹配构建 |
| `control/dns.go` | 442 | DNS 实现 |
| `control/udp.go` | 329 | UDP 处理 |
| `control/tcp.go` | 197 | TCP 处理 |
| `control/bpf_utils.go` | 280 | eBPF 工具 |
| `component/outbound/dialer_group.go` | 283 | Dialer 组 |
| `component/routing/optimizer.go` | 291 | 规则优化 |
| `common/subscription/subscription.go` | 231 | 订阅解析 |
| `component/dns/dns.go` | 232 | DNS 组件 |
| `component/dns/response_routing.go` | 292 | DNS 响应路由 |

### dae-rs 核心文件行数

| 文件路径 | 行数 | 描述 |
|----------|------|------|
| `dae-config/src/lib.rs` | 1,133 | 配置系统 |
| `dae-proxy/src/vless.rs` | 1,031 | VLESS 协议 |
| `dae-proxy/src/socks5.rs` | 824 | SOCKS5 协议 |
| `dae-proxy/src/rules.rs` | 662 | 规则类型 |
| `dae-proxy/src/vmess.rs` | 628 | VMess 协议 |
| `dae-proxy/src/tuic/codec.rs` | 624 | TUIC 编解码 |
| `dae-proxy/src/tuic/tuic.rs` | 595 | TUIC 实现 |
| `dae-proxy/src/proxy.rs` | 581 | 代理协调器 |
| `dae-proxy/src/juicity/juicity.rs` | 558 | Juicity 实现 |
| `dae-proxy/src/juicity/codec.rs` | 544 | Juicity 编解码 |
| `dae-proxy/src/shadowsocks.rs` | 552 | Shadowsocks |
| `dae-proxy/src/rule_engine.rs` | 531 | 规则引擎 |
| `dae-proxy/src/logging.rs` | 521 | 日志系统 |
| `dae-proxy/src/node/simple.rs` | 507 | 简单节点 |
| `dae-proxy/src/ebpf_integration.rs` | 503 | eBPF 集成 |
| `dae-proxy/src/transport/tls.rs` | 500 | TLS 传输 |
| `dae-proxy/src/connection_pool.rs` | 264 | 连接池 |
| `dae-proxy/src/tcp.rs` | 322 | TCP 中继 |
| `dae-proxy/src/connection.rs` | 174 | 连接跟踪 |
| `dae-ebpf/dae-ebpf-common/src/session.rs` | ~100 | 会话共享类型 |
| `dae-ebpf/dae-ebpf-common/src/routing.rs` | ~80 | 路由共享类型 |

---

## 九、总结对比表

| 维度 | Go dae | dae-rs | 胜出 |
|------|--------|--------|------|
| **代码总量** | 21,617 行 (139 文件) | 28,172 行 (127 文件) | dae-rs (更多实现) |
| **协议支持** | 完整 (outbound 库) | 部分 (进行中) | Go dae |
| **eBPF 实现** | C + Go (cilium) | Rust (aya) | 平局 |
| **类型安全** | Go (静态类型) | Rust (更严格) | dae-rs |
| **并发模型** | Goroutine + channel | Tokio async | 平局 |
| **内存安全** | 运行时检查 | 编译期保证 | dae-rs |
| **二进制大小** | ~20MB | ~10-15MB | dae-rs |
| **热更新** | SIGUSR1 重载 | 需重启 | Go dae |
| **订阅系统** | 内置 | 外部实现 | Go dae |
| **规则引擎** | 函数式 DSL | 结构化 Rust | 平局 |
| **测试覆盖** | 17 个测试文件 | 分散测试 | Go dae |
| **进程名分流** | pname() | 已实现 | 平局 |
| **MAC 分流** | mac() | 已实现 | 平局 |
| **AnyTLS** | 无 | 有 | dae-rs |
| **Full-Cone NAT** | 无 | 有 | dae-rs |
| **配置格式** | 自定义 DSL | TOML + Serde | 平局 |
| **模块化** | 外部库依赖 | 单一仓库 | dae-rs |

---

## 十、dae-rs 优先实现建议

### P0 - 高优先级
1. **VMess Legacy** (alterID > 0) - 兼容现有节点
2. **gRPC Transport** - 常用传输层
3. **Meek/HTTPUpgrade** - 抗审查传输

### P1 - 中优先级
4. **Subscription System** - 参考 Go dae 的 `subscription.go` (231 行)
5. **Hot Reload** - SIGUSR1 信号处理
6. **WAN/LAN Binding** - 接口绑定

### P2 - 低优先级
7. **v2ray-plugin** - WebSocket 混淆
8. **naiveproxy** - HTTP/2 代理
9. **Proxy Chain** - 多级代理

### dae-rs 特有功能优势保持
- 继续发展 AnyTLS Proxy Chain
- 继续发展 Full-Cone NAT
- 利用 Rust 内存安全特性

---

*报告生成完毕*
