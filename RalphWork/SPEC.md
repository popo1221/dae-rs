# dae-rs 模块拆分规格文档

## 1. 背景与目标

### 当前状态
dae-rs 项目（特别是 dae-proxy crate）存在以下问题：
- 28,967 行代码集中在 dae-proxy
- 超大文件难以维护 (ebpf_integration 1530行, vless 872行)
- 所有协议编译进单个库，无可选特性
- 模块间耦合紧密，难以独立测试

### 重构目标
1. **特性开关**: 将协议处理器、传输层、规则引擎变为可选 features
2. **模块拆分**: 将超大模块拆分为独立子模块
3. **函数提取**: 巨型函数拆分为可测试的小函数
4. **依赖解耦**: 减少循环依赖，建立清晰层次

---

## 2. 现有模块分析

### 2.1 dae-proxy 模块结构

| 模块 | 行数 | 职责 | 依赖 |
|------|------|------|------|
| core/ | ~200 | Context, Error, Result | 无 |
| config/ | ~500 | 配置与热重载 | core |
| metrics/ | ~800 | Prometheus 指标 | core |
| logging/ | ~300 | 日志服务 | core |
| tracking/ | ~1300 | 追踪存储 | core, config |
| proxy/ | ~400 | 代理协调器 | core, connection |
| connection/ | ~500 | 连接状态管理 | core |
| connection_pool/ | ~300 | 连接池 | connection |
| tcp/ | ~400 | TCP 代理 | proxy |
| udp/ | ~400 | UDP 代理 | proxy |
| protocol/ | ~600 | 协议抽象 | core |
| socks5/ | ~400 | SOCKS5 实现 | protocol |
| vless/ | ~900 | VLESS 实现 | protocol, transport |
| vmess/ | ~700 | VMess 实现 | protocol, transport |
| trojan/ | ~750 | Trojan 实现 | protocol, transport |
| shadowsocks/ | ~600 | SS/SSR 实现 | protocol |
| transport/ | ~2000 | 传输层 (ws/tls/grpc/h2) | core |
| hysteria2/ | ~800 | Hysteria2 协议 | transport, quinn |
| juicity/ | ~1100 | Juicity 协议 | transport, quinn |
| tuic/ | ~1250 | TUIC 协议 | transport, quinn |
| dns/ | ~500 | DNS 处理 | rule-engine |
| nat/ | ~400 | NAT 穿透 | core |
| mac/ | ~800 | MAC 规则 | core |
| process/ | ~400 | 进程规则 | core |
| tun/ | ~450 | TUN 接口 | core, dns |
| ebpf_integration/ | ~1530 | eBPF 集成 | core |
| ebpf_check/ | ~200 | eBPF 检查 | core |

### 2.2 超大文件分析

| 文件 | 行数 | 问题 |
|------|------|------|
| ebpf_integration/mod.rs | 1530 | 功能过多，需要拆分 |
| vless/handler.rs | 872 | 巨型函数，需要提取 |
| tuic/tuic.rs | 595 | 协议实现过大 |
| tuic/codec.rs | 624 | 编解码器独立 |
| hysteria2/hysteria2.rs | 438 | 协议逻辑 |
| hysteria2/quic.rs | 367 | QUIC 传输 |
| transport/httpupgrade.rs | 499 | HTTP Upgrade 传输 |
| shadowsocks/ssr.rs | 555 | SSR 协议 |
| node/simple.rs | 507 | 简单节点实现 |
| node/hash.rs | 509 | 哈希负载均衡 |

---

## 3. 重构方案

### 3.1 Feature 拆分方案

#### 方案 A: 协议级别拆分
```toml
[features]
default = ["protocol-core", "tcp", "udp", "socks5"]

# Core
protocol-core = []
tcp = ["protocol-core"]
udp = ["protocol-core"]

# Protocols (mutually exclusive or combinable)
socks5 = ["protocol-core"]
vless = ["protocol-core", "transport-tls"]
vmess = ["protocol-core", "transport-tls"]
trojan = ["protocol-core", "transport-tls"]
shadowsocks = ["protocol-core"]
hysteria2 = ["protocol-core", "transport-quic"]
juicity = ["protocol-core", "transport-quic"]
tuic = ["protocol-core", "transport-quic"]

# Transport
transport-tls = ["core"]
transport-ws = ["core"]
transport-grpc = ["core"]
transport-quic = ["core", "quinn"]

# Rule engines
rule-engine = []
dns = ["rule-engine"]
nat = ["core"]
mac-rule = ["core"]
process-rule = ["core"]

# Observability
metrics = []
logging = []
tracking = []

# eBPF
ebpf = []
```

#### 方案 B: 层次化 Features
```
dae-proxy/
├── features/
│   ├── transport-ws
│   ├── transport-tls  
│   ├── transport-grpc
│   ├── protocol-socks5
│   ├── protocol-vless
│   ├── protocol-vmess
│   ├── protocol-trojan
│   ├── protocol-shadowsocks
│   ├── rule-engine
│   └── ebpf
```

### 3.2 模块拆分方案

#### ebpf_integration/ 拆分
```
ebpf_integration/
├── mod.rs          # 主入口，保留公共类型
├── maps.rs         # eBPF Map 操作
├── session.rs      # Session 管理
├── routing.rs      # 路由决策
├── stats.rs        # 统计收集
└── diagnostics.rs  # 诊断功能 (已存在)
```

#### node/ 拆分
```
node/
├── mod.rs          # Node trait 和公共 API
├── simple.rs       # 简单节点 (可提取到 feature)
├── hash.rs         # 哈希负载均衡
├── store.rs        # 节点存储抽象
├── selector.rs     # 选择器策略
├── manager.rs      # 节点管理器
├── capability.rs   # 节点能力
└── health.rs       # 健康检查
```

#### protocol/ 拆分
```
protocol/
├── mod.rs          # ProtocolRegistry, ProtocolType
├── unified_handler.rs  # 统一 Handler 接口
├── handler.rs       # Handler Trait 定义
├── simple_handler.rs   # 简单处理器
├── relay.rs         #  relay 逻辑
└── handlers/        # 协议处理器子模块
    ├── mod.rs
    ├── socks5.rs
    ├── vless.rs
    ├── vmess.rs
    ├── trojan.rs
    └── shadowsocks.rs
```

### 3.3 函数提取方案

#### vless/handler.rs (872行)
提取为:
- `vless/handler/auth.rs` - 认证逻辑 (~150行)
- `vless/handler/handshake.rs` - 握手处理 (~200行)
- `vless/handler/relay.rs` - 数据中继 (~250行)
- `vless/handler/mod.rs` - 模块组装 (~272行保留)

#### ebpf_integration/mod.rs (1530行)
提取为:
- `ebpf_integration/maps.rs` - Map 操作 (~400行)
- `ebpf_integration/session.rs` - Session 管理 (~350行)
- `ebpf_integration/routing.rs` - 路由 (~300行)
- `ebpf_integration/mod.rs` - 入口和类型 (~480行)

---

## 4. 依赖层次设计

### 推荐层次 (从底到高)

```
Layer 0: core (无依赖)
    ↓
Layer 1: config, metrics, logging, tracking
    ↓
Layer 2: tcp, udp, connection, connection_pool
    ↓
Layer 3: protocol (抽象)
    ↓
Layer 4: transport (ws, tls, grpc, quic)
    ↓
Layer 5: protocol implementations (socks5, vless, vmess, trojan, shadowsocks)
    ↓
Layer 6: proxy, protocol_dispatcher, proxy_chain
    ↓
Layer 7: tun, ebpf_integration
```

### 禁止依赖规则
- 上层可以依赖下层
- 下层禁止依赖上层
- 同层之间尽量避免直接依赖， 通过 trait 解耦

---

## 5. 验收标准

### Feature 开关
- [ ] `cargo build --no-default-features` 成功
- [ ] `cargo build --features vless` 成功
- [ ] `cargo build --features hysteria2` 成功
- [ ] 组合 features 如 `vless,vmess,trojan` 成功

### 模块拆分
- [ ] ebpf_integration 拆分为 4+ 子模块
- [ ] node 拆分为独立子模块
- [ ] protocol 拆分为 handlers/ 子目录

### 函数粒度
- [ ] 无单个文件超过 800 行
- [ ] 无单个函数超过 200 行
- [ ] 每个提取的函数有单元测试

### 编译性能
- [ ] 增量编译时间减少 >30%
- [ ] 改动单个协议不影响其他协议

### 测试覆盖
- [ ] 核心层测试覆盖率 >80%
- [ ] 协议层有集成测试

---

## 6. 实施计划

### Phase 1: 分析与设计 (Iteration 1-2)
1. 完成依赖关系图
2. 设计 feature 结构
3. 设计模块拆分方案
4. 定义验收测试

### Phase 2: 基础设施拆分 (Iteration 3-5)
1. 拆分 metrics 为独立 feature
2. 拆分 logging 为独立 feature
3. 拆分 tracking 为独立 feature
4. 验证编译和测试

### Phase 3: 传输层拆分 (Iteration 6-8)
1. 提取 transport 为独立模块
2. 按传输类型拆分为 sub-features
3. 验证协议兼容性

### Phase 4: 协议层拆分 (Iteration 9-14)
1. 拆分 protocol 抽象层
2. 提取 vless handler 函数
3. 提取 vmess handler 函数
4. 提取 trojan handler 函数
5. 提取 shadowsocks handler 函数

### Phase 5: eBPF 拆分 (Iteration 15-17)
1. 拆分 ebpf_integration 模块
2. 建立诊断子模块
3. 验证 eBPF 功能

---

## 7. 风险与缓解

| 风险 | 影响 | 缓解策略 |
|------|------|----------|
| 循环依赖 | 编译失败 | 先分析依赖图，按层次重构 |
| Feature 组合爆炸 | 测试覆盖不足 | 选择主要组合进行 CI 测试 |
| 超大文件历史 | 代码丢失 | 保持 git 历史，拆分同时提交 |
| 协议兼容性 | 功能 regression | 完整集成测试套件 |

