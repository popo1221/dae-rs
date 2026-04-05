# dae-rs 重构方案

> 📅 制定时间：2026-04-04
> 📂 来源：dae-rs 全量代码学习（9/144 模块已完成）
> 🎯 目标：将 dae-rs 从 HashMap stub 重构为真实 eBPF 集成

---

## 一、现状分析

### 1.1 核心问题：eBPF stub 必须重构

| 文件 | 行数 | 问题 |
|------|------|------|
| `ebpf_integration.rs` | 1290 | ⚠️ **HashMap 模拟，非真实 eBPF** |
| `vless.rs` | 1526 | 待学习 |
| `vmess.rs` | 1229 | 待学习 |
| `tun.rs` | 1414 | 待学习 |
| `proxy.rs` | 742 | 核心调度，架构清晰 |

### 1.2 已确认架构（基于学习笔记）

```
dae-rs 架构（非 eBPF 加速）
├── proxy.rs         — 总调度（broadcast channel shutdown、双检锁）
├── connection_pool   — TCP 连接池（CompactIp 编码、HashMap retain）
├── node/selector    — 6 种选择策略
├── tcp.rs           — 全双工 tokio::io::split relay
├── udp.rs           — NAT session + 30s 超时清理
├── rules.rs         — 域名/IP 规则引擎
├── socks5.rs        — RFC 1928 协议实现
├── trojan_handler   — HTTPS 伪装协议
└── ebpf_integration — ⚠️ HashMap stub（需要替换为 aya crate）
```

### 1.3 go-dae vs dae-rs 架构差异

| 维度 | go-dae | dae-rs |
|------|--------|--------|
| eBPF | 真实（cilium/ebpf） | HashMap stub |
| 内核加速 | TC attach | 无 |
| 路由匹配 | eBPF Map + 用户 Trie | 用户空间规则引擎 |
| DNS 缓存 | 双层（内存+eBPF Map） | 单层内存 |
| 性能 | 内核级加速 | 用户空间代理 |

---

## 二、重构目标

### 2.1 短期目标（Phase 1-2）
1. ✅ **eBPF stub → aya crate 真实 eBPF**
2. ✅ 补全剩余模块学习（vless/vmess/tun）
3. ✅ 统一错误处理（thiserror 推广）
4. ✅ 完善测试覆盖率

### 2.2 中期目标（Phase 3）
1. ✅ 实现 eBPF 内核路由匹配（替代用户空间规则引擎）
2. ✅ DNS 双层缓存（内存 + eBPF Map）
3. ✅ 性能优化（减少 syscall、零拷贝）

### 2.3 长期目标（Phase 4）
1. ✅ 支持更多 eBPF map 类型（LpmTrie、Queue、Stack）
2. ✅ 多网卡绑定（TC + XDP）
3. ✅ 内核版本检测与降级

---

## 三、重构任务分解

### 🔴 P0 - 必须重构（阻塞核心功能）

#### T1：eBPF 集成重构
**文件**：`ebpf_integration.rs`（1290行）

**现状问题**：
```rust
// 当前：HashMap 模拟
HashMap<ConnectionKey, SessionEntry>  // stub，非真实 BPF Map
HashMap<u32, RoutingEntry>
HashMap<u32, StatsEntry>
```

**重构方案**：
```rust
// 目标：使用 aya crate 真实 eBPF Map
use aya::maps::HashMap;
use aya::programs::Xdp;

// 1. 替换 HashMap 为 aya::maps::HashMap
// 2. 替换模拟程序为真实 XDP/TC 程序
// 3. 实现 BPF ring buffer 替代 Channel
```

**依赖**：
- `aya` crate
- `aya-ebpf` crate
- 内核 5.8+（分层检查）

**工作量**：⭐⭐⭐⭐⭐（最大）

---

#### T2：协议处理器模块化
**文件**：
- `socks5.rs`（926行）
- `trojan_handler.rs`（693行）
- `shadowsocks.rs`（633行）

**重构方案**：
```rust
// 统一协议处理器接口
trait ProxyHandler: Send + Sync {
    async fn handle(&self, stream: &mut TcpStream) -> Result<(), Error>;
    fn name(&self) -> &str;
}

// 协议注册表
struct ProtocolRegistry {
    handlers: HashMap<String, Arc<dyn ProxyHandler>>,
}

impl ProtocolRegistry {
    fn register<H: ProxyHandler>(&mut self, name: &str, handler: H) {
        self.handlers.insert(name.to_string(), Arc::new(handler));
    }
}
```

---

### 🟠 P1 - 重要重构（提升可维护性）

#### T3：连接池重构
**文件**：`connection_pool.rs`（786行）

**现状问题**：
- `get_or_create` 双检锁有优化空间
- `HashMap` 替换为 `DashMap` 或 `RwLock<HashMap>`
- 缺少连接生命周期钩子

**重构方案**：
```rust
// 1. 引入 connection-lifecycle 事件
enum ConnectionEvent {
    Created(ConnectionKey),
    Reused(ConnectionKey),
    Closed(ConnectionKey),
}

// 2. 添加连接健康检查
async fn health_check(&self, key: &ConnectionKey) -> bool;

// 3. 优化清理策略
struct PoolConfig {
    max_idle_time: Duration,
    max_lifetime: Duration,
    min_idle: usize,
}
```

---

#### T4：规则引擎重构
**文件**：`rules.rs` + `rule_engine.rs`

**现状问题**：
- 域名匹配效率低（线性扫描）
- 缺少规则优先级
- 不支持规则组

**重构方案**：
```rust
// 1. 引入规则优先级
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum RulePriority {
    Highest = 0,
    High = 1,
    Normal = 2,
    Low = 3,
}

// 2. 域名匹配优化（参考 go-dae 的 DomainBitmap）
struct DomainBitmapMatcher {
    bitmap: Vec<u32>,  // 位图代替线性扫描
    domain_sets: HashMap<u32, DomainSet>,
}

// 3. 支持规则组和嵌套
struct RuleGroup {
    name: String,
    rules: Vec<Rule>,
    policy: GroupPolicy,  // FirstMatch / AllMatch
}
```

---

### 🟡 P2 - 优化重构（提升性能）

#### T5：UDP Session 管理优化
**文件**：`udp.rs`（410行）

**现状问题**：
- 30s 超时固定
- 无 UDP fragment 处理
- NAT 表无持久化

**重构方案**：
```rust
// 1. 动态超时
struct UdpSessionConfig {
    default_timeout: Duration,  // 30s
    dns_timeout: Duration,     // 17s (RFC 5452)
    large_timeout: Duration,   // 5min (QUIC)
}

// 2. Fragment 缓存
struct FragmentCache {
    cache: HashMap<(ConnectionKey, u16), Fragment>,
    max_size: usize,
}
```

---

#### T6：TUN 设备优化
**文件**：`tun.rs`（1414行）

**重构方案**：
```rust
// 1. 引入PacketHandle抽象
trait PacketHandle: Send + Sync {
    fn parse_ip_header(&self) -> IpHeader;
    fn routing_lookup(&self) -> RouteResult;
    fn forward_to_tcp(&self, stream: TcpStream);
    fn forward_to_udp(&self, session: UdpSession);
}

// 2. 批量处理优化
async fn process_batch(&self, packets: Vec<Packet>) -> Vec<Packet>;
```

---

## 四、重构实施计划

### Phase 1：基础设施（P0）
| 任务 | 文件 | 优先级 | 工时 |
|------|------|--------|------|
| eBPF stub → aya | `ebpf_integration.rs` | 🔴 P0 | 2-3周 |
| 错误处理统一 | 全局 | 🟠 P1 | 3天 |

### Phase 2：协议层（P0）
| 任务 | 文件 | 优先级 | 工时 |
|------|------|--------|------|
| 协议接口抽象 | `protocol_dispatcher.rs` | 🔴 P0 | 1周 |
| VLESS 实现 | `vless.rs` | 🔴 P0 | 1周 |
| VMess 实现 | `vmess.rs` | 🔴 P0 | 1周 |
| Trojan 完善 | `trojan_handler.rs` | 🟠 P1 | 3天 |

### Phase 3：核心优化（P1）
| 任务 | 文件 | 优先级 | 工时 |
|------|------|--------|------|
| 连接池重构 | `connection_pool.rs` | 🟠 P1 | 1周 |
| 规则引擎优化 | `rules.rs` | 🟠 P1 | 1周 |
| TUN 设备优化 | `tun.rs` | 🟠 P1 | 1周 |

### Phase 4：测试与部署（P2）
| 任务 | 优先级 | 工时 |
|------|--------|------|
| 单元测试覆盖 >80% | 🟡 P2 | 2周 |
| Integration 测试 | 🟡 P2 | 1周 |
| 性能基准测试 | 🟡 P2 | 1周 |

---

## 五、技术债务清单

### 5.1 高优先级
- [ ] `ebpf_integration.rs` 非真实 eBPF（阻塞生产部署）
- [ ] `vless.rs` + `vmess.rs` 未学习（协议覆盖不完整）
- [ ] 缺少统一错误类型（`thiserror` 未推广）

### 5.2 中优先级
- [ ] `connection_pool.rs` 连接复用率统计缺失
- [ ] `rules.rs` 域名匹配 O(n) → O(1) bitmap
- [ ] `udp.rs` 固定 30s 超时不合理

### 5.3 低优先级
- [ ] 日志格式不统一（`tracing` vs `log`）
- [ ] 缺少 metrics 暴露（Prometheus）
- [ ] `tun.rs` 批量处理缺失

---

## 六、重构风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| eBPF 复杂度 | 高 | 分阶段，先 stub 再真实 |
| 协议兼容性 | 高 | 保留旧接口，渐进迁移 |
| 性能退化 | 中 | 每次 PR 跑基准测试 |
| 测试覆盖不足 | 中 | 先行补充测试，再重构 |

---

## 七、推荐实施路径

```
Week 1-2:   学习 vless.rs + vmess.rs + tun.rs（补全代码理解）
Week 3-4:   eBPF 重构（aya crate 集成）
Week 5-6:   协议接口抽象 + VLESS/VMess 实现
Week 7-8:   连接池 + 规则引擎优化
Week 9-10:  TUN 优化 + 测试补充
Week 11-12: 集成测试 + 性能调优
```

---

## 八、结论

dae-rs 当前是**纯用户空间代理**，无法利用 eBPF 内核加速。核心重构方向：

1. **eBPF stub → 真实 aya crate**（最重要）
2. **协议处理器统一接口**（提升可维护性）
3. **规则引擎 bitmap 优化**（性能提升）
4. **补全 VLESS/VMess 协议**（功能完整）

参考 go-dae 的 eBPF 架构设计，dae-rs 可以逐步迁移到真实 eBPF，同时保持用户空间Fallback。
