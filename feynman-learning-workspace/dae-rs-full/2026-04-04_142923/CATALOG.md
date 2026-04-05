# 📚 dae-rs 全量代码学习编目

> 📅 学习日期：2026-04-04
> 📂 来源：/root/Projects/dae-rs（完整仓库）
> 🏷️ 状态：进行中（9/144 已学习）

---

## 学习统计

- 总扫描：144 个 Rust 代码文件
- 已学习：9 个
- 平均 Value_Score：~8/10
- 剩余：~135 个文件

---

## 已学习笔记索引

### 🔴 核心基础设施（⭐⭐⭐）

| # | 模块 | 文件 | 评分 | 摘要 |
|---|------|------|------|------|
| 001 | 代理核心编排器 | `proxy.rs` | 9/10 | 整个系统的"总调度室"，管理所有协议服务器的启动/关闭/生命周期 |
| 002 | 连接复用池 | `connection_pool.rs` | 9/10 | "玩具共享柜"——TCP连接复用，双检锁减少竞争，IPv4/IPv6双支持 |
| 003 | 节点选择策略 | `node/selector.rs` | 8/10 | 6种流量分配规则引擎：Latency/Random/RR/Direct/ConsistentHash/StickySession |

### 🟠 网络层（⭐⭐⭐）

| # | 模块 | 文件 | 评分 | 摘要 |
|---|------|------|------|------|
| 004 | TCP 透明代理 | `tcp.rs` | 8/10 | 电话接线员——全双工双向转发，超时控制，session 状态跟踪 |
| 005 | UDP 代理与NAT | `udp.rs` | 7/10 | 快递柜管理员——无连接UDP的会话化管理，tokio::select多路复用 |
| 006 | 规则引擎 | `rules.rs` + `rule_engine.rs` | 8/10 | 交通警察——域名/IP/GeoIP/进程等多维度规则匹配，Pass/Proxy/Drop 决策 |
| 007 | eBPF Maps封装 | `ebpf_integration.rs` | 7/10 | ⚠️ Stub实现（非真实eBPF）——HashMap模拟会话/路由/统计Map |
| 008 | SOCKS5 协议 | `socks5.rs` | 8/10 | RFC 1928实现——中介协议，支持IPv4/IPv6/域名三种地址格式 |
| 009 | Trojan 处理器 | `trojan_protocol/handler.rs` | 8/10 | 伪装HTTPS的代理协议——TLS隧道内嵌代理协议，多后端RoundRobin容灾 |

---

## 架构分层视图

```
┌─────────────────────────────────────────────────────────┐
│  dae-cli (入口)                                        │
└──────────────┬────────────────────────────────────────┘
               │ Proxy::new(config) + start()
               ▼
┌─────────────────────────────────────────────────────────┐
│  proxy.rs — 总调度室（Proxy）                          │
│  ├─ TcpProxy ──────────────────────────────────────► tcp.rs (TCP中继)  │
│  ├─ UdpProxy ──────────────────────────────────────► udp.rs (UDP会话NAT) │
│  ├─ RuleEngine ────────────────────────────────────► rules.rs (规则匹配)  │
│  ├─ ConnectionPool ───────────────────────────────► connection_pool.rs    │
│  └─ EbpfMaps (stub) ───────────────────────────► ebpf_integration.rs   │
│                                                         │
│  各协议服务器：                                         │
│  ├─ VlessServer ──────────────────────────────────► vless.rs (未学习)    │
│  ├─ VmessServer ─────────────────────────────────► vmess.rs (未学习)    │
│  ├─ TrojanServer ────────────────────────────────► trojan_protocol/     │
│  ├─ ShadowsocksServer ───────────────────────────► shadowsocks.rs (未学习)│
│  └─ CombinedProxyServer (SOCKS5/HTTP) ───────► socks5.rs              │
│                                                         │
│  节点管理：                                             │
│  ├─ NodeManager ─────────────────────────────────► node/manager.rs (未学习)│
│  ├─ DefaultNodeSelector ────────────────────────► node/selector.rs ✅     │
│  └─ Fnv1aHasher / SipHasher ───────────────► node/hash.rs (已学)       │
└─────────────────────────────────────────────────────────┘
```

---

## 待学习模块（按优先级）

### 🔴 高优先级
- `vless.rs`（1526行）— VLESS 协议实现
- `vmess.rs`（1229行）— VMess 协议实现
- `tun.rs`（1414行）— TUN 网络接口

### 🟠 中优先级
- `shadowsocks.rs`（633行）— Shadowsocks 协议
- `node/manager.rs`（507行）— 节点生命周期管理
- `protocol_dispatcher.rs`（372行）— 协议分发协调器

### 🟡 低优先级（测试/工具）
- `dae-api/src/`（API 模块）
- `dae-config/src/`（配置解析）
- `dae-ebpf/`（eBPF 内核程序）

---

## 跨模块关键设计

### 连接复用链
```
client → tcp.rs handle_client()
  → connection_pool.get_or_create(key)  // 查HashMap，有则复用，无则新建
    → connection_relay(client, remote)     // 双向中继
    → cleanup_expired()                   // 每10秒清理超时连接
```

### 节点选择链（与hash.rs关联）
```
ConnectionFingerprint.hash()  // FNV-1a 算出 u64
  → hash % node_count = 节点索引
    → ConsistentHashing/StickySession/UrlHash
      → select_consistent_hash/sticky_session()
```

### eBPF stub（重要澄清）
```
真实 eBPF 需要：aya crate + kernel 5.8+
当前是 HashMap stub，用于开发测试
```
