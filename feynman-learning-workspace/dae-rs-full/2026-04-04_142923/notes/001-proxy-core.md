# 💻 费曼代码笔记：proxy.rs — dae-rs 代理核心编排器

> 📅 学习日期：2026-04-04
> 📂 来源：packages/dae-proxy/src/proxy.rs
> 🏷️ 代码语言：Rust
> ⭐ Value_Score：9/10

## 一句话总结（10岁版本）

> 这个文件是整个代理系统的"总调度室"——它知道有哪些服务在跑（VLESS、VMess、Shadowsocks等），负责启动它们、在它们崩溃时关掉它们。

---

## 简化法则自检

- [ ] 口语化讲解区全篇没有专业术语吗？
- [ ] 每个概念都有生活类比吗？
- [ ] 外婆能听懂吗？
- [ ] 数据流每个环节都能说清吗？
- [ ] 设计取舍（为什么这样做）讲清楚了吗？
- [ ] 副作用都列清楚了吗？

---

## 口语化讲解区（外婆版）

想象一个大型游乐场（这就是 dae-rs 代理系统）。

**`Proxy` 就是游乐场的"总管理员"。**

游乐场里有好多游戏机（服务）：
- 有的游戏机叫 VLESS
- 有的叫 VMess
- 有的叫 Shadowsocks
- 还有 SOCKS5、HTTP 代理

每台游戏机要不要开、开的地址是多少（哪个端口），都写在"配置表"里（`ProxyConfig`）。

总管理员在启动时做了三件事：
1. **初始化游戏机**：按配置把每台游戏机装好、接上电
2. **同时开所有游戏**：VLESS、VMess、TCP 代理、UDP 代理一起跑
3. **等着收工信号**：收到 Ctrl+C 或关闭命令时，一起把所有游戏机都关掉

**`start()` 方法** 就是游乐场开门：
- 先把门锁打开（`*running = true`）
- 然后同时启动所有游戏（`tokio::spawn`）
- 然后就坐在门口等着（`recv().await`）
- 收到关门信号了，就把所有游戏机一起关掉

**`shutdown()` 关机时**：先把总开关拉掉（`*running = false`），然后把每台游戏机的电源线拔掉（`handle.abort()`），最后报告"关门完毕"。

---

## 专业结构区（同行版）

### 函数签名

#### 输入参数

| 参数名 | 数据类型 | 业务含义 | 可选？默认值 |
|--------|---------|---------|------------|
| `config: ProxyConfig` | struct | 整个代理系统的配置（各协议开关、监听地址、超时等） | 必填 |
| `tcp: TcpProxyConfig` | struct | TCP 代理监听地址和超时配置 | 必填 |
| `udp: UdpProxyConfig` | struct | UDP 代理配置 | 必填 |
| `ebpf: EbpfConfig` | struct | eBPF 会话映射大小等配置 | 必填 |
| `pool: ConnectionPoolConfig` | struct | 连接池超时配置 | 必填 |
| `vless_listen` | `Option<SocketAddr>` | VLESS 监听地址 | 可选，None=不启动 |
| `vmess_listen` | `Option<SocketAddr>` | VMess 监听地址 | 可选，None=不启动 |
| `trojan_listen` | `Option<SocketAddr>` | Trojan 监听地址 | 可选，None=不启动 |

#### 返回值

| 情况 | 返回类型 | 业务含义 |
|------|---------|---------|
| 正常 | `std::io::Result<Self>` | 初始化成功 |
| 配置错误 | `Err(ProxyError::ConfigError)` | 参数有问题 |

#### 副作用

- 启动了多个 tokio 异步任务（各协议服务器）
- 每 10 秒执行一次连接池清理（定时任务）
- 可选：启动 Prometheus/JSON API HTTP 服务器

---

### 宏观执行流程

**初始化（`Proxy::new()`）**：
1. 创建 in-memory eBPF Maps（会话映射、路由映射、统计映射）
2. 初始化连接池（设置超时参数）
3. 创建 TCP 代理实例
4. 创建 UDP 代理实例
5. 按配置创建各协议服务器（VLESS/VMess/Trojan/Shadowsocks/SOCKS5/HTTP）
6. 初始化 Tracking Store（如果开启）

**启动（`start()`）**：
1. 检查是否已在运行，是则直接返回
2. 标记 running=true
3. 同时 spawn 所有服务任务（TCP、UDP、连接池清理、各协议服务器）
4. 等待 shutdown 信号（broadcast channel）
5. 收到信号后：running=false → close_all() → abort 所有任务

**关闭（`stop()`）**：
发送 shutdown broadcast 信号

---

### 关键逻辑块

- **条件分支 if config.xxx.is_none()**：如果某个协议没配置，就跳过创建该服务器——按需启动
- **broadcast channel shutdown**：所有任务共享同一个 shutdown 信号，任何一个任务收到都会触发统一关闭
- **handle.abort()**：强制中止异步任务，等效于"拔电源"
- **pool.cleanup_expired()**：每 10 秒轮询清理过期连接，防止连接泄漏

---

### 核心数据结构

| 结构 | 字段 | 作用 | 类比 |
|------|------|------|------|
| `Proxy` | `tcp_proxy`, `udp_proxy` | 核心转发代理 | 游乐场的两条主干道（TCP是大堂走道，UDP是快递通道） |
| `Proxy` | `connection_pool` | 连接复用池 | 玩具共享柜——用完的玩具不扔，放柜里下次再用 |
| `Proxy` | `session_handle/routing_handle/stats_handle` | eBPF map 句柄 | 三本账簿：谁来了（会话）、去哪（路由）、干得怎样（统计） |
| `Proxy` | `shutdown_tx: broadcast::Sender` | 广播关闭信号 | 全楼火警铃——一拉全部响 |
| `ProxyConfig` | 各种 `Option<SocketAddr>` | 各协议开关 | 游戏机的电源插座——插了才供电，不插不开机 |

---

### 依赖关系

- **内部模块**：
  - `crate::tcp::TcpProxy` — TCP 转发实现
  - `crate::udp::UdpProxy` — UDP 转发实现
  - `crate::connection_pool` — 连接复用
  - `crate::ebpf_integration::EbpfMaps` — eBPF 会话跟踪
  - `crate::vless::VlessServer` — VLESS 协议
  - `crate::vmess::VmessServer` — VMess 协议
  - `crate::trojan_protocol::TrojanServer` — Trojan 协议
  - `crate::shadowsocks::ShadowsocksServer` — Shadowsocks 协议
  - `crate::tracking::store::TrackingStore` — 流量追踪
- **外部依赖**：
  - `tokio` — 异步运行时
  - `tracing` — 结构化日志

---

### 设计意图

- **为什么用 `broadcast::Sender` 而非 `oneshot`？** — 需要同时通知所有子任务关闭，broadcast 是一对多的，而 oneshot 只能一对一
- **为什么每个协议都用 `Option<Arc<T>>`？** — 配置里写明了"要不要启用"，None=不启动，Some=启动并 wrap 成 Arc 共享
- **为什么 `running` 要用 `RwLock` 而不是 `Mutex`？** — 只关心"运行/停止"两种状态，写少读多，RwLock 允许多个读并发，性能更好
- **为什么 TCP/UDP 代理必须启动，其他协议可选？** — TCP 和 UDP 是基础设施（底层流量），各协议都是挂在它们之上的"应用层"

---

### 边界与异常

- **重复启动**：第二次调用 `start()` 会 warn 并直接返回 Ok，不会 panic
- **所有协议都关闭**：如果所有 `Option` 都是 None，程序仍然正常运行（只跑 TCP/UDP 代理）
- **Ctrl+C 时任务在运行**：`tokio::select!` 捕获 `ctrl_c`，触发 graceful shutdown
- **任务 panic**：`if let Err(e) = result` 捕获并 log，不会传染其他任务

---

## 知识盲区与补充

**盲区**：`EbpfMaps::new_in_memory()` 实际上是什么数据结构？
- **尝试**：查看 ebpf_integration.rs，但当前文件只用了 handle 包装，没深入实现
- **补充**：`EbpfMaps` 是用户空间实现（不依赖真实 eBPF），用 `HashMap` 模拟 eBPF map，支持 `session_map`（会话跟踪）、`routing_map`（路由规则）、`stats_map`（统计计数）

---

## 关键应用场景

### 🗺️ dae-rs 代理系统的"总开关"

**这段代码在系统中做什么**：
`proxy.rs` 是 dae-rs 的主入口协调器，负责根据配置决定启动哪些服务，并管理它们的生命周期（启动→运行→关闭）。

**调用链追溯**：
```
dae-cli::main()
  → Proxy::new(config)     // 初始化所有组件
  → proxy.start()         // spawn 所有服务任务
    → TcpProxy::start()    // TCP 代理监听
    → UdpProxy::start()    // UDP 代理监听
    → 各协议服务器 start() // VLESS/VMess/Trojan/Shadowsocks
    → pool.cleanup task    // 每10秒清理过期连接
  → shutdown broadcast     // 收到关闭信号后
  → connection_pool.close_all()
  → handle.abort()         // 拔掉所有任务
```

**触发的关键决策**：

| 配置项 | 值为 None | 值为 Some | 后果 |
|--------|---------|---------|------|
| `vless_listen` | VLESS 不启动 | 在指定端口启动 VLESS 服务 | 用户能否通过 VLESS 协议接入 |
| `vmess_listen` | VMess 不启动 | 在指定端口启动 VMess 服务 | 用户能否通过 VMess 协议接入 |
| `tracking.enabled` | 不启动追踪 Store | 启动并可选导出 metrics | 能否查看流量统计 |

**如果这段代码消失会怎样**：
整个 dae-rs 代理无法启动——因为所有协议服务器都不知道自己什么时候该启动、什么时候该关闭，这就是系统的"中枢神经"。

**和同类方案相比为什么这样设计**：
- **不用每个协议单独配置文件启动**：统一走 `ProxyConfig`，一个配置搞定所有开关
- **用 `broadcast` 而非手动管理每个任务**：避免关闭时漏掉某个任务

---

## 大白话总结（外婆版）

> proxy.rs 就是这个游乐场的"总调度室"。
>
> 它有一本厚厚的"开业手册"（`ProxyConfig`），手册上写着：要不要开 VLESS 游戏机（端口多少）、要不要开 VMess 游戏机、每个游戏机的超时设置是多少。
>
> 调度室在开门前（`start()`）把游戏机全部装好、接上电，然后同时启动。关门时（`stop()` / Ctrl+C），调度室一声令下，所有游戏机一起断电、游戏结束。
>
> 最妙的是：每个游戏机的电源线都连在同一个"总开关"（`shutdown_tx`）上——拉一次总开关，全部一起关，不会有的游戏机还在跑忘了关。
