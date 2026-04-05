# 💻 费曼代码笔记：ebpf_integration.rs — eBPF Maps 用户空间封装

> 📅 学习日期：2026-04-04
> 📂 来源：packages/dae-proxy/src/ebpf_integration.rs
> 🏷️ 代码语言：Rust
> ⭐ Value_Score：7/10

## 一句话总结（10岁版本）

> 这个文件是"账本管理员"——但它不是真正的 eBPF，只是用普通笔记本（HashMap）模拟了 eBPF"账本"的样子，方便开发测试用。

---

## ⚠️ 重要前提：这是 Stub，不是真实 eBPF

```rust
// 文件开头大字声明：
// **This is an in-memory stub for development/testing.**
// Real eBPF map operations require the `aya` crate and kernel BPF support.
```

dae-rs 真实使用 eBPF 时，需要用 `aya` crate 来操作 kernel BPF maps。当前实现只是 HashMap 模拟：

- `SessionMapHandle` = `HashMap<ConnectionKey, SessionEntry>`（会话跟踪）
- `RoutingMapHandle` = `HashMap<u32, RoutingEntry>`（路由规则）
- `StatsMapHandle` = `HashMap<u32, StatsEntry>`（统计计数）

---

## 口语化讲解区（外婆版）

**什么是 eBPF Maps？**

eBPF 是 Linux 内核的一个特性——可以在内核里运行小程序。但内核程序不能随便访问用户空间数据，所以需要"账本"（Map）在内核和用户空间之间共享数据。

比如：内核里运行的网络数据包分类程序，需要知道路由规则（哪些 IP 该走代理），规则存在 Map 里，内核程序和用户空间程序都能读写。

这个文件把"真正的 eBPF Map"替换成了"普通 HashMap"，所以叫 stub——是赝品，不是真货。

**为什么用 stub？**

因为真正的 eBPF 需要：
1. Linux kernel 5.8+（有些特性需要更高版本）
2. 加载 BPF 程序到内核（需要 root 权限）
3. `aya` crate 的正确绑定

开发/测试时，不想装这些条件，就用 HashMap 代替，只要 API 接口一样，代码逻辑就不用改。

---

## 专业结构区（同行版）

### 三个 Map Handle

| Handle | 底层 | Key | 用途 |
|--------|------|-----|------|
| `SessionMapHandle` | `HashMap<ConnectionKey, SessionEntry>` | ConnectionKey | 跟踪每个 TCP/UDP 连接的状态（New→Active→Closing→Closed） |
| `RoutingMapHandle` | `HashMap<u32, RoutingEntry>` | u32（路由规则ID） | IP → 路由动作（Pass/Proxy/Drop）映射 |
| `StatsMapHandle` | `HashMap<u32, StatsEntry>` | u32（统计索引） | 字节数、包数等计数器 |

### SessionEntry 状态机

```
New(0) → Active(1) → Closing(2) → Closed(3)
```

每个 TCP 连接在 session map 里有一个状态，eBPF 内核程序可以查询这个状态决定如何路由数据包。

### 真实 eBPF 替换方案

当要迁移到真实 eBPF 时，把这些：
```rust
// 当前（stub）
Arc<StdRwLock<HashMap<K, V>>>
```

替换为 aya 的对应类型：
```rust
// 真实 eBPF
aya::maps::HashMap<K, V>
aya::maps::LpmTrie<K, V>  // 用于路由规则的 Longest Prefix Match
```

---

## 关键应用场景

**系统中做什么**：
eBPF Maps 是 dae-rs 实现"内核级流量分类"的核心——在 TCP/UDP 代理和内核网络栈之间建立状态共享通道，让内核能查询连接状态和路由决策。

**没了会怎样**（如果是真实 eBPF）：
代理无法在内核层做流量分类，所有数据包必须先到用户空间再处理，绕过了内核加速，性能大幅下降。

**现在 stub 的情况下没了会怎样**：
用 HashMap 模拟，功能逻辑仍然正常，只是没有真正的内核加速——对于开发测试够用。

---

## 大白话总结（外婆版）

> 想象你要在游乐场里管交通（这就是 dae-rs 做的事）。
>
> 真正的 eBPF 方案是：在游乐场的每个路口（内核网络栈）都装一个"智能摄像头"（内核 BPF 程序），摄像头能自动看每辆车（数据包），然后查"交通规则本"（Map）决定：这辆车该走哪条路。
>
> 但"智能摄像头"和"交通规则本"都在内核里，你的控制室（用户空间程序）怎么跟它们沟通？需要一个"对讲机"（eBPF Map）——摄像头看到的车流量数据写进对讲机，你在控制室也能看到；你更新了交通规则，控制室也能同步给摄像头。
>
> 这个文件就是"对讲机的模拟器"——在开发阶段，没有真正的摄像头，就用普通笔记本（HashMap）代替，反正功能是一样的。
