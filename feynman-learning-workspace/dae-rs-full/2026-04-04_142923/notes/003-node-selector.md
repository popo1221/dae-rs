# 💻 费曼代码笔记：selector.rs — 节点选择策略引擎

> 📅 学习日期：2026-04-04
> 📂 来源：packages/dae-proxy/src/node/selector.rs
> 🏷️ 代码语言：Rust
> ⭐ Value_Score：8/10

## 一句话总结（10岁版本）

> 这个文件是游戏场的"裁判分配器"——小朋友（用户请求）来了，按不同规则（最快/随机/固定）决定去哪个游戏机（节点）玩。

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

**场景：游乐场有多个游戏机（节点），新来一批小朋友（请求），怎么分配？**

`selector.rs` 实现了 6 种分配规则，每种适合不同的场景：

| 规则 | 像什么 | 什么时候用 |
|------|--------|---------|
| `LowestLatency` | 挑离得最近的游戏机 | 要最快响应 |
| `Random` | 随机抽一个 | 简单负载均衡 |
| `RoundRobin` | 轮流来，A1→A2→A3→A1... | 公平分担 |
| `PreferDirect` | 优先找"直连"通道 | 跨境流量走专线 |
| `ConsistentHashing` | 同一个顾客永远去同一个游戏机 | 保持 session 一致 |
| `StickySession` | 同一 IP 永远去同一个游戏机 | 防止会话混乱 |

**最容易搞混的两个：ConsistentHashing vs StickySession**

- `ConsistentHashing`：哈希到的游戏机不开了 → 顺时针找下一个开的（类似环形分配）
- `StickySession`：同一 IP 优先去哈希到的那个 → 只有当那个彻底坏了，才用一致性哈希兜底

区别在于"容错策略"不同：一致性哈希是"所有人顺时针挪"，粘性会话是"我只挪一次，还不行就算了"。

---

## 专业结构区（同行版）

### 函数签名

#### 输入参数

| 参数名 | 数据类型 | 业务含义 |
|--------|---------|---------|
| `nodes: &[Arc<dyn Node>]` | 节点列表 | 所有可用节点 |
| `policy: &SelectionPolicy` | enum | 用哪种分配规则 |

#### 返回值

| 情况 | 返回类型 | 业务含义 |
|------|---------|---------|
| 正常 | `Option<Arc<dyn Node>>` | 选中的节点 |
| 无可用节点 | `None` | 所有节点都挂了 |

#### 副作用

无副作用，纯函数。

---

### 宏观执行流程

所有选择器共享同一流程：
1. `collect_available()` — 过滤出所有 `is_available() = true` 的节点（并发检查）
2. 按策略分配 — 按 policy 匹配对应方法
3. 返回 `Option<Node>`

---

### 关键逻辑块

- **双检 + 顺时针查找**：`select_consistent_hash` 先哈希取模得到索引，如果那个节点挂了，就 `idx = (idx + 1) % count` 顺时针找下一个——这是 ketama 一致性哈希的简化版
- **原子计数器**：`RoundRobin` 用 `Arc<AtomicU32>` + `fetch_add(1, Relaxed)`，无锁递增，高并发安全
- **`collect_available` 并发检查**：每个节点并发调用 `is_available()`，最后 join_all 汇总结果
- **None 在排序末尾**：`LowestLatency` 的排序逻辑中，`ping` 失败的（`None`）排在最后，确保只选可达节点

---

### 核心数据结构

| 结构 | 字段 | 作用 | 类比 |
|------|------|------|------|
| `SelectionPolicy` | 6 种 variant | 分配规则枚举 | 裁判的"分配规则手册" |
| `DefaultNodeSelector` | `rr_counter: AtomicU32` | 轮询计数器 | 叫号机 |
| `ConnectionFingerprint` | 5-tuple | 连接特征 | 顾客的身份证号 |

---

### 设计意图

- **为什么 StickySession 和 ConsistentHashing 都用同一个哈希函数？** — 两者底层都用 `fp.hash()`，StickySession 是 ConsistentHashing 的"更严格版本"（优先固定，失败才顺延）
- **为什么 `collect_available` 不用锁保护 nodes 数组？** — `nodes` 是传入的只读引用，函数内部只是读取 `is_available()`，不需要写
- **为什么 `RoundRobin` 的 `Ordering::Relaxed` 足够？** — `Relaxed` 只保证原子性，不保证跨线程可见顺序——在 RR 场景下只需要"不重复计数"，不需要"立即看到最新值"

---

### 边界与异常

- **所有节点都 down**：所有策略统一返回 `None`
- **RoundRobin 节点数量变化**：原子计数器 mod 新数量，可能跳到不连续位置——这是可接受的，不会破坏 RR 本质
- **ConsistentHashing 所有节点都 down**：循环一圈找不到可用节点，返回 None

---

## 关键应用场景

### 🗺️ 多节点负载均衡的核心决策点

**这段代码在系统中做什么**：
`selector.rs` 是 dae-rs 代理流量分配规则的执行引擎——当有多个出口节点可用时，决定哪个请求去哪个节点。

**调用链追溯**：
```
用户请求进来
  → proxy 决策：走哪个节点？
    → NodeManager::select(policy)
      → DefaultNodeSelector::select(nodes, policy)
        → match policy { ConsistentHashing(fp) → select_consistent_hash(...) }
          → fp.hash() // 用 FNV-1a 算出哈希值
          → hash % nodes.len() // 取模得节点索引
          → 返回选中的节点
```

**触发的关键决策**：

| 场景 | 输入 | 决策 | 后果 |
|------|------|------|------|
| ConsistentHashing | 哈希值 % 3 = 1 | 选节点1 | 同一连接每次来都去同一节点 |
| StickySession 节点挂了 | 哈希到节点2但它 down 了 | 顺时针找下一个 | 容错漂移，但保证同 IP 优先固定 |
| RoundRobin | 第1001个请求 | counter=1000 mod 5 = 0 | 轮询第1个节点 |

**如果这段代码消失会怎样**：
所有流量分配策略全部失效，系统不知道该把请求发给哪个节点——代理功能直接瘫痪。

---

## 大白话总结（外婆版）

> 这个文件就是游乐场的"裁判分配规则手册"。
>
> 有的小游乐场只有一台游戏机，不用挑。有的大游乐场有 3 台、5 台甚至更多——这时候就要定规则。
>
> 6 种规则：
> 1. **最快响应**：哪台游戏机现在排队最短，就去那台（Latency）
> 2. **随机抽签**：随便抓阄（Random）
> 3. **轮流来**：1号→2号→3号→1号...（RoundRobin）
> 4. **有直连优先直连**：如果有专线游戏机，优先去那台（PreferDirect）
> 5. **固定分配**：同一个顾客每次都去同一台（一致性哈希）
> 6. **固定但能容错**：同一顾客优先同一台，但实在坏了就去下一台（StickySession）
>
> 最重要的是第 5、6 条——保证同一个用户（同一个 IP）永远去同一个出口，这样 VMess 等协议才不会因为出口不一致导致数据乱序。
