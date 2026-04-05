# 💻 费曼代码笔记：rules.rs + rule_engine.rs — 规则引擎

> 📅 学习日期：2026-04-04
> 📂 来源：packages/dae-proxy/src/rules.rs + packages/dae-proxy/src/rule_engine.rs
> 🏷️ 代码语言：Rust
> ⭐ Value_Score：8/10

## 一句话总结（10岁版本）

> 这个文件是"交通警察"——每个数据包进来，警察看一眼，问："要去哪？"（DNS 查域名），然后按规则本决定：直行（Pass）还是绕道（Proxy）还是禁止通行（Drop）。

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

**规则引擎是怎么工作的？**

想象一个高速收费站的入口：
- 你是本地车牌（国内 IP）→ 直接放行（Pass）
- 你是外地车牌（境外 IP）→ 绕道上高速（Proxy）
- 你没有车牌（被禁止的 IP）→ 禁止通行（Drop）

规则本上写着各种条件，满足哪个就执行哪个动作。

**域名规则的三种匹配方式**：

| 写法 | 规则 | 例子 |
|------|------|------|
| `example.com` | 精确匹配 | 只匹配 `example.com` |
| `.example.com` | 后缀匹配 | 匹配 `sub.example.com`、`deep.sub.example.com` |
| `keyword:google` | 关键词匹配 | 匹配任何包含 `google` 的域名 |

**规则按配置顺序匹配，先命中先执行。**

---

## 专业结构区（同行版）

### RuleAction 枚举

| Variant | 含义 | eBPF action 值 |
|---------|------|----------------|
| `Pass` | 直行（不代理） | 0 (PASS) |
| `Direct` | 强制直连 | 0 (PASS) |
| `MustDirect` | 最高优先级直连 | 0 (PASS) |
| `Proxy` | 走代理 | 0 (PASS) |
| `Drop` | 丢弃 | 2 (DROP) |
| `Default` | 默认行为 | 0 (PASS) |

### 关键数据结构

| 结构 | 作用 |
|------|------|
| `DomainRule` | 域名匹配（精确/后缀/关键词） |
| `IpCidrRule` | IP 段匹配（支持 `!` 前缀排除） |
| `GeoIpRule` | 按国家代码匹配 |
| `ProcessRule` | 进程名匹配（Linux） |
| `RuleEngine` | 规则集合 + 匹配入口 |

### eBPF stub（重要）

`ebpf_integration.rs` **不是真正的 eBPF**！注释明确写着：
> **This is an in-memory stub for development/testing.**
> Real eBPF map operations require the `aya` crate and kernel BPF support.

实际是三个 `HashMap`：
- `SessionMapHandle` → `HashMap<ConnectionKey, SessionEntry>`
- `RoutingMapHandle` → `HashMap<u32, RoutingEntry>`
- `StatsMapHandle` → `HashMap<u32, StatsEntry>`

真正需要 kernel BPF 支持时，需要替换为 `aya` crate 的 map 类型。

---

## 关键应用场景

**系统中做什么**：
规则引擎是流量路由决策的核心——每个数据包进来，根据规则（域名/IP/进程/GeoIP）决定走代理还是直连还是丢弃。

**没了会怎样**：
所有流量无法分类——不知道哪些该代理、哪些该直连、哪些该丢弃，代理完全无法工作。

---

## 大白话总结（外婆版）

> rules.rs 就是"交通规则手册"：
> - 本地车（国内 IP）→ 走普通公路（Pass）
> - 外地车（境外 IP）→ 走高速（Proxy）
> - 黑名单车辆 → 禁止上路（Drop）
>
> 手册上每条规则有三种查法：
> 1. **精确门牌号**：`example.com` —— 只认这一家
> 2. **街道后缀**：`.example.com` —— 这条街上所有户号都算
> 3. **关键词**：车牌含"北京" —— 有北京两个字的车牌都算
>
> 交通警察（rule_engine）按手册顺序一条条查，第一个命中就执行对应的动作。
