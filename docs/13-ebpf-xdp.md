# eBPF/XDP 实现 - 功能描述

## 概述
dae-rs 使用 eBPF (Extended Berkeley Packet Filter) 和 XDP (Express Data Path) 实现高性能的数据包分类和路由决策。内核态程序运行在 XDP 层，用户态程序管理 eBPF Maps。

## 模块结构

### dae-ebpf-common
共享的 eBPF 类型定义，在 kernel 和 user 空间之间共享。

### dae-xdp
XDP (Express Data Path) eBPF 程序，用于数据包捕获和初始分类。

## 流程图/数据流

### XDP 数据包处理流程
```
NIC RX -> [XDP Driver Hook] -> [xdp_prog_main]
                                    |
                                    v
                          [Parse Ethernet Header]
                                    |
                                    v
                          [Parse IPv4 Header]
                                    |
                                    v
                          [Lookup Routing (LPM Trie)]
                                    |
                    +---------------+---------------+
                    |                               |
              action::PASS                    action::DROP
                    |                               |
                    v                               v
              [Pass to Stack]                 [Drop Packet]
```

### eBPF Maps 架构
```
User Space (dae-proxy)          Kernel Space (XDP)
        |                               |
        | <------ SESSIONS ------>       |
        |   (Connection Tracking)        |
        |                               |
        | <------ ROUTING ------>        |
        |   (Routing Rules LPM Trie)     |
        |                               |
        | <------ STATS ------>          |
        |   (Traffic Statistics)         |
        |                               |
        | <------ CONFIG ------>         |
        |   (Global Configuration)       |
```

## eBPF Maps

### CONFIG Map
全局配置项数组。
```rust
struct ConfigEntry {
    enabled: u8,
    mode: u8,
    // ...
}
```

### SESSIONS Map
会话跟踪哈希表，Key 为 5 元组。
```rust
struct SessionKey {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
}

struct SessionEntry {
    state: u8,
    packets: u64,
    bytes: u64,
    start_time: u64,
    last_time: u64,
    route_id: u32,
}
```

### ROUTING Map
LPM Trie (Longest Prefix Match) 路由规则表。
```rust
struct RoutingEntry {
    route_id: u32,
    action: u8,    // PASS, DROP, REDIRECT
    ifindex: u32,
}
```

### STATS Map
Per-CPU 流量统计数组。
```rust
struct StatsEntry {
    tcp_bytes: u64,
    tcp_packets: u64,
    udp_bytes: u64,
    udp_packets: u64,
    other_bytes: u64,
    other_packets: u64,
}
```

## 路由动作

| Action | 值 | 说明 |
|--------|---|------|
| PASS | 0 | 放行/直连 |
| REDIRECT | 1 | 重定向到代理 |
| DROP | 2 | 丢弃数据包 |

## 接口设计

### dae-ebpf-common 模块
```rust
pub mod config;    // ConfigEntry, GLOBAL_CONFIG_KEY
pub mod direct;    // Direct routing types
pub mod routing;   // RoutingEntry, action constants
pub mod session;   // SessionEntry, SessionKey, state constants
pub mod stats;     // StatsEntry, idx constants
```

### dae-xdp 模块
```rust
#[xdp]
pub fn xdp_prog_main(ctx: XdpContext) -> u32

fn xdp_prog(ctx: &mut XdpContext) -> Result<u32, ()>
fn lookup_routing(dst_ip: u32) -> Option<RoutingEntry>
```

### User Space Integration (dae-proxy)
```rust
struct EbpfMaps {
    sessions: Option<SessionMapHandle>,
    routing: Option<RoutingMapHandle>,
    stats: Option<StatsMapHandle>,
}

struct EbpfSessionHandle { maps: EbpfMaps }
struct EbpfRoutingHandle { maps: EbpfMaps }
struct EbpfStatsHandle { maps: EbpfMaps }
```

## 配置项

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | true | 启用 eBPF |
| `session_map_size` | u32 | 65536 | 会话 Map 大小 |
| `routing_map_size` | u32 | 16384 | 路由 Map 大小 |
| `stats_map_size` | u32 | 256 | 统计 Map 大小 |

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `MapNotFound` | eBPF Map 不存在 | 检查加载 |
| `KeyNotFound` | 查找的 Key 不存在 | 使用默认路由 |
| `UpdateFailed` | Map 更新失败 | 记录错误 |
| `PermissionDenied` | 无 eBPF 权限 | 需要 root/CAP_BPF |

## 安全性考虑

1. **CAP_BPF**: 需要 CAP_BPF 或 root 权限加载 eBPF 程序
2. **XDP Mode**: 可在 SKB/DRV/HC 模式下运行
3. **LPM Trie**: 支持最长前缀匹配，适合 CIDR 路由规则
4. **Per-CPU Stats**: 统计使用 Per-CPU 数组避免锁竞争
5. **Session Tracking**: 会话表支持连接跟踪和超时管理
