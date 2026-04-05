//! dae-xdp Maps 模块 - eBPF Map 类型重导出
//!
//! 本模块将从 [dae_ebpf_common] 导出的各种 eBPF Map 类型进行二次导出，
//! 方便 dae-xdp eBPF 程序和用户态加载器使用统一的类型定义。
//!
//! # 导出的 Map 类型
//!
//! | Map 名称     | Key 类型             | Value 类型       | 来源 crate            |
//! |-------------|---------------------|------------------|----------------------|
//! | CONFIG      | u32 (索引)          | ConfigEntry      | dae_ebpf_common::config |
//! | ROUTING     | u32 (LPM 前缀)      | RoutingEntry     | dae_ebpf_common::routing |
//! | SESSIONS    | SessionKey (5元组)  | SessionEntry     | dae_ebpf_common::session |
//! | STATS       | u32 (协议索引)      | StatsEntry       | dae_ebpf_common::stats |
//!
//! # 使用说明
//!
//! 用户态加载器（如 dae-ebpf）通过 Aya 框架操作这些 Map：
//! - 向 CONFIG 写入全局配置（启用/禁用代理）
//! - 向 ROUTING 插入/删除 CIDR 路由规则
//! - 从 SESSIONS 读取连接跟踪状态
//! - 从 STATS 汇总各 CPU 核心的统计数据

//! 配置 Map 重导出 - dae_ebpf_common::config
//!
//! CONFIG Map 用于存储全局配置项，目前主要包含 `enabled` 字段控制代理总开关。
//!
//! # ConfigEntry 结构
//!
//! - `enabled`：u8，全局代理开关（1=启用，0=禁用）
//! - `reserved`：7字节保留字段
pub use dae_ebpf_common::config::*;

//! 路由 Map 重导出 - dae_ebpf_common::routing
//!
//! ROUTING Map 使用 LPM Trie（最长前缀匹配）数据结构存储 CIDR 路由规则。
//! 支持 PASS（透传）、REDIRECT（重定向）、DROP（丢弃）三种动作。
//!
//! # RoutingEntry 结构
//!
//! - `route_id`：路由规则 ID，用于标识匹配了哪条规则
//! - `action`：动作类型（0=PASS, 1=REDIRECT, 2=DROP）
//! - `ifindex`：目标接口索引（用于 REDIRECT 动作）
//!
//! # LPM Trie 查询策略
//!
//! eBPF 程序采用降级策略进行路由查询：
//! 1. 优先尝试精确匹配 /32
//! 2. 若未命中，尝试从 /24 到 /1 递减前缀长度
//! 3. 最后尝试 /0 作为默认路由（catch-all）
pub use dae_ebpf_common::routing::{RoutingEntry, action};

//! 会话 Map 重导出 - dae_ebpf_common::session
//!
//! SESSIONS Map 是一个 HashMap，以 5 元组（源IP、目标IP、源端口、目标端口、协议）为键，
//! 存储活跃连接的状态信息。
//!
//! # SessionKey（5元组）
//!
//! - `src_ip`：源 IP 地址（网络字节序）
//! - `dst_ip`：目标 IP 地址（网络字节序）
//! - `src_port`：源端口（网络字节序）
//! - `dst_port`：目标端口（网络字节序）
//! - `proto`：IP 协议号（6=TCP, 17=UDP）
//!
//! # SessionEntry（会话状态）
//!
//! - `state`：连接状态（0=NEW, 1=ESTABLISHED, 2=CLOSED）
//! - `packets`：已处理的包数量
//! - `bytes`：已传输的总字节数
//! - `start_time`：会话建立时间（jiffies）
//! - `last_time`：最后活动时间（jiffies）
//! - `route_id`：匹配的路由规则 ID
//! - `src_mac`：源 MAC 地址（用于 LAN 流量识别）
pub use dae_ebpf_common::session::{SessionEntry, SessionKey, state};

//! 统计 Map 重导出 - dae_ebpf_common::stats
//!
//! STATS Map 使用 PerCpuArray 类型，每个 CPU 核心有独立的计数，
//! 避免了多核并发更新时的锁竞争，开销极低。
//!
//! # 统计指标
//!
//! - `packets`：处理的包总数
//! - `bytes`：处理的总字节数
//! - `redirected`：被重定向的包数
//! - `passed`：透传的包数
//! - `dropped`：丢弃的包数
//! - `routed`：匹配路由规则的包数
//! - `unmatched`：未匹配任何规则的包数
//!
//! # 统计索引
//!
//! - `idx::OVERALL (0)`：总体统计
//! - `idx::TCP (1)`：TCP 协议统计
//! - `idx::UDP (2)`：UDP 协议统计
//! - `idx::ICMP (3)`：ICMP 协议统计
//! - `idx::OTHER (4)`：其他协议统计
//!
//! # PerCpuArray 优势
//!
//! 使用 PerCpuArray 时，每个 CPU 核心有独立的 StatsEntry 副本，
//! 更新操作无需锁，仅在用户态读取时需要汇总各核数据。
//! 这对高频数据包处理场景（如 XDP）至关重要。
pub use dae_ebpf_common::stats::{StatsEntry, idx};
pub use dae_ebpf_common::ConfigEntry;

//! dae-xdp 工具模块
//!
//! 包含数据包解析工具函数和协议常量定义。

pub mod packet;
