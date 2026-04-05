//! dae-xdp - XDP eBPF 程序 for dae-rs
//!
//! 本模块实现基于 XDP（eXpress Data Path）的透明代理 eBPF 程序，用于在内核网络栈的早期阶段
//! 捕获、分类和处理网络数据包。
//!
//! # 核心功能
//!
//! - **XDP 钩子**：在网卡驱动层（最早可能阶段）捕获数据包，实现零拷贝、零开销流量分类
//! - **流量分类**：基于目标 IP 的最长前缀匹配（LPM）路由规则，决定数据包是直连、代理还是丢弃
//! - **连接跟踪**：维护活跃连接的会话状态，用于有状态的代理决策
//! - **统计计数**：使用 PerCPU 数组高效统计各类数据包和字节数
//!
//! # 数据包处理流程
//!
//! ```text
//! NIC 收到数据包
//!      │
//!      ▼
//! +------------------+
//! |    XDP 钩子       | ◄── dae-xdp 在此阶段拦截
//! +------------------+
//!      │
//!      ├─► 解析以太网头（EthHdr）
//!      │     │
//!      │     ├─► 检查 VLAN 标签（VlanHdr）
//!      │     │
//!      │     ▼
//!      │   解析 IPv4 头（IpHdr）
//!      │     │
//!      │     ▼
//!      │   查询 SESSIONS HashMap（5元组 → 会话）
//!      │     │
//!      │     ▼
//!      │   查询 ROUTING LPM Trie（目标IP → 路由规则）
//!      │     │
//!      │     ▼
//!      │   执行动作：XDP_PASS / XDP_DROP / XDP_REDIRECT
//!      │
//!      ▼
//! 返回内核继续处理或丢弃
//! ```
//!
//! # eBPF Map 用途
//!
//! | Map 名称    | 类型          | Key                | Value            | 用途              |
//! |------------|---------------|--------------------|------------------|-------------------|
//! | CONFIG     | Array         | u32 (索引=0)       | ConfigEntry       | 全局使能/禁用     |
//! | SESSIONS   | HashMap       | SessionKey (5元组)  | SessionEntry     | TCP/UDP 连接跟踪  |
//! | ROUTING    | LpmTrie       | u32 (IP地址)       | RoutingEntry      | CIDR 路由规则     |
//! | STATS      | PerCpuArray   | u32 (协议类型)     | StatsEntry        | 流量统计计数      |
//!
//! # 限制与注意事项
//!
//! - 当前仅支持 IPv4 数据包，IPv6 会直接透传（XDP_PASS）
//! - 不解析 TCP/UDP 端口（由 dae-tc 处理更精细的分类）
//! - 不支持分段数据包（fragment）
//! - 使用 LPM Trie 时采用降级策略，优先精确匹配 /32 再尝试递减前缀长度
//!
//! # 与 dae-tc 的区别
//!
//! - **dae-xdp**：在 XDP 层工作，适合高速路径的早期分流；不解析传输层端口
//! - **dae-tc**：在 TC 层工作，可以解析 TCP/UDP 端口，支持更精细的规则匹配
//! - 两者可以同时部署，dae-xdp 做粗筛，dae-tc 做细筛

#![no_std]
#![deny(warnings)]
// Allow strict clippy lints for eBPF code patterns
#![allow(clippy::field_reassign_with_default)]

use aya_ebpf::bindings::xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS};
use aya_ebpf::macros::map;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{Array, HashMap, LpmTrie, PerCpuArray};
use aya_ebpf::programs::XdpContext;

use dae_ebpf_common::{
    action, state, ConfigEntry, RoutingEntry, SessionEntry, SessionKey, StatsEntry,
};

mod utils;

use utils::packet::*;

/// 全局配置 Map
///
/// 类型：[`Array<ConfigEntry>`]
/// 容量：1 个元素（索引 0 = GLOBAL_CONFIG_KEY）
///
/// # 用途
///
/// 用户态程序写入全局配置，eBPF 程序在处理每个包前检查 `enabled` 字段：
/// - `enabled = 1`：启用代理，正常处理
/// - `enabled = 0`：禁用代理，所有包透传（XDP_PASS）
///
/// # 注意事项
///
/// - 使用 Array 而不是 HashMap，因为配置项数量固定为 1
/// - 索引 0 固定为全局配置（`GLOBAL_CONFIG_KEY = 0`）
#[map]
static CONFIG: Array<ConfigEntry> = Array::with_max_entries(1, 0);

/// 连接会话跟踪 Map
///
/// 类型：[`HashMap<SessionKey, SessionEntry>`]
/// 最大容量：65536 个并发连接
///
/// # 用途
///
/// 维护活跃连接的会话状态，包括：
/// - 连接状态（NEW/ESTABLISHED/CLOSED）
/// - 数据包和字节计数
/// - 时间戳（建立时间、最后活动时间）
/// - 路由规则 ID
/// - 源 MAC 地址（用于 LAN 识别）
///
/// # 键结构（SessionKey）
///
/// 5 元组：`(src_ip, dst_ip, src_port, dst_port, proto)`
/// 用于唯一标识一个 TCP 或 UDP 连接。
///
/// # 注意事项
///
/// - HashMap 查询为 O(1)，适合海量连接场景
/// - 需要用户态程序定期清理超时会话（建议 5 分钟无活动视为超时）
#[map]
static SESSIONS: HashMap<SessionKey, SessionEntry> = HashMap::with_max_entries(65536, 0);

/// 统计计数 Map
///
/// 类型：[`PerCpuArray<StatsEntry>`]
/// 容量：16 个统计槽位
///
/// # 用途
///
/// 使用 PerCPU 数组高效统计各类数据包处理情况：
/// - `idx::OVERALL (0)`：所有协议汇总
/// - `idx::TCP (1)`：TCP 统计
/// - `idx::UDP (2)`：UDP 统计
/// - `idx::ICMP (3)`：ICMP 统计
/// - `idx::OTHER (4)`：其他协议
///
/// # PerCpuArray 优势
///
/// 每个 CPU 核心有独立的 StatsEntry 副本，原子更新无需锁，n/// 仅在用户态读取汇总时需要合并数据，开销极低。
/// 这对 XDP 每包必检的高性能场景至关重要。
///
/// # Safety
///
/// - PerCpuArray 的 `get_ptr_mut` 返回可变指针，必须在有效作用域内使用
#[map]
static STATS: PerCpuArray<StatsEntry> = PerCpuArray::with_max_entries(16, 0);

/// 路由规则 Map
///
/// 类型：[`LpmTrie<u32, RoutingEntry>`]
/// 最大容量：65536 条 CIDR 规则
///
/// # 用途
///
/// 存储 CIDR 格式的路由规则，用于决定数据包的处理方式：
/// - `action::PASS (0)`：透传，不经过代理
/// - `action::REDIRECT (1)`：重定向到代理
/// - `action::DROP (2)`：丢弃数据包
///
/// # LPM Trie 查询
///
/// LpmTrie 支持最长前缀匹配，如：
/// - 规则 `10.0.0.0/8` 可以匹配 `10.1.2.3`
/// - 规则 `10.1.0.0/16` 比 `10.0.0.0/8` 更精确
///
/// 内核自动返回最长前缀匹配的规则。
///
/// # 注意事项
///
/// - Key 是 `(prefix_len, ip)` 元组，通过 `Key::new(prefix_len, ip)` 构造
/// - 支持任意前缀长度（0-32），`/0` 为默认路由
#[map]
static ROUTING: LpmTrie<u32, RoutingEntry> = LpmTrie::with_max_entries(65536, 0);

/// XDP 程序入口点
///
/// 由 `#[aya_ebpf::macros::xdp]` 宏生成外层包装函数，签名：
/// `fn xdp_prog_main(ctx: *mut xdp_md) -> u32`
/// 内部调用本函数执行实际数据包处理逻辑。
///
/// # 返回值
///
/// - `XDP_PASS (2)`：数据包继续正常处理（透传）
/// - `XDP_DROP (1)`：丢弃数据包
/// - `XDP_ABORTED (3)`：处理异常（丢弃并记录追踪信息）
///
/// # eBPF Safety
///
/// - 宏自动处理上下文指针转换和错误处理
/// - 若 `xdp_prog` 返回 `Err`，本函数返回 `XDP_ABORTED`
/// - 外层函数由 aya_ebpf 框架生成，保证符合 eBPF 验证器要求
#[aya_ebpf::macros::xdp]
pub fn xdp_prog_main(mut ctx: XdpContext) -> u32 {
    match xdp_prog(&mut ctx) {
        Ok(ret) => ret,
        Err(_) => XDP_ABORTED,
    }
}

/// XDP 程序主逻辑
///
/// 解析以太网头 → 检查 VLAN → 解析 IP 头 → 查询会话 → 查询路由 → 执行动作。
///
/// # 参数
///
/// * `ctx` - XDP 上下文，包含数据包指针和边界信息
///
/// # 返回值
///
/// - `Ok(u32)`：返回 XDP action（XDP_PASS/XDP_DROP/XDP_ABORTED）
/// - `Err(())`：处理失败，返回 XDP_ABORTED
///
/// # 数据包处理步骤
///
/// 1. **解析以太网头**：获取 EtherType，判断是否 IPv4
/// 2. **检查 VLAN**：若 EtherType=0x8100，解析 VLAN 标签获取实际协议类型
/// 3. **解析 IPv4 头**：提取源/目标 IP、协议号
/// 4. **会话管理**：
///    - 查询 SESSIONS HashMap，命中则更新，不命中则创建新会话
///    - 新会话记录源 MAC、状态=NEW、包计数=1
/// 5. **路由查询**：
///    - 调用 `lookup_routing(dst_ip)` 使用 LPM 查找匹配规则
///    - 未匹配则透传
///    - 匹配则更新会话的 route_id
/// 6. **执行动作**：
///    - PASS → XDP_PASS
///    - DROP → XDP_DROP
///    - REDIRECT → XDP_PASS（当前版本 REDIRECT 和 PASS 等效）
///
/// # Safety
///
/// - `unsafe { *hdr }` 解引用前，调用方已通过边界检查确保指针有效
/// - 所有头解析函数（`from_ctx`/`from_ctx_after_eth`）在返回 `Some` 前验证边界
fn xdp_prog(ctx: &mut XdpContext) -> Result<u32, ()> {
    // Parse Ethernet header
    let eth = match EthHdr::from_ctx(ctx) {
        // SAFETY: EthHdr::from_ctx returns None if bounds check fails,
        // otherwise returns a valid pointer that can be safely dereferenced.
        Some(hdr) => unsafe { *hdr },
        None => {
            // Can't parse Ethernet header, pass
            return Ok(XDP_PASS);
        }
    };

    // Extract source MAC address for LAN traffic classification
    let src_mac = eth.src_mac();

    // Handle MACv2 extension (VLAN tagging)
    // When VLAN tag is present (EtherType = 0x8100), the actual protocol
    // type is after the 4-byte VLAN tag, and IP header starts at offset 18
    let (ip_offset, is_ipv4) = if eth.has_vlan() {
        // VLAN tag present, check inner EtherType
        let vlan = match VlanHdr::from_ctx_after_eth(ctx, core::mem::size_of::<EthHdr>()) {
            // SAFETY: VlanHdr::from_ctx_after_eth returns None if bounds check fails,
            // otherwise returns a valid pointer that can be safely dereferenced.
            Some(hdr) => unsafe { *hdr },
            None => {
                return Ok(XDP_PASS);
            }
        };
        let inner_ethertype = vlan.inner_ether_type();
        // Inner EtherType is in lower 16 bits of TCI
        let actual_ethertype = inner_ethertype;
        // After EthHdr (14 bytes) + VlanHdr (4 bytes) = 18 bytes
        (
            core::mem::size_of::<EthHdr>() + core::mem::size_of::<VlanHdr>(),
            actual_ethertype == ethertype::IPV4,
        )
    } else {
        // No VLAN tag
        (core::mem::size_of::<EthHdr>(), eth.is_ipv4())
    };

    // Check if IPv4 (we only support IPv4 for now)
    if !is_ipv4 {
        // Pass non-IPv4 packets
        return Ok(XDP_PASS);
    }

    // Parse IPv4 header
    let ip = match IpHdr::from_ctx_after_eth(ctx, ip_offset) {
        // SAFETY: IpHdr::from_ctx_after_eth returns None if bounds check fails,
        // otherwise returns a valid pointer that can be safely dereferenced.
        Some(hdr) => unsafe { *hdr },
        None => {
            return Ok(XDP_PASS);
        }
    };

    // Verify this is IPv4
    if ip.version() != 4 {
        return Ok(XDP_PASS);
    }

    // Get source MAC and destination IP for routing lookup
    let src_ip = ip.src_addr();
    let dst_ip = ip.dst_addr();

    // Create session key
    let session_key = SessionKey::new(src_ip, dst_ip, 0, 0, ip.protocol());

    // Look up or create session entry with MAC information
    // SAFETY: SESSIONS is a valid eBPF map; get() returns None if key not found.
    let session = match unsafe { SESSIONS.get(&session_key) } {
        Some(entry) => {
            // Update existing session, preserve MAC if already set
            let mut updated = *entry;
            if updated.src_mac_len == 0 {
                updated.src_mac = src_mac;
                updated.src_mac_len = 6;
            }
            updated
        }
        None => {
            // Create new session with MAC
            let mut session = SessionEntry::default();
            session.state = state::NEW;
            session.src_mac_len = 6;
            session.src_mac = src_mac;
            session.packets = 1;
            session
        }
    };

    // Store session (ignore errors for now)
    let _ = SESSIONS.insert(&session_key, &session, 0);

    // Look up routing decision
    let route = match lookup_routing(dst_ip) {
        Some(r) => r,
        None => {
            // No routing rule matched
            return Ok(XDP_PASS);
        }
    };

    // Update session with routing decision
    let mut updated_session = session;
    updated_session.route_id = route.route_id;
    let _ = SESSIONS.insert(&session_key, &updated_session, 0);

    // Handle based on routing action
    match route.action {
        action::PASS => Ok(XDP_PASS),
        action::REDIRECT => Ok(XDP_PASS), // For now, just pass
        action::DROP => Ok(XDP_DROP),
        _ => Ok(XDP_PASS),
    }
}

/// 使用最长前缀匹配（LPM）查询目标 IP 的路由条目
///
/// 采用降级策略补偿部分内核版本 LpmTrie 精确匹配 /32 时的兼容性问题：
///
/// # 参数
///
/// * `dst_ip` - 目标 IP 地址（网络字节序，u32）
///
/// # 返回值
///
/// - `Some(RoutingEntry)`：找到匹配的路由规则
/// - `None`：没有匹配的路由规则（数据包应透传）
///
/// # 查询顺序
///
/// 1. 先尝试精确匹配 `/32`（具体主机路由）
/// 2. 若未命中，从 `/24` 递减到 `/1` 逐级尝试
/// 3. 最后尝试 `/0`（默认路由，catch-all）
///
/// # 性能考虑
///
/// - 最坏情况需要 25 次 LpmTrie 查询（/32 + /24..1 + /0）
/// - LpmTrie 内部实现为二分查找树，单次查询 O(log n)
/// - 对大多数场景（规则数量 < 10K），额外查询次数可忽略
fn lookup_routing(dst_ip: u32) -> Option<RoutingEntry> {
    // Try exact match first (/32)
    let key = Key::new(32, dst_ip);
    if let Some(route) = ROUTING.get(&key) {
        return Some(*route);
    }

    // Try decreasing prefix lengths from /24 down to /1
    let mut prefix: u32 = 24;
    while prefix > 0 {
        let key = Key::new(prefix, dst_ip);
        if let Some(route) = ROUTING.get(&key) {
            return Some(*route);
        }
        prefix -= 1;
    }

    // Try /0 (catch-all)
    let key = Key::new(0, 0);
    ROUTING.get(&key).copied()
}
