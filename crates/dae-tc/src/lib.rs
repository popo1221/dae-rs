//! dae-tc - TC eBPF program for dae-rs transparent proxy
//!
//! This program captures network packets using tc (traffic control) clsact
//! qdisc and performs traffic classification and redirection for
//! transparent proxy support.
//!
//! # Architecture
//!
//! ```text
//! Network Packet
//!      |
//!      v
//! +-----------------+
//! |  clsact qdisc   | (Kernel TC layer)
//! +-----------------+
//!      |
//!      v
//! +-----------------+
//! |  dae-tc eBPF    | (This program)
//! |  tc_prog_main   |
//! +-----------------+
//!      |
//!      +---> Parse Ethernet header
//!      +---> Parse IPv4 header
//!      +---> Parse TCP/UDP header
//!      +---> Lookup session (SESSIONS map)
//!      +---> Lookup routing (ROUTING map - LPM)
//!      +---> Apply action (PASS/REDIRECT/DROP)
//! ```
//!
//! # Key Features
//!
//! - Attaches to tc clsact qdisc on the specified interface
//! - Parses Ethernet, IPv4, TCP, and UDP headers
//! - Supports VLAN tagging (802.1Q)
//! - Performs longest-prefix-match (LPM) routing lookups
//! - Tracks connection state for stateful proxying
//! - Supports PASS, REDIRECT, and DROP routing actions
//!
//! # Maps
//!
//! - `SESSIONS`: HashMap<SessionKey, SessionEntry> - Connection tracking
//! - `ROUTING`: LpmTrie<u32, RoutingEntry> - CIDR routing rules
//! - `DNS_MAP`: HashMap<u64, DnsMapEntry> - Domain name mapping
//! - `CONFIG`: Array<ConfigEntry> - Global configuration
//! - `STATS`: PerCpuArray<StatsEntry> - Statistics counters
//!
//! # Usage
//!
//! This eBPF program is loaded by the user-space loader (dae-ebpf) using
//! the TC program type. The loader will:
//! 1. Setup clsact qdisc on the target interface
//! 2. Load this eBPF program into the kernel
//! 3. Attach it as an ingress filter

#![no_std]
#![allow(unused)]
// Allow strict clippy lints for eBPF code patterns
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::needless_range_loop)]

use aya_ebpf::bindings::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::map;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{Array, HashMap, LpmTrie, PerCpuArray};
use aya_ebpf::programs::TcContext;

use dae_ebpf_common::{
    action, state, ConfigEntry, DnsMapEntry, RoutingEntry, SessionEntry, SessionKey, StatsEntry,
};

mod constants;
mod maps;
mod packet;

use crate::constants::{ethertype, ip_proto};
use maps::idx;
use packet::*;

/// 全局配置 Map
///
/// 类型：[`Array<ConfigEntry>`]
/// 容量：1 个元素
///
/// # 用途
///
/// 存储全局配置，目前只有一个条目：
/// - `enabled = 1`：代理启用
/// - `enabled = 0`：代理禁用（所有包透传 TC_ACT_OK）
///
/// # 注意
///
/// 与 dae-xdp 的 CONFIG 是同一个概念，但 dae-xdp 和 dae-tc 运行在不同层级，
/// 两者可以通过各自的 CONFIG Map 独立控制。
#[map]
static CONFIG: Array<ConfigEntry> = Array::with_max_entries(1, 0);

/// 连接会话跟踪 Map
///
/// 类型：[`HashMap<SessionKey, SessionEntry>`]
/// 最大容量：65536 个连接
///
/// # 用途
///
/// 跟踪 TCP/UDP 连接状态，比 dae-xdp 更详细：
/// - 支持 TCP/UDP 端口解析
/// - 记录每个连接的包计数、字节计数
/// - 记录连接建立时间和最后活动时间（纳秒级精度）
///
/// # 5 元组 SessionKey
///
/// `(src_ip, dst_ip, src_port, dst_port, proto)`
/// - `src_ip`, `dst_ip`：源/目标 IP（网络字节序）
/// - `src_port`, `dst_port`：源/目标端口（网络字节序）
/// - `proto`：协议号（6=TCP, 17=UDP）
///
/// # 与 dae-xdp SESSIONS 的区别
///
/// - dae-xdp：仅记录 IPv4 头部信息（无端口），用于粗筛
/// - dae-tc：完整 5 元组，更精细化的连接跟踪
#[map]
static SESSIONS: HashMap<SessionKey, SessionEntry> = HashMap::with_max_entries(65536, 0);

/// 路由规则 Map（LPM Trie for CIDR 匹配）
///
/// 类型：[`LpmTrie<u32, RoutingEntry>`]
/// 最大容量：65536 条规则
///
/// # 用途
///
/// 存储 CIDR 路由规则，决定每个数据包的处理动作：
/// - `action::PASS`：透传，不经过代理
/// - `action::REDIRECT`：重定向（设置 skb mark 为 route_id，用户态读取后处理）
/// - `action::DROP`：丢弃（返回 TC_ACT_SHOT）
///
/// # LPM 查询特性
///
/// 内核 LpmTrie 自动做最长前缀匹配，例如：
/// - 规则 `192.168.1.0/24` → 匹配 `192.168.1.x` 所有地址
/// - 规则 `192.168.0.0/16` → 匹配 `192.168.x.y` 所有地址
/// - 查询 `192.168.1.100` → 精确匹配 /24（优于 /16）
///
/// # 与 dae-xdp ROUTING 的区别
///
/// - dae-xdp：简化版，仅做 IP 层分类
/// - dae-tc：可结合端口信息做更细粒度的规则匹配（通过 DNS_MAP 等辅助判断）
#[map]
static ROUTING: LpmTrie<u32, RoutingEntry> = LpmTrie::with_max_entries(65536, 0);

/// DNS 映射 Map
///
/// 类型：[`HashMap<u64, DnsMapEntry>`]
/// 最大容量：65536 条
///
/// # 用途
///
/// 存储域名到 IP 地址的映射关系，用于基于域名的路由决策：
/// - 键：域名 DJB2 哈希（64位）
/// - 值：`DnsMapEntry { ip, expire_time, domain_len, domain }`
///
/// # 超时机制
///
/// `expire_time` 字段存储过期时间戳（jiffies），
/// 用户态程序应定期清理过期条目或检查 `is_expired()`。
///
/// # 使用场景
///
/// 1. 用户态拦截 DNS 请求，记录 `domain → resolved_ip` 映射
/// 2. eBPF 在数据包处理时查询 `DNS_MAP`，根据目标 IP 查对应域名
/// 3. 若命中 BLOCK 规则对应的域名，则 DROP 相关流量
#[map]
static DNS_MAP: HashMap<u64, DnsMapEntry> = HashMap::with_max_entries(65536, 0);

/// IP → 域名反向映射 Map
///
/// 类型：[`HashMap<u32, u64>`]
/// 最大容量：65536 条
///
/// # 用途
///
/// 提供从 IP 地址到域名的反向查询能力：
/// - 键：IP 地址（网络字节序，u32）
/// - 值：域名哈希（与 DNS_MAP 相同算法）
///
/// # 使用场景
///
/// 当只知道目标 IP（而非域名）时，通过本 Map 查找对应域名：
/// 1. 查 `IP_DOMAIN_MAP[ip]`，得到域名哈希
/// 2. 查 `DNS_MAP[hash]`，得到 `DnsMapEntry`
/// 3. 结合域名信息做路由决策
#[map]
static IP_DOMAIN_MAP: HashMap<u32, u64> = HashMap::with_max_entries(65536, 0);

/// 统计计数 Map
///
/// 类型：[`PerCpuArray<StatsEntry>`]
/// 容量：16 个统计槽
///
/// # 用途
///
/// 按协议类型统计流量：
/// - `idx::TCP`：TCP 包统计
/// - `idx::UDP`：UDP 包统计
/// - `idx::OTHER`：其他协议统计
///
/// # PerCpuArray 优势
///
/// 每个 CPU 核心独立计数，无锁原子更新，极适合高频流量处理。
/// TC 程序在每个包处理路径上执行统计更新，开销极小。
#[map]
static STATS: PerCpuArray<StatsEntry> = PerCpuArray::with_max_entries(16, 0);

/// TC 程序入口点
///
/// 挂载在 `clsact` qdisc 上的 eBPF 分类器，每个经过网卡的包都会触发本函数。
/// 内核传递原始 `__sk_buff` 指针，aya_ebpf 将其包装为 `TcContext`。
///
/// # 参数
///
/// * `ctx` - 内核传递的 `__sk_buff` 原始指针的包装
///
/// # 返回值
///
/// * `TC_ACT_OK (1)`：继续正常处理数据包（透传）
/// * `TC_ACT_SHOT (2)`：丢弃数据包
///
/// # eBPF 程序签名要求
///
/// TC eBPF 程序的函数签名必须为 `extern "C" fn(*mut __sk_buff) -> i32`。
/// `#[link_section = "classifier"]` 将本函数放到 eBPF 对象的 `.classifier` 段，
/// 供 TC 基础设施加载和绑定。
///
/// # Safety
///
/// - 本函数由内核调用，上下文指针由内核保证有效
/// - 内部 `TcContext::new()` 包装 raw pointer，不执行额外内存分配
/// - 若 `tc_prog` 返回 `Err`，默认返回 `TC_ACT_OK`（保守策略，不丢弃）
#[no_mangle]
#[link_section = "classifier"]
pub extern "C" fn tc_prog_main(ctx: *mut __sk_buff) -> i32 {
    let mut tc_ctx = TcContext::new(ctx);
    match tc_prog(&mut tc_ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

/// TC 程序主逻辑
///
/// 完整数据包处理流程：解析 Ethernet → 解析 IP → 解析 TCP/UDP → 会话跟踪 → 路由查询 → 统计 → 执行动作。
///
/// # 参数
///
/// * `ctx` - TC 上下文，包含 `sk_buff` 数据包指针和边界信息
///
/// # 返回值
///
/// - `Ok(i32)`：返回 TC action（`TC_ACT_OK` 或 `TC_ACT_SHOT`）
/// - `Err(())`：解析失败或异常，返回 `TC_ACT_OK`（保守策略）
///
/// # 数据包处理步骤
///
/// 1. **解析 Ethernet 头**：获取 EtherType，判断 IPv4 或 VLAN
/// 2. **VLAN 处理**：若存在 802.1Q VLAN 标签，提取实际 EtherType
/// 3. **解析 IPv4 头**：提取 src_ip、dst_ip、protocol、header_len
/// 4. **提取端口**（TCP/UDP）：
///    - TCP：解析 TcpHdr，获取 src_port、dst_port
///    - UDP：解析 UdpHdr，获取 src_port、dst_port
///    - 其他协议：端口设为 0
/// 5. **会话管理**：
///    - 查询 SESSIONS，存在则更新（包计数+1、最后时间）
///    - 不存在则创建新会话（state=NEW，MAC 地址，时间戳）
/// 6. **路由查询**：调用 `lookup_routing(dst_ip)` 查找 LPM 规则
/// 7. **更新会话路由 ID**：将匹配规则的 route_id 写入会话
/// 8. **统计计数**：
///    - 按协议类型（TCP/UDP/OTHER）更新对应槽的 STATS
///    - 原子递增 packets 和 bytes
/// 9. **执行动作**：
///    - PASS → TC_ACT_OK（包正常通过）
///    - REDIRECT → 设置 skb mark = route_id → TC_ACT_OK（用户态读取 mark 处理）
///    - DROP → TC_ACT_SHOT（丢弃）
///
/// # Safety
///
/// - `unsafe { *hdr }` 解引用前，解析函数已通过边界检查验证
/// - `bpf_ktime_get_ns()` 是内核 BPF helper，始终返回有效时间戳
/// - `STATS.get_ptr_mut()` 在有效 Map 索引范围内使用是安全的
fn tc_prog(ctx: &mut TcContext) -> Result<i32, ()> {
    // Parse Ethernet header
    let eth = match EthHdr::from_ctx(ctx) {
        // SAFETY: EthHdr::from_ctx returns Some only when valid ethernet header exists in packet buffer
        Some(hdr) => unsafe { *hdr },
        None => {
            // Can't parse Ethernet header, pass
            return Ok(TC_ACT_OK);
        }
    };

    // Get source MAC address for potential LAN classification
    let src_mac = eth.src_mac();

    // Handle VLAN tagging
    let (ip_offset, is_ipv4) = if eth.has_vlan() {
        // VLAN tag present - need to look at the VLAN header to get actual EtherType
        let vlan = match VlanHdr::from_ctx_after_eth(ctx, core::mem::size_of::<EthHdr>()) {
            // SAFETY: VlanHdr::from_ctx_after_eth returns Some when VLAN tag is present and valid
            Some(hdr) => unsafe { *hdr },
            None => {
                return Ok(TC_ACT_OK);
            }
        };
        let actual_ethertype = vlan.tpid;
        (
            core::mem::size_of::<EthHdr>() + core::mem::size_of::<VlanHdr>(),
            actual_ethertype == ethertype::IPV4,
        )
    } else {
        (core::mem::size_of::<EthHdr>(), eth.is_ipv4())
    };

    // Check if IPv4
    if !is_ipv4 {
        return Ok(TC_ACT_OK);
    }

    // Parse IPv4 header
    let ip = match IpHdr::from_ctx_after_eth(ctx, ip_offset) {
        // SAFETY: IpHdr::from_ctx_after_eth returns Some when IPv4 header is present and valid
        Some(hdr) => unsafe { *hdr },
        None => {
            return Ok(TC_ACT_OK);
        }
    };

    // Verify IPv4
    if ip.version() != 4 {
        return Ok(TC_ACT_OK);
    }

    let src_ip = ip.src_addr();
    let dst_ip = ip.dst_addr();
    let ip_proto = ip.protocol();
    let ip_hdr_len = ip.header_len();

    // Extract ports for TCP/UDP
    let (src_port, dst_port) = match ip_proto {
        ip_proto::TCP => {
            let tcp = match TcpHdr::from_ctx_after_ip(ctx, ip_offset, ip_hdr_len) {
                // SAFETY: TcpHdr::from_ctx_after_ip returns Some when TCP header is present and valid
                Some(hdr) => unsafe { *hdr },
                None => return Ok(TC_ACT_OK),
            };
            (tcp.src_port(), tcp.dst_port())
        }
        ip_proto::UDP => {
            let udp = match UdpHdr::from_ctx_after_ip(ctx, ip_offset, ip_hdr_len) {
                // SAFETY: UdpHdr::from_ctx_after_ip returns Some when UDP header is present and valid
                Some(hdr) => unsafe { *hdr },
                None => return Ok(TC_ACT_OK),
            };
            (udp.src_port(), udp.dst_port())
        }
        _ => (0, 0),
    };

    // Create session key (5-tuple)
    let session_key = SessionKey::new(src_ip, dst_ip, src_port, dst_port, ip_proto);

    // Get current timestamp
    // SAFETY: bpf_ktime_get_ns is a BPF helper that always returns a valid timestamp
    let now = unsafe { bpf_ktime_get_ns() };

    // Look up or create session
    // SAFETY: SESSIONS map access is safe - we provide a valid key and handle the Option returned
    let session = match unsafe { SESSIONS.get(&session_key) } {
        Some(entry) => {
            // Update existing session
            let mut updated = *entry;
            updated.packets += 1;
            updated.last_time = now;
            updated
        }
        None => {
            // Create new session
            let mut session = SessionEntry::default();
            session.state = state::NEW;
            session.packets = 1;
            session.start_time = now;
            session.last_time = now;
            session.src_mac_len = 6;
            session.src_mac = src_mac;
            session
        }
    };

    // Store/update session
    let _ = SESSIONS.insert(&session_key, &session, 0);

    // Look up routing decision for destination using LPM
    let route = match lookup_routing(dst_ip) {
        Some(r) => r,
        None => {
            // No routing rule matched, pass
            return Ok(TC_ACT_OK);
        }
    };

    // Update session with routing decision
    let mut updated_session = session;
    updated_session.route_id = route.route_id;
    let _ = SESSIONS.insert(&session_key, &updated_session, 0);

    // Update statistics using per-CPU array
    // Note: PerCpuArray values are updated in place via get_ptr_mut
    let stats_idx = match ip_proto {
        ip_proto::TCP => idx::TCP,
        ip_proto::UDP => idx::UDP,
        _ => idx::OTHER,
    };
    if let Some(stats_ptr) = unsafe { STATS.get_ptr_mut(stats_idx) } {
        // SAFETY: stats_ptr is guaranteed to be valid since we got it from the map
        let stats = unsafe { &mut *stats_ptr };
        stats.packets += 1;
        stats.bytes += ip.tot_len() as u64;
    }

    // Handle based on routing action
    match route.action {
        action::PASS => {
            // Packet passes through unchanged
            Ok(TC_ACT_OK)
        }
        action::REDIRECT => {
            // Mark packet for redirection to proxy
            // We set the skb mark which can be read by userspace
            ctx.set_mark(route.route_id);
            Ok(TC_ACT_OK)
        }
        action::DROP => {
            // Drop the packet
            Ok(TC_ACT_SHOT)
        }
        _ => Ok(TC_ACT_OK),
    }
}

/// Look up routing entry for a destination IP using longest prefix match
///
/// Uses the eBPF LpmTrie map which automatically performs longest prefix
/// matching. For compatibility with older kernels, we also try decreasing
/// prefix lengths.
fn lookup_routing(dst_ip: u32) -> Option<RoutingEntry> {
    // First try exact match with /32
    let key = Key::new(32, dst_ip);
    if let Some(route) = ROUTING.get(&key) {
        return Some(*route);
    }

    // Fallback: try decreasing prefix lengths from /24 down to /1
    // This provides compatibility with kernels that may have issues
    // with the exact /32 lookup
    let mut prefix: u32 = 24;
    while prefix > 0 {
        let key = Key::new(prefix, dst_ip);
        if let Some(route) = ROUTING.get(&key) {
            return Some(*route);
        }
        prefix -= 1;
    }

    // Try /0 (catch-all default route)
    let key = Key::new(0, 0);
    ROUTING.get(&key).copied()
}
