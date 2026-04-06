//! dae-ebpf-direct - Direct Socket 模式的 eBPF 程序
//!
//! 本 crate 实现 Direct Socket（直接套接字）模式的 eBPF 程序，
//! 实现了真正的内核级透明代理，无需 iptables 或 XDP/TC 层面拦截数据包。
//!
//! # 核心优势
//!
//! 与传统 iptables + XDP/TC 方案相比，Direct Socket 有以下优势：
//! - **零数据包截获**：直接在 socket 层处理，不经过网络栈的包处理
//! - **零拷贝**：通过 sockmap 直接重定向消息，避免包拷贝开销
//! - **支持 TCP 重传**：由内核透明处理，无需代理实现复杂 TCP 逻辑
//! - **cgroup 隔离**：基于 cgroup 绑定，可精确控制哪些进程的流量走代理
//!
//! # 架构图
//!
//! ```text
//! 用户进程（Browser/App）
//!      │
//!      │ 发起 TCP 连接（connect）
//!      ▼
//! +------------------+
//! |   内核 TCP 栈    |
//! +------------------+
//!      │
//!      │ 触发 sock_ops 钩子
//!      ▼
//! +------------------+
//! |  sock_ops eBPF   | ◄── 记录连接信息到 CONNECTIONS
//! +------------------+    添加 socket 到 SOCKMAP
//!      │
//!      ▼
//! +------------------+
//! |   代理进程        | ◄── sk_msg 从 SOCKMAP 获取 socket
//! +------------------+    重定向消息
//! ```
//!
//! # 两种 eBPF 程序
//!
//! ## sock_ops（挂载类型：BPF_PROG_TYPE_SOCK_OPS）
//!
//! 挂载在 cgroup 层级，拦截 TCP socket 操作：
//! - `BPF_SOCK_OPS_TCP_CONNECT_CB`：TCP 连接发起时
//! - `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB`：客户端连接建立时
//! - `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`：服务端接受连接时
//! - `BPF_SOCK_OPS_STATE_CB`：TCP 状态变化时
//!
//! 主要职责：
//! 1. 记录连接 5 元组到 CONNECTIONS HashMap
//! 2. 查询 DIRECT_ROUTES 判断是否需要代理
//! 3. 将需要代理的 socket 添加到 SOCKMAP
//!
//! ## sk_msg（挂载类型：BPF_PROG_TYPE_SK_MSG）
//!
//! 挂载在 SOCKMAP 上，拦截 socket 消息：
//! - `sk_msg_out`：拦截外出消息，重定向到代理
//! - `sk_msg_in`：拦截代理返回消息，重定向到原 socket
//!
//! # 关键 eBPF Map
//!
//! | Map 名称       | 类型        | Key                      | Value        | 用途                     |
//! |--------------|-------------|--------------------------|--------------|--------------------------|
//! | CONNECTIONS  | HashMap     | ConnKey (5元组)         | ConnValue    | 连接跟踪                 |
//! | SOCKMAP_OUT  | SockMap     | fd (socket fd)          | socket       | 外出消息重定向           |
//! | SOCKMAP_IN   | SockMap     | fd (socket fd)          | socket       | 归来消息重定向           |
//! | SOCKHASH     | SockHash    | ConnKey (5元组)         | socket       | 按 5 元组查找 socket    |
//! | DIRECT_ROUTES| HashMap    | u32 (目标 IP)           | DirectRouteEntry | 直连路由规则         |

#![no_std]
#![deny(warnings)]
// Allow strict clippy lints for eBPF code patterns
#![allow(clippy::field_reassign_with_default)]
#![allow(dead_code)]

use aya_ebpf::bindings::{
    BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, BPF_SOCK_OPS_NEEDS_ECN, BPF_SOCK_OPS_PARSE_HDR_OPT_CB,
    BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB, BPF_SOCK_OPS_RTO_CB, BPF_SOCK_OPS_RTT_CB,
    BPF_SOCK_OPS_RWND_INIT, BPF_SOCK_OPS_STATE_CB, BPF_SOCK_OPS_TCP_CONNECT_CB,
    BPF_SOCK_OPS_TCP_LISTEN_CB, BPF_SOCK_OPS_TIMEOUT_INIT, BPF_SOCK_OPS_VOID,
    BPF_SOCK_OPS_WRITE_HDR_OPT_CB, BPF_TCP_BOUND_INACTIVE, BPF_TCP_CLOSE, BPF_TCP_CLOSE_WAIT,
    BPF_TCP_CLOSING, BPF_TCP_ESTABLISHED, BPF_TCP_FIN_WAIT1, BPF_TCP_FIN_WAIT2, BPF_TCP_LAST_ACK,
    BPF_TCP_LISTEN, BPF_TCP_NEW_SYN_RECV, BPF_TCP_SYN_RECV, BPF_TCP_SYN_SENT, BPF_TCP_TIME_WAIT,
};
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::macros::{map, sk_msg, sock_ops};
use aya_ebpf::maps::{HashMap, SockHash, SockMap};
use aya_ebpf::programs::{SkMsgContext, SockOpsContext};

use dae_ebpf_common::direct::{rule_type, DirectRouteEntry};

// ============================================================================
// Constants
// ============================================================================

/// TCP 协议号
const IPPROTO_TCP: u8 = 6;

/// IPv4 地址族
const AF_INET: u32 = 2;

// ============================================================================
// Types
// ============================================================================

/// 连接跟踪键（Connection Tracking Key）
///
/// 使用 5 元组唯一标识一个 TCP 连接，用于：
/// - `CONNECTIONS` HashMap 的键
/// - `SOCKHASH` 的键
///
/// # 5 元组组成
///
/// - `src_ip`：源 IP（网络字节序）
/// - `dst_ip`：目标 IP（网络字节序）
/// - `src_port`：源端口（主机字节序）
/// - `dst_port`：目标端口（主机字节序）
/// - `protocol`：协议号（当前仅支持 TCP=6）
/// - `_padding`：对齐填充（1 字节，置零）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ConnKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    _padding: u8,
}

impl ConnKey {
    /// 从原始值创建连接键
    ///
    /// # 参数
    ///
    /// * `src_ip` - 源 IP（网络字节序）
    /// * `dst_ip` - 目标 IP（网络字节序）
    /// * `src_port` - 源端口（主机字节序）
    /// * `dst_port` - 目标端口（主机字节序）
    /// * `protocol` - 协议号（6=TCP）
    ///
    /// # 返回值
    ///
    /// 新的 ConnKey 实例
    pub fn new(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            _padding: 0,
        }
    }

    /// 从 sock_ops 上下文创建连接键（仅 TCP）
    ///
    /// 从 TCP socket 操作事件中提取 5 元组信息。
    ///
    /// # 参数
    ///
    /// * `ctx` - SockOps 上下文
    ///
    /// # 返回值
    ///
    /// - `Some(ConnKey)`：成功提取，返回连接键
    /// - `None`：非 IPv4 TCP 连接，忽略
    ///
    /// # 安全说明
    ///
    /// `ctx.family()`、`ctx.local_port()` 等字段访问由 Aya 框架保证安全。
    /// 端口转换：socket API 中端口存储在 u32 的高 16 位，网络字节序。
    pub fn from_sock_ops(ctx: &SockOpsContext) -> Option<Self> {
        let family = ctx.family();
        // 当前仅支持 IPv4（AF_INET = 2）
        if family != AF_INET {
            return None;
        }

        // 端口存储在 u32 的高 16 位，网络字节序（大端）
        let local_port_raw = ctx.local_port();
        let remote_port_raw = ctx.remote_port();
        // 从高 16 位提取端口，并转换为主机字节序
        let src_port = u16::from_be((local_port_raw >> 16) as u16);
        let dst_port = u16::from_be((remote_port_raw >> 16) as u16);

        Some(Self::new(
            ctx.local_ip4(),
            ctx.remote_ip4(),
            src_port,
            dst_port,
            IPPROTO_TCP,
        ))
    }

    /// 从 sk_msg 上下文创建连接键
    ///
    /// 从 socket 消息事件中提取 5 元组信息。
    ///
    /// # 参数
    ///
    /// * `ctx` - SkMsg 上下文
    ///
    /// # 返回值
    ///
    /// - `Some(ConnKey)`：成功提取
    /// - `None`：非 IPv4 连接
    ///
    /// # Safety
    ///
    /// - `ctx.msg` 是指向 `sk_msg_md` 结构的有效指针
    /// - BPF 验证器保证在程序执行期间该指针始终有效
    /// - 字段解引用安全，因为 Aya 框架已验证边界
    pub fn from_sk_msg(ctx: &SkMsgContext) -> Option<Self> {
        // SAFETY: ctx.msg 是指向 sk_msg_md 的有效指针，验证器保证有效
        let family = unsafe { (*ctx.msg).family };
        if family != AF_INET {
            return None;
        }

        let local_port_raw = unsafe { (*ctx.msg).local_port };
        let remote_port_raw = unsafe { (*ctx.msg).remote_port };
        let src_port = u16::from_be((local_port_raw >> 16) as u16);
        let dst_port = u16::from_be((remote_port_raw >> 16) as u16);

        Some(Self::new(
            unsafe { (*ctx.msg).local_ip4 },
            unsafe { (*ctx.msg).remote_ip4 },
            src_port,
            dst_port,
            IPPROTO_TCP,
        ))
    }
}

/// 连接跟踪值（Connection Tracking Value）
///
/// 存储已跟踪连接的元数据，包括进程 ID、连接状态和路由标记。
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ConnValue {
    /// Process ID that owns this connection
    pub pid: u32,
    /// TCP connection state
    pub state: u32,
    /// Routing mark (0 = undecided, 1 = direct, 2 = proxy)
    pub mark: u8,
    /// Reserved for alignment
    _reserved: [u8; 3],
}

impl ConnValue {
    /// 创建新的连接值
    ///
    /// # 参数
    ///
    /// * `pid` - 拥有该连接的进程 ID
    ///
    /// # 返回值
    ///
    /// 新建 ConnValue，`state=0`，`mark=0`（未决定）
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            state: 0,
            mark: 0,
            _reserved: [0; 3],
        }
    }
}

// ============================================================================
// eBPF Maps
// ============================================================================

/// 连接跟踪 Map
///
/// 类型：HashMap<ConnKey, ConnValue>
/// 容量：65536 条
///
/// # 用途
///
/// 存储活跃 TCP 连接的元数据，供 sock_ops 和 sk_msg 共享：
/// - sock_ops 写入：新建连接、状态变化时写入
/// - sk_msg 读取：消息拦截时查询，判断是否需要重定向
#[map]
static CONNECTIONS: HashMap<ConnKey, ConnValue> = HashMap::with_max_entries(65536, 0);

/// SockMap（外出消息重定向）
///
/// sock_ops 将需要代理的 socket 添加到本 Map；
/// sk_msg_out 通过本 Map 查找 socket 并重定向消息。
///
/// # 重定向流程
///
/// 1. sock_ops 在连接建立时将 socket fd 添加到 SOCKMAP_OUT
/// 2. 进程发送数据时，sk_msg_out 拦截消息
/// 3. sk_msg_out 调用 `redirect_msg` 将消息重定向到 SOCKMAP_OUT 中记录的 proxy socket
#[map]
static SOCKMAP_OUT: SockMap = SockMap::with_max_entries(65536, 0);

/// SockMap（入站消息重定向）
///
/// 用于 sk_msg_in，拦截代理进程的返回消息，重定向回原始 socket。
#[map]
static SOCKMAP_IN: SockMap = SockMap::with_max_entries(65536, 0);

/// SockHash（5 元组到 socket 的映射）
///
/// 与 SOCKMAP 类似，但使用 Hash 而非 SockMap：
/// - 键：ConnKey（5 元组）
/// - 值：socket
///
/// 适用于需要按 5 元组精确查找 socket 的场景。
#[map]
static SOCKHASH: SockHash<ConnKey> = SockHash::with_max_entries(65536, 0);

/// 直连路由规则 Map
///
/// 类型：HashMap<u32, DirectRouteEntry>
/// 容量：65536 条
///
/// # 用途
///
/// 存储直连路由规则：
/// - 键：目标 IP 地址（网络字节序）
/// - 值：DirectRouteEntry（规则类型 + 数据）
///
/// # 规则类型
///
/// - `DIRECT_RULE_IPV4_CIDR`：IPv4 CIDR 规则
/// - `DIRECT_RULE_PORT`：端口规则
/// - `DIRECT_RULE_DOMAIN_SUFFIX`：域名后缀规则
/// - `DIRECT_RULE_PROCESS`：进程名规则
#[map]
static DIRECT_ROUTES: HashMap<u32, DirectRouteEntry> = HashMap::with_max_entries(65536, 0);

// ============================================================================
// sock_ops Program
// ============================================================================

/// sock_ops 程序入口点
///
/// 挂载在 cgroup_sock_ops 上，拦截 TCP socket 操作。
/// 记录连接信息供后续 sk_msg 程序使用。
///
/// # 钩子点（通过 `op()` 值区分）
///
/// | op 值 | 名称                          | 触发时机                      |
/// |-------|-------------------------------|-------------------------------|
/// | 0     | VOID                           | 空回调，不做任何事             |
/// | 1     | TIMEOUT_INIT                   | 初始化连接超时                 |
/// | 2     | RWND_INIT                      | 初始化接收窗口                 |
/// | 3     | TCP_CONNECT_CB                 | 发起 TCP 连接（客户端）        |
/// | 4     | ACTIVE_ESTABLISHED_CB          | 主动端连接建立完成             |
/// | 5     | PASSIVE_ESTABLISHED_CB         | 被动端连接建立完成             |
/// | 6     | NEEDS_ECN                      | 查询连接是否需要 ECN           |
/// | 8     | RTO_CB                         | RTO 计时器触发                 |
/// | 10    | STATE_CB                       | TCP 状态变化                   |
/// | 11    | TCP_LISTEN_CB                  | TCP 进入 LISTEN 状态           |
/// | 12    | RTT_CB                         | RTT（往返时间）变化            |
/// | 13    | PARSE_HDR_OPT_CB               | 解析 TCP 头部选项              |
/// | 15    | WRITE_HDR_OPT_CB               | 写入 TCP 头部选项              |
///
/// # 参数
///
/// * `ctx` - SockOps 上下文，包含 socket 操作详情
///
/// # 返回值
///
/// 始终返回 1（成功），允许内核继续处理。返回 0 会终止内核处理。
///
/// # Safety
///
/// - 本函数由内核调用，`ctx` 指针由内核保证有效
/// - 内部通过 `sock_ops_prog` 分发到具体处理器
/// - BPF 验证器确保本程序不会越界访问内存
#[sock_ops]
pub fn sock_ops_main(ctx: SockOpsContext) -> u32 {
    sock_ops_prog(&ctx).unwrap_or(1)
}

/// sock_ops 主逻辑 - 根据 op 值分发到具体处理器
///
/// # 参数
///
/// * `ctx` - SockOps 上下文
///
/// # 返回值
///
/// `Ok(u32)`：处理成功（大部分返回 1）
/// `Err(())`：解析失败（返回 1，允许内核继续）
fn sock_ops_prog(ctx: &SockOpsContext) -> Result<u32, ()> {
    let op = ctx.op();

    match op {
        BPF_SOCK_OPS_VOID => Ok(1),
        BPF_SOCK_OPS_TIMEOUT_INIT => handle_timeout_init(ctx),
        BPF_SOCK_OPS_RWND_INIT => Ok(1), // Let kernel set rwnd
        BPF_SOCK_OPS_TCP_CONNECT_CB => handle_tcp_connect(ctx),
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB => handle_active_established(ctx),
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => handle_passive_established(ctx),
        BPF_SOCK_OPS_NEEDS_ECN => Ok(0), // No ECN by default
        BPF_SOCK_OPS_RTO_CB => handle_rto_cb(ctx),
        BPF_SOCK_OPS_STATE_CB => handle_state_change(ctx),
        BPF_SOCK_OPS_TCP_LISTEN_CB => handle_listen(ctx),
        BPF_SOCK_OPS_RTT_CB => handle_rtt_update(ctx),
        BPF_SOCK_OPS_PARSE_HDR_OPT_CB => Ok(1),
        BPF_SOCK_OPS_WRITE_HDR_OPT_CB => Ok(1),
        _ => Ok(1),
    }
}

/// 处理超时初始化 - 记录新连接
///
/// 在 TCP 连接超时初始化时，将连接 5 元组记录到 CONNECTIONS Map。
///
/// # 处理逻辑
///
/// 1. 从 `ctx` 提取连接 5 元组
/// 2. 获取当前进程 PID
/// 3. 创建 ConnValue 并插入 CONNECTIONS HashMap
///
/// # Safety
///
/// `CONNECTIONS.insert` 需要 unsafe 块，但由 BPF 验证器保证安全
fn handle_timeout_init(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    let pid = bpf_get_current_pid_tgid() as u32;
    let value = ConnValue::new(pid);
    let _ = CONNECTIONS.insert(&key, &value, 0);

    Ok(1)
}

/// Handle TCP connect initiated
/// 处理 TCP 连接发起
///
/// 在客户端调用 `connect()` 发起 TCP 连接时触发。
///
/// # 处理逻辑
///
/// 1. 提取连接 5 元组
/// 2. 查询 DIRECT_ROUTES 判断目标是否需要直连
/// 3. 若标记为直连（mark=1），将 socket 添加到 SOCKMAP_OUT
/// 4. 记录连接信息到 CONNECTIONS
///
/// # 直连判断
///
/// - 规则类型 `DIRECT_RULE_IPV4_CIDR`：目标 IP 匹配 CIDR 规则
/// - 规则类型 `DIRECT_RULE_PORT`：目标端口匹配端口规则
///
/// # Safety
///
/// - `ctx.ops` 指针在程序执行期间有效（验证器保证）
/// - `DIRECT_ROUTES.get` 返回后解引用安全（条目始终有效）
/// - `SOCKMAP_OUT.update` 是 unsafe 操作，但由验证器保证安全
fn handle_tcp_connect(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    let pid = bpf_get_current_pid_tgid() as u32;

    // Check routing rules to determine if this should be direct or proxied
    let dst_ip = key.dst_ip;
    let mut value = ConnValue::new(pid);

    // SAFETY: ctx.ops is a valid pointer for the duration of this program.
    // The verifier ensures this.
    unsafe {
        if let Some(route) = DIRECT_ROUTES.get(&dst_ip) {
            match route.rule_type {
                rule_type::DIRECT_RULE_IPV4_CIDR => {
                    if (*route).matches_ipv4(dst_ip) {
                        value.mark = 1; // Direct
                    }
                }
                rule_type::DIRECT_RULE_PORT => {
                    if (*route).matches_port(key.dst_port, key.protocol) {
                        value.mark = 1; // Direct
                    }
                }
                _ => {}
            }
        }
    }

    // If marked for direct, add socket to sockmap
    if value.mark == 1 {
        // SAFETY: update requires unsafe because map operations are unsafe.
        // The sock_ops pointer is valid for the duration of this program.
        let _ = unsafe { SOCKMAP_OUT.update(0, ctx.ops, 0) };
    }

    let _ = CONNECTIONS.insert(&key, &value, 0);

    Ok(1)
}

/// 处理主动端（客户端）连接建立完成
///
/// 在三次握手完成后，客户端侧触发此回调。
///
/// # 处理逻辑
///
/// 1. 提取连接 5 元组和当前状态
/// 2. 再次检查路由规则（可能在 TCP_CONNECT 时未决定）
/// 3. 若仍未标记，尝试直连判断
/// 4. 更新 CONNECTIONS 中的连接状态
fn handle_active_established(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    let state = get_tcp_state(ctx);
    let mut value = ConnValue::new(bpf_get_current_pid_tgid() as u32);
    value.state = state;

    // Check routing rules
    let dst_ip = key.dst_ip;

    // SAFETY: ctx.ops is valid; map operations require unsafe blocks.
    unsafe {
        if let Some(route) = DIRECT_ROUTES.get(&dst_ip) {
            if route.rule_type == rule_type::DIRECT_RULE_IPV4_CIDR && (*route).matches_ipv4(dst_ip)
            {
                value.mark = 1; // Direct
                                // Add to sockmap for redirect
                let _ = SOCKMAP_OUT.update(0, ctx.ops, 0);
            } else if route.rule_type == rule_type::DIRECT_RULE_PORT
                && (*route).matches_port(key.dst_port, key.protocol)
            {
                value.mark = 1; // Direct
                let _ = SOCKMAP_OUT.update(0, ctx.ops, 0);
            }
        }
    }

    let _ = CONNECTIONS.insert(&key, &value, 0);

    Ok(1)
}

/// 处理被动端（服务端）连接建立完成
///
/// 在三次握手完成后，服务端侧接受连接时触发。
///
/// # 处理逻辑
///
/// 服务端接受连接，记录连接状态为 ESTABLISHED。
/// 服务端连接通常不需要代理侧处理直连逻辑。
fn handle_passive_established(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    let mut value = ConnValue::new(0);
    value.state = BPF_TCP_ESTABLISHED;

    let _ = CONNECTIONS.insert(&key, &value, 0);

    Ok(1)
}

/// 处理 RTO（重传超时）回调
///
/// TCP 重传超时计时器触发时刷新连接跟踪。
///
/// # 处理逻辑
///
/// 1. 获取当前连接状态
/// 2. 更新 CONNECTIONS 中的连接条目
/// 3. 保持 PID 信息（用于识别发起连接的进程）
fn handle_rto_cb(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    // Refresh the connection entry
    let mut value = ConnValue::new(bpf_get_current_pid_tgid() as u32);
    value.state = get_tcp_state(ctx);

    let _ = CONNECTIONS.insert(&key, &value, 0);

    Ok(1)
}

/// 处理 TCP 状态变化回调
///
/// 监听 TCP 连接的状态转换事件，管理连接生命周期。
///
/// # 状态处理
///
/// | 状态                       | 处理逻辑                                           |
/// |---------------------------|--------------------------------------------------|
/// | SYN_SENT                  | 新连接发起，记录 PID 和状态                        |
/// | SYN_RECV                  | 服务端收到 SYN，记录状态                           |
/// | ESTABLISHED               | 连接建立完成，尝试直连判断，必要时加入 SOCKMAP    |
/// | FIN_WAIT1/2, CLOSE_WAIT   | 连接关闭中，更新状态                              |
/// | TIME_WAIT/CLOSE/CLOSING/LAST_ACK | 连接关闭，从 CONNECTIONS 移除          |
/// | LISTEN                    | 服务端开始监听，记录 PID                          |
/// | NEW_SYN_RECV              | 收到新 SYN（同时打开）                           |
/// | BOUND_INACTIVE            | socket 绑定到非活跃地址                           |
///
/// # Safety
///
/// - `CONNECTIONS.get/insert/remove` 操作均为 unsafe，但由验证器保证安全
fn handle_state_change(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    let state = get_tcp_state(ctx);

    match state {
        BPF_TCP_SYN_SENT => {
            let mut value = ConnValue::new(bpf_get_current_pid_tgid() as u32);
            value.state = state;
            let _ = CONNECTIONS.insert(&key, &value, 0);
        }
        BPF_TCP_SYN_RECV => {
            let mut value = ConnValue::default();
            // SAFETY: ctx.ops is valid; map get requires unsafe.
            if let Some(existing) = unsafe { CONNECTIONS.get(&key) } {
                value = *existing;
            }
            value.state = state;
            let _ = CONNECTIONS.insert(&key, &value, 0);
        }
        BPF_TCP_ESTABLISHED => {
            let mut value = ConnValue::default();
            // SAFETY: ctx.ops is valid; map get requires unsafe.
            if let Some(existing) = unsafe { CONNECTIONS.get(&key) } {
                value = *existing;
            }
            value.state = state;
            // Re-check routing on established
            let dst_ip = key.dst_ip;
            if value.mark == 0 {
                // SAFETY: ctx.ops is valid.
                unsafe {
                    if let Some(route) = DIRECT_ROUTES.get(&dst_ip) {
                        if route.rule_type == rule_type::DIRECT_RULE_IPV4_CIDR
                            && (*route).matches_ipv4(dst_ip)
                        {
                            value.mark = 1;
                            let _ = SOCKMAP_OUT.update(0, ctx.ops, 0);
                        }
                    }
                }
            }
            let _ = CONNECTIONS.insert(&key, &value, 0);
        }
        BPF_TCP_FIN_WAIT1 | BPF_TCP_FIN_WAIT2 | BPF_TCP_CLOSE_WAIT => {
            let mut value = ConnValue::default();
            // SAFETY: ctx.ops is valid.
            if let Some(existing) = unsafe { CONNECTIONS.get(&key) } {
                value = *existing;
            }
            value.state = state;
            let _ = CONNECTIONS.insert(&key, &value, 0);
        }
        BPF_TCP_TIME_WAIT | BPF_TCP_CLOSE | BPF_TCP_CLOSING | BPF_TCP_LAST_ACK => {
            // Connection closing - clean up tracking
            let _ = CONNECTIONS.remove(&key);
            // SOCKHASH.update requires a key to remove - we use the connection key
            // But SockHash doesn't have remove, so we just remove from CONNECTIONS
        }
        BPF_TCP_LISTEN => {
            let mut value = ConnValue::new(bpf_get_current_pid_tgid() as u32);
            value.state = state;
            let _ = CONNECTIONS.insert(&key, &value, 0);
        }
        BPF_TCP_NEW_SYN_RECV => {
            let mut value = ConnValue::new(0);
            value.state = state;
            let _ = CONNECTIONS.insert(&key, &value, 0);
        }
        BPF_TCP_BOUND_INACTIVE => {
            let mut value = ConnValue::default();
            // SAFETY: ctx.ops is valid.
            if let Some(existing) = unsafe { CONNECTIONS.get(&key) } {
                value = *existing;
            }
            value.state = state;
            let _ = CONNECTIONS.insert(&key, &value, 0);
        }
        _ => {}
    }

    Ok(1)
}

/// 处理 TCP 监听回调
///
/// 当 socket 进入 LISTEN 状态（开始监听连接）时触发。
/// 记录监听 socket 的 PID 和状态。
///
/// # 用途
///
/// 用于追踪哪个进程在监听端口，辅助分类来自该进程的连接。
fn handle_listen(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    let mut value = ConnValue::new(bpf_get_current_pid_tgid() as u32);
    value.state = BPF_TCP_LISTEN;
    let _ = CONNECTIONS.insert(&key, &value, 0);

    Ok(1)
}

/// 处理 RTT（往返时间）更新回调
///
/// 当 TCP 连接的 RTT 估计值变化时触发。
/// 将当前 RTT（srtt_us）存储到 ConnValue.pid 字段用于监控。
///
/// # 注意
///
/// - 将 `srtt_us`（平滑往返时间，微秒）存储到 `pid` 字段是一种数据复用
/// - 这样做可以监控 RTT 而不需要额外的 Map
/// - `pid` 字段在监听 socket 场景下使用，RTT 监控不会与之冲突
fn handle_rtt_update(ctx: &SockOpsContext) -> Result<u32, ()> {
    let key = match ConnKey::from_sock_ops(ctx) {
        Some(k) => k,
        None => return Ok(1),
    };

    // Update connection with latest RTT metrics
    // SAFETY: ctx.ops is valid; accessing srtt_us field is safe.
    let srtt = unsafe { (*ctx.ops).srtt_us };

    let mut value = ConnValue::default();
    // SAFETY: ctx.ops is valid.
    if let Some(existing) = unsafe { CONNECTIONS.get(&key) } {
        value = *existing;
    }

    // Store srtt in pid field for monitoring (repurpose field)
    value.pid = srtt;

    let _ = CONNECTIONS.insert(&key, &value, 0);

    Ok(1)
}

/// 从 sock_ops 上下文获取 TCP 状态
///
/// # 返回值
///
/// TCP 连接当前状态（BPF_TCP_* 常量）
///
/// # Safety
///
/// - `ctx.ops` 指针由内核保证有效
/// - 字段访问在 BPF 验证器的边界检查下安全
fn get_tcp_state(ctx: &SockOpsContext) -> u32 {
    // SAFETY: ctx.ops is a valid pointer for the duration of the program.
    // The verifier ensures the pointer is valid and the field access is within bounds.
    unsafe { (*ctx.ops).state }
}

// ============================================================================
// sk_msg Program
// ============================================================================

/// sk_msg 程序入口点（外出消息重定向）
///
/// 挂载到 SOCKMAP_OUT 上，拦截已标记 socket 的外出消息。
/// 消息直接重定向到代理进程，无需经过内核网络栈。
///
/// # 参数
///
/// * `ctx` - SkMsg 上下文，包含消息详情
///
/// # 返回值
///
/// - `>= 0`：重定向成功（返回 BPF action 值）
/// - `< 0`：重定向失败（返回 0，交给内核处理）
///
/// # 处理流程
///
/// 1. 从 `ctx` 提取连接 5 元组
/// 2. 查询 CONNECTIONS，判断是否需要重定向
/// 3. 若 mark=1（直连），通过 SOCKMAP_OUT.redirect_msg 重定向到代理
#[sk_msg]
pub fn sk_msg_out(ctx: SkMsgContext) -> u32 {
    sk_msg_prog_out(&ctx).unwrap_or(1)
}

/// sk_msg 程序入口点（入站消息重定向）
///
/// 挂载到 SOCKMAP_IN 上，拦截来自代理进程的返回消息。
/// 将代理的回复消息重定向回原始接收 socket。
#[sk_msg]
pub fn sk_msg_in(ctx: SkMsgContext) -> u32 {
    sk_msg_prog_in(&ctx).unwrap_or(1)
}

/// sk_msg 主逻辑（外出消息）
///
/// 拦截从本机外出到目标服务器的消息。
/// 若连接标记为需要代理（mark=1），则通过 SOCKMAP 重定向到代理 socket。
///
/// # 参数
///
/// * `ctx` - SkMsg 上下文
///
/// # 返回值
///
/// - `Ok(u32)`：重定向成功或不需要重定向（透传）
/// - `Err(())`：解析失败，交给内核处理
fn sk_msg_prog_out(ctx: &SkMsgContext) -> Result<u32, ()> {
    // Look up the connection key for this message
    let key = match ConnKey::from_sk_msg(ctx) {
        Some(k) => k,
        None => return Ok(0), // Unknown connection - don't redirect
    };

    // Check if this connection should be redirected
    // SAFETY: ctx.msg is valid; map get requires unsafe.
    if let Some(value) = unsafe { CONNECTIONS.get(&key) } {
        if value.mark == 1 {
            // Marked for direct - redirect via sockmap to proxy
            // Index 0 is used for the proxy socket in our design
            // SAFETY: redirect_msg is unsafe due to raw pointer access.
            let ret = unsafe { SOCKMAP_OUT.redirect_msg(ctx, 0, 0) };
            // Return >= 0 means success (BPF action result)
            if ret >= 0 {
                return Ok(ret as u32);
            }
        }
    }

    // Not in redirect map - pass to kernel
    Ok(0)
}

/// sk_msg 主逻辑（入站消息）
///
/// 拦截从代理进程返回的消息，将其重定向回原始的 socket。
/// 通过 SOCKMAP_IN.redirect_msg 实现零拷贝消息传递。
///
/// # Safety
///
/// `redirect_msg` 是 unsafe 操作，但由 BPF 验证器保证安全。
fn sk_msg_prog_in(ctx: &SkMsgContext) -> Result<u32, ()> {
    // Similar to outbound - redirect via inbound sockmap
    // SAFETY: redirect_msg is unsafe.
    let ret = unsafe { SOCKMAP_IN.redirect_msg(ctx, 0, 0) };
    if ret >= 0 {
        return Ok(ret as u32);
    }

    Ok(0)
}

// ============================================================================
// Utilities
// ============================================================================

/// 从原始组件创建连接键（便捷函数）
///
/// # 参数
///
/// * `src_ip` - 源 IP（网络字节序）
/// * `dst_ip` - 目标 IP（网络字节序）
/// * `src_port` - 源端口（主机字节序）
/// * `dst_port` - 目标端口（主机字节序）
/// * `protocol` - 协议号
///
/// # 返回值
///
/// 新的 ConnKey 实例
#[allow(dead_code)]
pub fn conn_key_from_parts(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
) -> ConnKey {
    ConnKey::new(src_ip, dst_ip, src_port, dst_port, protocol)
}

/// 检查 IP 是否匹配 CIDR 路由规则
///
/// 用于 Direct Route 模式下的快速 IP 匹配判断。
///
/// # 参数
///
/// * `ip` - 待检查的 IP 地址（主机字节序）
/// * `cidr_ip` - CIDR 规则的基 IP（主机字节序）
/// * `prefix_len` - CIDR 前缀长度（0-32）
///
/// # 返回值
///
/// - `true`：IP 匹配该 CIDR 规则
/// - `false`：IP 不匹配
///
/// # 算法
///
/// 对 IP 和 CIDR 基地址应用前缀掩码后比较：
/// - `prefix_len=0`：匹配所有 IP（返回 true）
/// - `prefix_len>32`：无效前缀（返回 false）
/// - 否则：`(ip & mask) == (cidr_ip & mask)`
#[allow(dead_code)]
pub fn ip_matches_cidr(ip: u32, cidr_ip: u32, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 32 {
        return false;
    }

    let mask = !0u32 << (32 - prefix_len);
    (ip & mask) == (cidr_ip & mask)
}
