//! dae-protocol-trojan 共享类型模块
//!
//! 本模块提供 Trojan 处理器所需的共享类型和 trait 定义，
//! 包括协议类型枚举、处理器配置 trait 和双向数据转发 trait。
//!
//! # 类型层次
//! - `ProtocolType`: 标识支持的协议类型（目前仅有 Trojan）
//! - `HandlerConfig`: 处理器配置 trait，所有配置类型需实现此 trait
//! - `BidirectionalRelay`: 双向数据转发 trait

use tokio::net::TcpStream;

/// 协议类型枚举
///
/// 标识当前处理器实现的协议类型。
/// 用于协议识别和路由决策。
///
/// # 变体
/// - `Trojan`: Trojan 协议
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    Trojan,
}

impl std::fmt::Display for ProtocolType {
    /// 将协议类型格式化为字符串表示
    ///
    /// # 返回值
    /// - `Trojan` -> `"trojan"`
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolType::Trojan => write!(f, "trojan"),
        }
    }
}

/// 处理器配置 trait
///
/// 所有协议处理器的配置类型必须实现此 trait。
/// 该 trait 要求实现类型满足 `Send + Sync + Debug`，
/// 确保配置可以在多线程环境中安全共享。
///
/// # 设计目的
/// - 统一不同协议处理器的配置接口
/// - 允许运行时动态获取处理器配置
/// - 支持配置的热更新（通过 Arc<dyn HandlerConfig>）
pub trait HandlerConfig: Send + Sync + std::fmt::Debug {}

/// 双向数据转发 trait
///
/// 提供客户端与远程服务器之间的双向数据转发能力。
/// 默认实现使用 `dae_relay::relay_bidirectional` 函数，
/// 实现高效的异步双向数据传递。
///
/// # 方法
/// - `relay_stream(client, remote)`: 在客户端和远程连接之间转发数据
///
/// # 实现说明
/// - 默认实现调用 `dae_relay::relay_bidirectional`
/// - 适用于 TCP 流量的透明代理场景
#[allow(async_fn_in_trait)]
pub trait BidirectionalRelay: Send + Sync {
    /// 在客户端和远程 TCP 流之间进行双向数据转发
    ///
    /// # 参数
    /// - `client`: 客户端 TCP 连接
    /// - `remote`: 远程服务器 TCP 连接
    ///
    /// # 返回值
    /// - 成功时返回 `Ok(())`
    /// - 失败时返回 `std::io::Result<()>`
    ///
    /// # 实现细节
    /// - 使用 `tokio::io::copy_bidirectional` 实现高效转发
    /// - 双向同时进行，不分先后顺序
    /// - 任一方向出错都会终止整个转发
    async fn relay_stream(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
        dae_relay::relay_bidirectional(client, remote).await
    }
}

// 重新导出 relay_bidirectional 函数
// 允许外部模块直接使用 dae_relay 中的高效转发实现
pub use dae_relay::relay_bidirectional;
