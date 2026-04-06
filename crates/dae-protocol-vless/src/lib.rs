//! VLESS 协议处理器 for dae-rs
//!
//! 本模块实现 VLESS 协议及其 XTLS Reality 传输支持。
//!
//! # 协议说明
//! VLESS 是一种无状态的 VPN 协议，使用 TLS/XTLS 传输。
//! 协议特点：
//! - 无状态设计，无需维护连接状态
//! - 支持 XTLS Reality Vision 流量伪装
//! - 支持多路复用和 UDP 转发
//! - 使用 UUID 进行用户认证
//!
//! # 版本支持
//! - VLESS 协议版本: 0x01
//! - 支持 XTLS Reality Vision（用于深度包检测对抗）
//!
//! # 架构
//! - `config`: 配置类型（服务器/客户端/TLS/Reality 配置）
//! - `crypto`: 加密工具函数（HMAC-SHA256）
//! - `protocol`: 协议数据类型和解析
//! - `handler`: 协议处理器（TCP/UDP/Reality Vision）
//! - `server`: 服务器，监听和处理连接
//!
//! # 使用示例
//! ```ignore
//! use dae_protocol_vless::{VlessHandler, VlessClientConfig};
//! let config = VlessClientConfig::default();
//! let handler = Arc::new(VlessHandler::new(config));
//! ```

pub mod config;
pub mod crypto;
pub mod errors;
pub mod handler;
pub mod protocol;
pub mod server;
pub mod tls;

// 协议类型
pub use protocol::{
    VlessAddressType, VlessCommand, VlessTargetAddress, VLESS_HEADER_MIN_SIZE,
    VLESS_REQUEST_HEADER_SIZE, VLESS_VERSION,
};

// 配置
pub use config::{VlessClientConfig, VlessRealityConfig, VlessServerConfig, VlessTlsConfig};

// 处理器
pub use handler::VlessHandler;

// 错误类型
pub use errors::VlessError;

// 服务器
pub use server::VlessServer;

// 加密
pub use crypto::hmac_sha256;

// 数据转发（来自 dae-relay）
pub use dae_relay::relay_bidirectional;

use tokio::net::TcpStream;

/// 在客户端和远程之间转发数据
///
/// 这是一个包装函数，提供 VLESS 特定的数据转发接口，
/// 内部调用 `dae_relay::relay_bidirectional` 实现高效转发。
///
/// # 参数
/// - `client`: 客户端 TCP 连接
/// - `remote`: 远程服务器 TCP 连接
///
/// # 返回
/// - `Ok(())`: 转发完成
/// - `Err(std::io::Error)`: 转发失败
pub async fn relay_data(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
    relay_bidirectional(client, remote).await
}
