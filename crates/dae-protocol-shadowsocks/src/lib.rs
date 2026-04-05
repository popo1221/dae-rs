//! dae-protocol-shadowsocks crate
//!
//! Shadowsocks AEAD 协议处理器，从 dae-proxy 中提取。
//!
//! # 支持的协议
//!
//! - **Shadowsocks AEAD**: 标准的 AEAD 加密方式的 Shadowsocks 流量
//! - **Shadowsocks SSR**: 带有协议混淆的 ShadowsocksR 协议
//! - **simple-obfs**: HTTP/TLS 混淆插件，使流量看起来像普通 HTTP 或 TLS
//! - **v2ray-plugin**: WebSocket 传输混淆插件，支持 TLS
//!
//! # AEAD 加密算法支持
//!
//! - `chacha20-ietf-poly1305` (推荐)
//! - `aes-256-gcm`
//! - `aes-128-gcm`
//!
//! # 注意事项
//!
//! 流式加密算法（如 rc4-md5、aes-ctr、aes-cfb 等）暂不支持。
//!
//! # 模块结构
//!
//! - `config`: 服务器和客户端配置结构
//! - `handler`: ss-local 侧连接处理器
//! - `server`: 服务器监听和连接管理
//! - `protocol`: 协议类型定义和地址解析
//! - `aead`: AEAD 加密算法实现
//! - `ssr`: ShadowsocksR 协议实现
//! - `plugin`: 混淆插件（obfs 和 v2ray-plugin）

pub mod aead;
pub mod config;
pub mod handler;
pub mod plugin;
pub mod protocol;
pub mod server;
pub mod ssr;

// Re-export all public types from submodules
pub use config::{SsClientConfig, SsServerConfig};
pub use handler::ShadowsocksHandler;
pub use plugin::{
    ObfsConfig, ObfsHttp, ObfsMode, ObfsStream, ObfsTls, V2rayConfig, V2rayMode, V2rayPlugin,
    V2rayStream,
};
pub use protocol::{SsCipherType, TargetAddress};
pub use server::ShadowsocksServer;
pub use ssr::{SsrClientConfig, SsrHandler, SsrObfs, SsrObfsHandler, SsrProtocol, SsrServerConfig};

// Re-export relay from dae-relay for backward compatibility
pub use dae_relay::relay_bidirectional;
