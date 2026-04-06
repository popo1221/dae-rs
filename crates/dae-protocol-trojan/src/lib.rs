//! dae-protocol-trojan crate
//!
//! Trojan 协议处理器，从 dae-proxy 中提取的独立模块。
//!
//! # 协议说明
//! Trojan 是一种基于 TLS 的代理协议，客户端将请求伪装成正常的 HTTPS 流量。
//! 协议特点：
//! - 使用 TLS 1.3 加密传输
//! - 密码+CRLF 作为协议头部分隔符
//! - 支持 TCP 直连和 UDP 转发
//! - 支持 Trojan-Go 扩展（WebSocket 传输）
//!
//! # 架构
//! - `config`: 配置类型（服务器/客户端/TLS 配置）
//! - `types`: 共享类型和 trait 定义
//! - `protocol`: Trojan 协议层面的数据类型和解析
//! - `handler`: 客户端处理器，实现连接处理逻辑
//! - `server`: 服务端，监听和处理连接
//! - `trojan_go`: Trojan-Go 协议扩展（WebSocket 支持）
//!
//! # 使用示例
//! ```ignore
//! use dae_protocol_trojan::{TrojanHandler, TrojanClientConfig};
//! let config = TrojanClientConfig::default();
//! let handler = Arc::new(TrojanHandler::new(config));
//! ```

pub mod config;
pub mod errors;
pub mod handler;
pub mod protocol;
pub mod server;
pub mod trojan_go;
pub mod types;

// 重新导出公共类型供外部使用
pub use config::{TrojanClientConfig, TrojanServerConfig, TrojanTlsConfig};
pub use handler::TrojanHandler;
pub use errors::TrojanError;
pub use protocol::{TrojanAddressType, TrojanCommand, TrojanTargetAddress};
pub use server::TrojanServer;
pub use trojan_go::{TrojanGoMode, TrojanGoWsConfig, TrojanGoWsHandler, TrojanGoWsStream};
