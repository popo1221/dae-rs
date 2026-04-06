//! dae-protocol-socks4 crate
//!
//! SOCKS4/SOCKS4a 协议处理器，从 dae-proxy 中提取。
//!
//! # SOCKS4 协议简介
//!
//! SOCKS4 是一种基于 TCP 的代理协议，工作在 OSI 模型的应用层和传输层之间。
//! 它允许客户端通过代理服务器转发 TCP 连接，而无需了解目标服务器的详细信息。
//!
//! # SOCKS4 vs SOCKS4a
//!
//! | 特性 | SOCKS4 | SOCKS4a |
//! |------|--------|---------|
//! | IPv6 支持 | ❌ 仅 IPv4 | ❌ 仅 IPv4 |
//! | 域名支持 | ❌ | ✅ 通过特殊标记 |
//! | 认证 | 简单 user ID | 简单 user ID |
//!
//! # SOCKS4a 域名支持机制
//!
//! 当 DST.IP 的前三个字节为 0.0.0 且第四个字节非零时，
//! 表示这是一个 SOCKS4a 请求，后续会有一个以 null 结尾的域名。
//!
//! # 支持的命令
//!
//! - `CONNECT`: 建立到目标服务器的 TCP 连接
//! - `BIND`: 等待远程服务器发起连接（用于 FTP 等协议）
//!
//! # 端口限制
//!
//! SOCKS4 协议规范中，连接目标的端口号不能为 0。
//!
//! # 模块结构
//!
//! - `error`: 错误类型定义
//! - `handler`: 服务器处理逻辑
//! - `protocol`: 协议常量和类型
//! - `request`: 请求解析和响应处理

mod error;
mod handler;
mod protocol;
mod request;

pub use error::Socks4Error;
pub use handler::{Socks4Config, Socks4Server};
pub use protocol::{Socks4Address, Socks4Command, Socks4Reply};
pub use request::Socks4Request;
