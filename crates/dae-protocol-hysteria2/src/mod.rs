//! Hysteria2 协议处理器模块
//!
//! 实现了 Hysteria2 协议的核心功能：
//! - Hysteria2 配置管理
//! - 客户端/服务器消息处理
//! - 密码认证
//! - UDP 数据报中继

mod errors;

#[allow(clippy::module_inception)]
pub mod hysteria2;
pub mod quic;

pub use errors::Hysteria2Error;
pub use hysteria2::{Hysteria2Config, Hysteria2Handler, Hysteria2Server};
