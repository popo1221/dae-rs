//! Juicity 协议处理器模块
//!
//! 为 dae-rs 实现 Juicity 协议支持。
//! Juicity 是一个为高性能设计的 UDP 代理协议。
//!
//! 协议参考: https://github.com/juicity/juicity
//!
//! # 协议流程
//!
//! 客户端 -> dae-rs (Juicity 客户端) -> 远程 Juicity 服务器 -> 目标
//!
//! # 主要特性
//!
//! - 基于 UDP 的低延迟通信
//! - 支持 BBR/CUBIC/Reno 拥塞控制
//! - 基于令牌的身份验证
//! - 连接 ID 和会话 ID 用于多路复用

mod codec;
mod juicity;
mod types;

pub use codec::JuicityCodec;
pub use juicity::{
    CongestionControl, JuicityClient, JuicityConfig, JuicityConnection, JuicityError,
    JuicityHandler, JuicityServer,
};
pub use types::{JuicityAddress, JuicityCommand, JuicityFrame};
