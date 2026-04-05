//! TUIC 协议模块
//!
//! TUIC 是一个基于 QUIC 的代理协议。
//! 提供高效的 UDP 代理功能，支持以下命令类型：
//!
//! - 认证 (Auth)
//! - 连接 (Connect)
//! - 断开连接 (Disconnect)
//! - 心跳 (Heartbeat)
//! - UDP 数据包 (UdpPacket)
//!
//! # 子模块
//!
//! - `codec`: TUIC 协议消息的编解码器
//! - `tuic_impl`: TUIC 协议核心实现

pub mod codec;
pub mod tuic_impl;

// Re-exports for convenience
pub use codec::TuicCodec;
pub use tuic_impl::{TuicCommand, TuicClient, TuicCommandType, TuicConfig, TuicError, TuicHandler, TuicServer};
