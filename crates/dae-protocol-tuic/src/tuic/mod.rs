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

pub mod codec;
pub mod consts;
pub mod server;
pub mod client;
pub mod tuic_impl;

// Re-exports for convenience
pub use codec::TuicCodec;
pub use consts::{
    Context, ProxyResult, TuicCommand, TuicCommandType, TuicError, TUIC_VERSION,
    TuicAuthRequest, TuicConnectRequest, TuicHeartbeatRequest,
};
pub use server::{TuicServer, TuicSession};
pub use client::{TuicClient, TuicClientSession};
pub use tuic_impl::{TuicConfig, TuicHandler};
