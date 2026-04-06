//! dae-protocol-tuic 协议处理器 crate
//!
//! 从 dae-proxy 提取的 TUIC 协议处理器。
//!
//! # TUIC 协议简介
//!
//! TUIC 是一个基于 QUIC 的代理协议，设计用于高性能和低延迟。
//! 支持 UDP 代理、连接多路复用和拥塞控制。
//!
//! # 主要导出
//!
//! - `TuicCodec`: 协议消息编解码器
//! - `TuicConfig`: 配置结构
//! - `TuicError`: 错误类型
//! - `TuicServer`: 服务器实现
//! - `TuicClient`: 客户端实现
//! - `TuicHandler`: 协议处理器
//! - `TuicCommand`: 命令类型
//! - `TuicCommandType`: 命令类型枚举

pub mod tuic;

// Re-exports from the tuic module
pub use tuic::{
    TuicClient, TuicCodec, TuicCommand, TuicCommandType, TuicConfig, TuicError, TuicHandler,
    TuicServer,
};
