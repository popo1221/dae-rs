//! VMess 协议处理器 for dae-rs
//!
//! 本模块实现 VMess AEAD 协议支持。
//!
//! # 协议说明
//! VMess 是 V2Ray 项目使用的无状态 VPN 协议。
//! 本实现支持 VMess-AEAD-2022，这是最新版本的 VMess 协议。
//!
//! # 协议特点
//! - 无状态设计
//! - 支持 AEAD 加密（VMess-AEAD-2022）
//! - 使用 AES-256-GCM 加密
//! - 基于 HMAC-SHA256 的密钥派生
//!
//! # VMess-AEAD-2022
//! 新版本协议使用 AEAD 进行头部加密，相比旧版本：
//! - 更高的安全性
//! - 更好的防重放攻击能力
//! - 需要 16 字节 nonce + 密文 + 16 字节认证标签
//!
//! # 架构
//! - `config`: 配置类型（服务器/客户端/目标地址）
//! - `protocol`: 协议常量、命令类型、安全类型
//! - `handler`: 协议处理器
//! - `server`: 服务器
//!
//! # 使用示例
//! ```ignore
//! use dae_protocol_vmess::{VmessHandler, VmessClientConfig};
//! let config = VmessClientConfig::default();
//! let handler = Arc::new(VmessHandler::new(config));
//! ```

pub mod config;
pub mod handler;
pub mod protocol;
pub mod server;

// 重新导出公共类型
pub use config::{VmessClientConfig, VmessTargetAddress};
pub use handler::VmessHandler;
pub use protocol::{VmessAddressType, VmessCommand, VmessSecurity, VmessServerConfig};
pub use server::VmessServer;

// 协议常量
pub use protocol::{VMESS_AEAD_VERSION, VMESS_VERSION};
