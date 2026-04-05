//! dae-protocol-socks5 crate
//!
//! SOCKS5 协议处理器，从 dae-proxy 中提取。
//!
//! # SOCKS5 协议简介
//!
//! SOCKS5 是 SOCKS 协议的第五版，是一种基于 TCP 的代理协议。
//! 与 SOCKS4 不同，SOCKS5 支持 IPv6 和域名地址，以及多种认证方式。
//!
//! # 与 SOCKS4 的主要区别
//!
//! | 特性 | SOCKS4 | SOCKS5 |
//! |------|--------|--------|
//! | IPv6 支持 | ❌ | ✅ |
//! | 域名支持 | ❌（SOCKS4a 扩展） | ✅ |
//! | 认证机制 | 仅 user ID | 多种认证机制 |
//! | UDP 关联 | ❌ | ✅ |
//!
//! # SOCKS5 工作流程（三个阶段）
//!
//! ## 阶段 1：认证方法协商
//!
//! 客户端发送：
//! ```
//! |VER | NMETHODS | METHODS  |
//! | 1  |    1     |  1-255   |
//! ```
//!
//! 服务器响应：
//! ```
//! |VER | METHOD |
//! | 1  |   1    |
//! ```
//!
//! ## 阶段 2：认证（可选）
//!
//! 如果选择了用户名/密码认证，则进行认证流程。
//!
//! ## 阶段 3：请求处理
//!
//! 客户端发送请求：
//! ```
//! |VER | CMD | RSV | ATYP |  DST.ADDR   |  DST.PORT   |
//! | 1  |  1  |  1  |  1   | Variable   |      2      |
//! ```
//!
//! # 支持的地址类型（ATYP）
//!
//! - 0x01: IPv4 地址（4字节）
//! - 0x03: 域名（1字节长度 + 域名）
//! - 0x04: IPv6 地址（16字节）
//!
//! # 支持的认证方法
//!
//! - 0x00: NO_AUTH（无需认证）
//! - 0x01: GSSAPI
//! - 0x02: USERNAME_PASSWORD
//! - 0xFF: NO_ACCEPTABLE（无可接受的方法）
//!
//! # 模块结构
//!
//! - `address`: SOCKS5 地址解析
//! - `auth`: 认证处理器
//! - `commands`: 命令处理
//! - `handshake`: 握手和问候
//! - `reply`: 响应类型

mod address;
pub mod auth;
pub mod commands;
mod consts;
mod error;
pub mod handler;
pub mod handshake;
pub mod reply;

// Re-export types for convenience
pub use address::Socks5Address;
pub use auth::{
    AuthHandler, CombinedAuthHandler, NoAuthHandler, UserCredentials, UsernamePasswordHandler,
};
pub use commands::{CommandHandler, Socks5Command};
pub use consts::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_BIND, CMD_CONNECT, CMD_UDP_ASSOCIATE, GSSAPI,
    NO_ACCEPTABLE, NO_AUTH, REP_ADDRESS_TYPE_NOT_SUPPORTED, REP_COMMAND_NOT_SUPPORTED,
    REP_CONNECTION_NOT_ALLOWED, REP_CONNECTION_REFUSED, REP_GENERAL_FAILURE, REP_HOST_UNREACHABLE,
    REP_NETWORK_UNREACHABLE, REP_SUCCESS, REP_TTL_EXPIRED, USERNAME_PASSWORD, VER,
};
pub use error::Socks5Error;
pub use handler::{Socks5Handler, Socks5HandlerConfig, Socks5Server};
pub use reply::Socks5Reply;

// Re-export relay from dae-relay for backward compatibility
pub use dae_relay::relay_bidirectional;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_command_from_u8() {
        assert!(matches!(
            Socks5Command::from_u8(0x01),
            Some(Socks5Command::Connect)
        ));
        assert!(matches!(
            Socks5Command::from_u8(0x03),
            Some(Socks5Command::UdpAssociate)
        ));
        assert!(Socks5Command::from_u8(0xFF).is_none());
    }

    #[test]
    fn test_socks5_command_all_variants() {
        assert!(matches!(
            Socks5Command::from_u8(0x01),
            Some(Socks5Command::Connect)
        ));
        assert!(matches!(
            Socks5Command::from_u8(0x02),
            Some(Socks5Command::Bind)
        ));
        assert!(matches!(
            Socks5Command::from_u8(0x03),
            Some(Socks5Command::UdpAssociate)
        ));
        assert!(Socks5Command::from_u8(0x00).is_none());
        assert!(Socks5Command::from_u8(0x04).is_none());
        assert!(Socks5Command::from_u8(0xFF).is_none());
    }

    #[test]
    fn test_socks5_consts() {
        assert_eq!(VER, 0x05);
        assert_eq!(NO_AUTH, 0x00);
        assert_eq!(USERNAME_PASSWORD, 0x02);
        assert_eq!(CMD_CONNECT, 0x01);
        assert_eq!(ATYP_IPV4, 0x01);
        assert_eq!(ATYP_DOMAIN, 0x03);
        assert_eq!(ATYP_IPV6, 0x04);
        assert_eq!(REP_SUCCESS, 0x00);
    }

    #[test]
    fn test_socks5_handler_config_default() {
        let config = Socks5HandlerConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("Socks5HandlerConfig"));
    }
}
