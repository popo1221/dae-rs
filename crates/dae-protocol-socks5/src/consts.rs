//! SOCKS5 协议常量定义模块（RFC 1928）
//!
//! 定义 SOCKS5 协议使用的所有常量。

/// SOCKS5 协议版本号
pub const VER: u8 = 0x05;

/// 认证方法：无需认证
pub const NO_AUTH: u8 = 0x00;

/// 认证方法：GSSAPI 认证
#[allow(dead_code)]
pub const GSSAPI: u8 = 0x01;

/// 认证方法：用户名/密码认证
pub const USERNAME_PASSWORD: u8 = 0x02;

/// 认证方法：无可接受的认证方法
pub const NO_ACCEPTABLE: u8 = 0xFF;

/// 命令：CONNECT - 请求连接到目标服务器
pub const CMD_CONNECT: u8 = 0x01;

/// 命令：BIND - 请求服务器绑定地址并等待连接
pub const CMD_BIND: u8 = 0x02;

/// 命令：UDP ASSOCIATE - 请求建立 UDP 代理
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// 地址类型：IPv4 地址（4字节）
pub const ATYP_IPV4: u8 = 0x01;

/// 地址类型：域名（1字节长度 + 域名）
pub const ATYP_DOMAIN: u8 = 0x03;

/// 地址类型：IPv6 地址（16字节）
pub const ATYP_IPV6: u8 = 0x04;

/// 回复码：成功
pub const REP_SUCCESS: u8 = 0x00;

/// 回复码：常规失败
pub const REP_GENERAL_FAILURE: u8 = 0x01;

/// 回复码：连接不允许（ACL 规则）
pub const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;

/// 回复码：网络不可达
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;

/// 回复码：主机不可达
pub const REP_HOST_UNREACHABLE: u8 = 0x04;

/// 回复码：连接被拒绝
pub const REP_CONNECTION_REFUSED: u8 = 0x05;

/// 回复码：TTL 过期
pub const REP_TTL_EXPIRED: u8 = 0x06;

/// 回复码：命令不支持
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;

/// 回复码：地址类型不支持
pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
