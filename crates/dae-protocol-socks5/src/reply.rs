//! SOCKS5 回复类型模块（RFC 1928）
//!
//! 定义 SOCKS5 服务器返回给客户端的响应码。

use super::consts;

/// SOCKS5 回复类型
///
/// 定义 SOCKS5 服务器返回给客户端的响应状态码。
#[derive(Debug, Clone, Copy)]
pub enum Socks5Reply {
    /// 成功，连接已建立或请求已被接受
    Success,
    /// 常规失败
    GeneralFailure,
    /// 连接不允许（ACL 规则拒绝）
    ConnectionNotAllowed,
    /// 网络不可达
    NetworkUnreachable,
    /// 主机不可达
    HostUnreachable,
    /// 连接被拒绝（目标服务器拒绝连接）
    ConnectionRefused,
    /// TTL 过期
    TtlExpired,
    /// 命令不支持
    CommandNotSupported,
    /// 地址类型不支持
    AddressTypeNotSupported,
}

impl Socks5Reply {
    /// 转换为字节值
    ///
    /// # 返回值
    /// - 0x00: Success
    /// - 0x01: GeneralFailure
    /// - 0x02: ConnectionNotAllowed
    /// - 0x03: NetworkUnreachable
    /// - 0x04: HostUnreachable
    /// - 0x05: ConnectionRefused
    /// - 0x06: TtlExpired
    /// - 0x07: CommandNotSupported
    /// - 0x08: AddressTypeNotSupported
    pub fn to_u8(self) -> u8 {
        match self {
            Socks5Reply::Success => consts::REP_SUCCESS,
            Socks5Reply::GeneralFailure => consts::REP_GENERAL_FAILURE,
            Socks5Reply::ConnectionNotAllowed => consts::REP_CONNECTION_NOT_ALLOWED,
            Socks5Reply::NetworkUnreachable => consts::REP_NETWORK_UNREACHABLE,
            Socks5Reply::HostUnreachable => consts::REP_HOST_UNREACHABLE,
            Socks5Reply::ConnectionRefused => consts::REP_CONNECTION_REFUSED,
            Socks5Reply::TtlExpired => consts::REP_TTL_EXPIRED,
            Socks5Reply::CommandNotSupported => consts::REP_COMMAND_NOT_SUPPORTED,
            Socks5Reply::AddressTypeNotSupported => consts::REP_ADDRESS_TYPE_NOT_SUPPORTED,
        }
    }

    /// 从 IO 错误转换为对应的回复码
    ///
    /// 根据 IO 错误的类型，选择最合适的 SOCKS5 回复码。
    ///
    /// # 参数
    /// - `e`: IO 错误引用
    ///
    /// # 映射关系
    ///
    /// - ConnectionRefused → ConnectionRefused
    /// - HostUnreachable → HostUnreachable
    /// - NetworkUnreachable → NetworkUnreachable
    /// - TimedOut → TtlExpired
    /// - 其他 → GeneralFailure
    pub fn from_io_error(e: &std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::ConnectionRefused => Socks5Reply::ConnectionRefused,
            std::io::ErrorKind::HostUnreachable => Socks5Reply::HostUnreachable,
            std::io::ErrorKind::NetworkUnreachable => Socks5Reply::NetworkUnreachable,
            std::io::ErrorKind::TimedOut => Socks5Reply::TtlExpired,
            _ => Socks5Reply::GeneralFailure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_reply_to_u8() {
        assert_eq!(Socks5Reply::Success.to_u8(), 0x00);
        assert_eq!(Socks5Reply::GeneralFailure.to_u8(), 0x01);
        assert_eq!(Socks5Reply::ConnectionRefused.to_u8(), 0x05);
    }

    #[test]
    fn test_socks5_reply_all_variants() {
        assert_eq!(Socks5Reply::Success.to_u8(), 0x00);
        assert_eq!(Socks5Reply::GeneralFailure.to_u8(), 0x01);
        assert_eq!(Socks5Reply::ConnectionNotAllowed.to_u8(), 0x02);
        assert_eq!(Socks5Reply::NetworkUnreachable.to_u8(), 0x03);
        assert_eq!(Socks5Reply::HostUnreachable.to_u8(), 0x04);
        assert_eq!(Socks5Reply::ConnectionRefused.to_u8(), 0x05);
        assert_eq!(Socks5Reply::TtlExpired.to_u8(), 0x06);
        assert_eq!(Socks5Reply::CommandNotSupported.to_u8(), 0x07);
        assert_eq!(Socks5Reply::AddressTypeNotSupported.to_u8(), 0x08);
    }
}
