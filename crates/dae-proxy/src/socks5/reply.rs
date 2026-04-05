//! SOCKS5 reply types (RFC 1928)
//!
//! Reply codes returned to clients after request processing.

use super::consts;

/// SOCKS5 reply type
#[derive(Debug, Clone, Copy)]
pub enum Socks5Reply {
    Success,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl Socks5Reply {
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
