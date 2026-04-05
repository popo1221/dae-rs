//! dae-protocol-socks5 crate
//!
//! SOCKS5 protocol handler extracted from dae-proxy.

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
