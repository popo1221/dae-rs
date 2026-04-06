//! Trojan protocol constants
//!
//! Contains constants used in the Trojan protocol implementation.

/// Maximum UDP frame size
pub const MAX_UDP_FRAME_SIZE: usize = 65535;

/// Trojan UDP frame header size (cmd + uuid + ver + port + atyp = 1 + 16 + 1 + 2 + 1)
pub const TROJAN_UDP_HEADER_SIZE: usize = 21;

/// Trojan UDP command: UDP data packet
pub const TROJAN_UDP_CMD_DATA: u8 = 0x01;
/// Trojan UDP command: disconnect
pub const TROJAN_UDP_CMD_DISCONNECT: u8 = 0x02;
/// Trojan UDP command: ping (keepalive)
pub const TROJAN_UDP_CMD_PING: u8 = 0x03;
/// Trojan UDP protocol version
pub const TROJAN_UDP_VERSION: u8 = 0x01;
