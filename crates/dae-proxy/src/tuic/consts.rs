//! TUIC protocol constants and types

/// TUIC protocol version
pub const TUIC_VERSION: u8 = 0x05;

/// TUIC command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TuicCommandType {
    /// Authentication command
    Auth = 0x01,
    /// Connect command (TCP)
    Connect = 0x02,
    /// Disconnect command
    Disconnect = 0x03,
    /// Heartbeat command
    Heartbeat = 0x04,
    /// UDP packet command
    UdpPacket = 0x05,
}

impl TuicCommandType {
    /// Parse command type from u8
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(TuicCommandType::Auth),
            0x02 => Some(TuicCommandType::Connect),
            0x03 => Some(TuicCommandType::Disconnect),
            0x04 => Some(TuicCommandType::Heartbeat),
            0x05 => Some(TuicCommandType::UdpPacket),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// TUIC protocol error
#[derive(Debug, thiserror::Error)]
pub enum TuicError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid protocol: {0}")]
    InvalidProtocol(String),

    #[error("Invalid command: {0}")]
    InvalidCommand(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("QUIC error: {0}")]
    Quic(String),

    #[error("Timeout")]
    Timeout,

    #[error("Not connected")]
    NotConnected,
}
