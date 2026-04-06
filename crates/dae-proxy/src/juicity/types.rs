//! Juicity types module
//!
//! Contains error types and enums for the Juicity protocol.

/// Juicity protocol error types
#[derive(Debug, thiserror::Error)]
pub enum JuicityError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid header")]
    InvalidHeader,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Connection not found: {0}")]
    ConnectionNotFound(u32),

    #[error("Session expired")]
    SessionExpired,

    #[error("Timeout")]
    Timeout,

    #[error("Protocol error: {0}")]
    Protocol(String),
}

impl From<tokio::time::error::Elapsed> for JuicityError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        JuicityError::Timeout
    }
}

/// Congestion control algorithms supported by Juicity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionControl {
    /// BBR congestion control
    Bbr,
    /// CUBIC congestion control
    Cubic,
    /// Reno congestion control
    Reno,
}

impl CongestionControl {
    /// Parse from string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "bbr" => Some(CongestionControl::Bbr),
            "cubic" => Some(CongestionControl::Cubic),
            "reno" => Some(CongestionControl::Reno),
            _ => None,
        }
    }

    /// Convert to protocol byte
    pub fn to_byte(self) -> u8 {
        match self {
            CongestionControl::Bbr => 0x01,
            CongestionControl::Cubic => 0x02,
            CongestionControl::Reno => 0x03,
        }
    }
}
