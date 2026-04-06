//! eBPF error types

use thiserror::Error;

/// Error type for eBPF operations
#[derive(Error, Debug)]
pub enum EbpfError {
    #[error("Map not found: {0}")]
    MapNotFound(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Update failed: {0}")]
    UpdateFailed(String),
    #[error("Lookup failed: {0}")]
    LookupFailed(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("eBPF not available: {0}")]
    EbpfNotAvailable(String),
    #[error("Kernel version not supported: {0}")]
    KernelNotSupported(String),
    #[error("Other error: {0}")]
    Other(String),
}

impl From<std::io::Error> for EbpfError {
    fn from(e: std::io::Error) -> Self {
        EbpfError::Other(e.to_string())
    }
}

impl From<aya::EbpfError> for EbpfError {
    fn from(e: aya::EbpfError) -> Self {
        EbpfError::Other(e.to_string())
    }
}

impl From<aya::maps::MapError> for EbpfError {
    fn from(e: aya::maps::MapError) -> Self {
        EbpfError::Other(e.to_string())
    }
}

impl From<aya::programs::ProgramError> for EbpfError {
    fn from(e: aya::programs::ProgramError) -> Self {
        EbpfError::Other(e.to_string())
    }
}

/// Result type for eBPF operations
pub type Result<T> = std::result::Result<T, EbpfError>;
