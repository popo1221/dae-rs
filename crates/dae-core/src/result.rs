//! Result type alias for dae-rs

use crate::error::Error;

/// Result type alias using dae_core::Error
pub type Result<T> = std::result::Result<T, Error>;
