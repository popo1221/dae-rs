//! Result type alias for dae-proxy
//!
//! This module provides a centralized Result type alias using the unified Error type.

use crate::core::error::Error;

/// Result type alias using dae-proxy's unified Error type
pub type Result<T> = std::result::Result<T, Error>;
