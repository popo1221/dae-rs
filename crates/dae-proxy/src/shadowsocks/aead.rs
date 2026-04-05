//! Shadowsocks AEAD encryption implementation
//!
//! This module provides AEAD cipher implementations for Shadowsocks.
//!
//! # Supported Ciphers
//!
//! - chacha20-ietf-poly1305
//! - aes-256-gcm
//! - aes-128-gcm
//!
//! # Note
//!
//! Full AEAD encryption/decryption is not yet implemented.
//! See GitHub Issue #78 for details.

use super::protocol::SsCipherType;

/// AEAD cipher result type
pub type AeadResult<T> = Result<T, AeadError>;

/// AEAD cipher error types
#[derive(Debug)]
pub enum AeadError {
    /// Invalid key length
    InvalidKeyLength,
    /// Invalid nonce length
    InvalidNonceLength,
    /// Encryption failed
    EncryptionFailed,
    /// Decryption failed
    DecryptionFailed,
    /// Authentication tag verification failed
    TagVerificationFailed,
}

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AeadError::InvalidKeyLength => write!(f, "invalid key length"),
            AeadError::InvalidNonceLength => write!(f, "invalid nonce length"),
            AeadError::EncryptionFailed => write!(f, "encryption failed"),
            AeadError::DecryptionFailed => write!(f, "decryption failed"),
            AeadError::TagVerificationFailed => write!(f, "authentication tag verification failed"),
        }
    }
}

impl std::error::Error for AeadError {}

/// AEAD cipher trait
pub trait AeadCipher: Send + Sync {
    /// Get the cipher type
    fn cipher_type(&self) -> SsCipherType;

    /// Get the key length
    fn key_len(&self) -> usize;

    /// Get the nonce length
    fn nonce_len(&self) -> usize;

    /// Encrypt data
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        tag: &mut [u8],
    ) -> AeadResult<Vec<u8>>;

    /// Decrypt data
    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> AeadResult<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_error_display() {
        let err = AeadError::InvalidKeyLength;
        assert_eq!(format!("{}", err), "invalid key length");
    }
}
