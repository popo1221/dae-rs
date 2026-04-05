//! VLESS crypto utilities
//!
//! Cryptographic functions used by VLESS protocol.

/// Compute HMAC-SHA256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    let mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    let result = mac.chain_update(data).finalize();
    result.into_bytes().into()
}
