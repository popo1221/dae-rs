//! Hash algorithms for node selection
//!
//! This module provides two hash algorithms used for consistent hashing
//! and sticky session policies:
//!
//! - [`Fnv1aHasher`]: FNV-1a (Fowler–Noll–Vo) hash algorithm
//! - [`SipHasher`]: SipHash-2-4 algorithm (Rust DefaultHasher)
//!
//! # FNV-1a
//!
//! FNV-1a is a non-cryptographic hash function designed for fast hashing.
//! It has good distribution properties and is suitable for hash tables.
//!
//! # SipHash
//!
//! SipHash-2-4 is a cryptographically keyed hash function that provides
//! protection against hash flooding attacks. Rust's `DefaultHasher` uses
//! SipHash by default.

use std::hash::{Hash, Hasher};

/// FNV-1a hasher for 64-bit hashes
///
/// FNV-1a (Fowler–Noll–Vo) is a non-cryptographic hash function.
/// Reference: <https://www.ietf.org/rfc/rfc7693.txt>
///
/// # Algorithm
///
/// ```ignore
/// hash = offset_basis
/// for each byte b:
///     hash = hash XOR b
///     hash = hash * FNV_prime
/// ```
///
/// # Constants (64-bit)
///
/// - offset_basis: 14695981039346656037
/// - FNV_prime: 1099511628211
#[derive(Debug, Clone, Default)]
pub struct Fnv1aHasher {
    /// Current hash value
    hash: u64,
}

impl Fnv1aHasher {
    /// Create a new FNV-1a hasher with the initial offset basis
    pub fn new() -> Self {
        Self {
            hash: FNV_OFFSET_BASIS_64,
        }
    }
}

impl Hasher for Fnv1aHasher {
    fn write(&mut self, bytes: &[u8]) {
        // FNV-1a: hash = (hash XOR byte) * FNV_prime
        for &b in bytes {
            self.hash ^= b as u64;
            self.hash = self.hash.wrapping_mul(FNV_PRIME_64);
        }
    }

    fn finish(&self) -> u64 {
        self.hash
    }
}

/// SipHash-2-4 hasher (wrapper around Rust's DefaultHasher)
///
/// This is a convenience wrapper that explicitly documents we're using
/// SipHash-2-4 via Rust's DefaultHasher.
#[derive(Debug, Clone, Default)]
pub struct SipHasher {
    inner: std::collections::hash_map::DefaultHasher,
}

impl SipHasher {
    /// Create a new SipHasher
    pub fn new() -> Self {
        Self {
            inner: std::collections::hash_map::DefaultHasher::new(),
        }
    }
}

impl Hasher for SipHasher {
    fn write(&mut self, bytes: &[u8]) {
        self.inner.write(bytes);
    }

    fn finish(&self) -> u64 {
        self.inner.finish()
    }
}

/// FNV-1a offset basis for 64-bit hash
const FNV_OFFSET_BASIS_64: u64 = 14695981039346656037;

/// FNV-1a prime for 64-bit hash
const FNV_PRIME_64: u64 = 1099511628211;

/// Compute FNV-1a hash of a value
pub fn fnv1a_hash<T: Hash>(value: &T) -> u64 {
    let mut hasher = Fnv1aHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Compute SipHash of a value
pub fn sip_hash<T: Hash>(value: &T) -> u64 {
    let mut hasher = SipHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1a_empty_string() {
        // FNV-1a("") = offset_basis = 14695981039346656037 = 0xCBF29CE484222325
        let empty: &[u8] = &[];
        let mut hasher = Fnv1aHasher::new();
        hasher.write(empty);
        assert_eq!(hasher.finish(), 0xCBF29CE484222325);
    }

    #[test]
    fn test_fnv1a_vs_siphash_different() {
        // FNV-1a and SipHash should produce different outputs
        let data = b"hello world";
        let fnv = {
            let mut h = Fnv1aHasher::new();
            h.write(data);
            h.finish()
        };
        let sip = {
            let mut h = SipHasher::new();
            h.write(data);
            h.finish()
        };
        // They should be different (very high probability)
        assert_ne!(fnv, sip, "FNV-1a and SipHash should produce different hashes");
    }

    #[test]
    fn test_fnv1a_deterministic() {
        let data = b"test connection fingerprint";
        let h1 = {
            let mut hasher = Fnv1aHasher::new();
            hasher.write(data);
            hasher.finish()
        };
        let h2 = {
            let mut hasher = Fnv1aHasher::new();
            hasher.write(data);
            hasher.finish()
        };
        assert_eq!(h1, h2, "FNV-1a should be deterministic");
    }

    #[test]
    fn test_fnv1a_one_bit_change() {
        // Small change in input should produce very different output (avalanche property)
        let mut d1 = [0u8; 8];
        let mut d2 = [0u8; 8];
        d2[3] = 1;

        let h1 = {
            let mut hasher = Fnv1aHasher::new();
            hasher.write(&d1);
            hasher.finish()
        };
        let h2 = {
            let mut hasher = Fnv1aHasher::new();
            hasher.write(&d2);
            hasher.finish()
        };

        // At least half the bits should differ (avalanche)
        let diff = h1 ^ h2;
        let bits_set = diff.count_ones();
        assert!(
            bits_set >= 20,
            "Avalanche property: only {}/64 bits differ, expected >=20",
            bits_set
        );
    }

    #[test]
    fn test_hash_functions() {
        let value = "test";
        assert_eq!(fnv1a_hash(&value), {
            let mut h = Fnv1aHasher::new();
            value.hash(&mut h);
            h.finish()
        });
        assert_eq!(sip_hash(&value), {
            let mut h = SipHasher::new();
            value.hash(&mut h);
            h.finish()
        });
    }

    #[test]
    fn test_u8_slice_hash() {
        let data = [1u8, 2, 3, 4, 5];
        let mut h1 = Fnv1aHasher::new();
        h1.write(&data);
        let h1_result = h1.finish();

        // Should match byte-by-byte hashing
        let mut h2 = Fnv1aHasher::new();
        for &b in &data {
            h2.write_u8(b);
        }
        assert_eq!(h1_result, h2.finish());
    }
}
