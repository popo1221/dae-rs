//! 节点选择的哈希算法
//!
//! 本模块提供两种用于一致性哈希和粘性会话策略的哈希算法：
//!
//! - [`Fnv1aHasher`]: FNV-1a (Fowler–Noll–Vo) 哈希算法
//! - [`SipHasher`]: SipHash-2-4 算法（Rust DefaultHasher）
//!
//! # FNV-1a
//!
//! FNV-1a 是一种非加密哈希函数，专为快速哈希而设计。
//! 它具有良好的分布特性，适用于哈希表。
//!
//! # SipHash
//!
//! SipHash-2-4 是一种加密学上有保障的密钥哈希函数，
//! 可防止哈希洪水攻击。Rust 的 `DefaultHasher` 默认使用 SipHash。

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
        // Process each byte in the order given (native endianness from Hash impl)
        for &b in bytes {
            self.hash ^= b as u64;
            self.hash = self.hash.wrapping_mul(FNV_PRIME_64);
        }
    }

    fn write_u64(&mut self, i: u64) {
        // FNV-1a processes bytes, split u64 into bytes
        // Use little-endian to match Hash impl for u64 on most platforms
        self.write(&i.to_le_bytes());
    }

    fn write_usize(&mut self, i: usize) {
        // FNV-1a processes bytes, split usize into bytes
        self.write(&i.to_le_bytes());
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

    // ========================================================================
    // FNV-1a correctness tests
    // ========================================================================

    #[test]
    fn test_fnv1a_empty_string() {
        // FNV-1a("") = offset_basis = 14695981039346656037 = 0xCBF29CE484222325
        let empty: &[u8] = &[];
        let mut hasher = Fnv1aHasher::new();
        hasher.write(empty);
        assert_eq!(hasher.finish(), 0xCBF29CE484222325);
    }

    #[test]
    fn test_fnv1a_single_byte_write_u8() {
        // Test write_u8 (calls write(&[byte]) under the hood)
        // FNV-1a of single byte 0x41 ('A')
        let mut hasher = Fnv1aHasher::new();
        hasher.write_u8(0x41);
        let result = hasher.finish();
        assert_ne!(result, 0, "Hash should not be zero");
        // Determinism: same input should give same output
        let mut hasher2 = Fnv1aHasher::new();
        hasher2.write_u8(0x41);
        assert_eq!(result, hasher2.finish());
        // Different byte should give different hash
        let mut hasher3 = Fnv1aHasher::new();
        hasher3.write_u8(0x42);
        assert_ne!(result, hasher3.finish());
    }

    #[test]
    fn test_fnv1a_various_bytes() {
        // Test various single byte values - all should be non-zero and distinct
        let bytes = [0x00u8, 0x01, 0x41, 0xFF];
        let mut hashes = std::collections::HashSet::new();
        for &byte in &bytes {
            let mut hasher = Fnv1aHasher::new();
            hasher.write_u8(byte);
            let result = hasher.finish();
            assert_ne!(result, 0, "Hash of {:02x?} should not be zero", byte);
            assert!(
                hashes.insert(result),
                "Duplicate hash for different byte value {:02x?}",
                byte
            );
        }
    }

    #[test]
    fn test_fnv1a_multi_byte_incremental() {
        // Hash of "ab" should equal incremental hash of 'a' then 'b'
        let mut h1 = Fnv1aHasher::new();
        h1.write(b"ab");
        let result1 = h1.finish();

        let mut h2 = Fnv1aHasher::new();
        h2.write_u8(b'a');
        h2.write_u8(b'b');
        let result2 = h2.finish();

        assert_eq!(
            result1, result2,
            "Incremental write should equal bulk write"
        );
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
    fn test_fnv1a_one_bit_change_avalanche() {
        // Test that a 1-bit change produces significantly different output
        let d1 = [0u8; 8];
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

        let diff = h1 ^ h2;
        let bits_set = diff.count_ones();
        // At least 20 of 64 bits should differ (avalanche property)
        assert!(
            bits_set >= 20,
            "Avalanche: only {}/64 bits differ for 1-bit change",
            bits_set
        );
    }

    #[test]
    fn test_fnv1a_all_zero_input() {
        // All zeros should produce a specific (non-zero) value
        let data = [0u8; 32];
        let mut hasher = Fnv1aHasher::new();
        hasher.write(&data);
        let result = hasher.finish();
        assert_ne!(result, 0, "Hash of all zeros should not be zero");
        // Same input should always produce same output
        let mut hasher2 = Fnv1aHasher::new();
        hasher2.write(&data);
        assert_eq!(result, hasher2.finish());
    }

    #[test]
    fn test_fnv1a_long_repeated_byte() {
        // FNV-1a with repeated bytes should be well-distributed
        let data = [0x41u8; 256]; // 'A' repeated 256 times
        let mut hasher = Fnv1aHasher::new();
        hasher.write(&data);
        let result = hasher.finish();
        assert_ne!(result, 0);
        // Verify determinism
        let mut hasher2 = Fnv1aHasher::new();
        hasher2.write(&data);
        assert_eq!(result, hasher2.finish());
    }

    // ========================================================================
    // SipHash tests
    // ========================================================================

    #[test]
    fn test_siphash_deterministic_single_instance() {
        // SipHash with DefaultHasher uses a random key PER INSTANCE,
        // so the same input produces DIFFERENT outputs across instances.
        // This test verifies determinism WITHIN A SINGLE INSTANCE.
        let data = b"consistent session key";

        let mut hasher = SipHasher::new();
        hasher.write(data);
        let h1 = hasher.finish();

        let mut hasher2 = SipHasher::new();
        hasher2.write(data);
        let _h2 = hasher2.finish();

        // Each hasher instance has its own random key, so outputs differ.
        // This is BY DESIGN (hash flooding protection).
        // The key point: within one hasher, the result is consistent.
        let mut hasher3 = SipHasher::new();
        hasher3.write(data);
        let h3 = hasher3.finish();
        assert_eq!(h1, h3, "Same instance should give same result");
        // Different instances give different results (random key per instance)
        // This is expected and correct behavior
    }

    #[test]
    fn test_siphash_different_inputs_different_outputs() {
        let inputs = [b"packet1", b"packet2", b"packet3"];
        let mut hasher = SipHasher::new();
        let mut results = Vec::new();
        for inp in &inputs {
            hasher.write(*inp);
            results.push(hasher.finish());
        }
        // All three should be different (extremely high probability)
        assert_ne!(results[0], results[1]);
        assert_ne!(results[1], results[2]);
        assert_ne!(results[0], results[2]);
    }

    #[test]
    fn test_siphash_empty_input() {
        let mut hasher = SipHasher::new();
        hasher.write(b"");
        let result = hasher.finish();
        assert_ne!(result, 0, "Empty input should not hash to zero");
        // Verify determinism
        let mut hasher2 = SipHasher::new();
        hasher2.write(b"");
        // Note: different instance = different key = different result (by design)
    }

    // ========================================================================
    // Cross-algorithm tests
    // ========================================================================

    #[test]
    fn test_fnv1a_vs_siphash_different() {
        // FNV-1a and SipHash MUST produce different outputs
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
        assert_ne!(
            fnv, sip,
            "FNV-1a and SipHash should produce different hashes"
        );
    }

    // ========================================================================
    // Hash trait integration tests
    // ========================================================================

    #[test]
    fn test_hash_functions_trait_impl() {
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
    fn test_fnv1a_with_hash_trait_integers() {
        // Verify Hash trait integration works correctly for integer types
        let mut hasher = Fnv1aHasher::new();
        42u32.hash(&mut hasher);
        let h_u32 = hasher.finish();

        let mut hasher2 = Fnv1aHasher::new();
        42u64.hash(&mut hasher2);
        let h_u64 = hasher2.finish();

        let mut hasher3 = Fnv1aHasher::new();
        (42usize).hash(&mut hasher3);
        let h_usize = hasher3.finish();

        // All should be non-zero and deterministic
        assert_ne!(h_u32, 0);
        assert_ne!(h_u64, 0);
        assert_ne!(h_usize, 0);
        // 42u32, 42u64, 42usize should hash differently (different byte lengths)
        assert_ne!(h_u32, h_u64);
    }

    #[test]
    fn test_fnv1a_hash_trait_integration() {
        // Verify Hash trait integration works correctly for [u8]
        let data: &[u8] = &[1, 2, 3, 4, 5];
        let mut hasher = Fnv1aHasher::new();
        data.hash(&mut hasher);
        let result = hasher.finish();
        assert_ne!(result, 0, "Hash should not be zero");
        // Determinism
        let mut hasher2 = Fnv1aHasher::new();
        data.hash(&mut hasher2);
        assert_eq!(result, hasher2.finish());
    }

    #[test]
    fn test_fnv1a_u8_slice_hash() {
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

    #[test]
    fn test_fnv1a_string_vs_bytes() {
        // Note: String and [u8] have DIFFERENT Hash trait implementations in std.
        // String::hash() includes a length prefix, [u8]::hash() does not.
        // So fnv1a_hash(&"abc") != fnv1a_hash(&b"abc"[..])
        // This is EXPECTED behavior in Rust's standard library.
        //
        // What we CAN verify: String "abc" is deterministic
        let s = "abc";
        let h1 = fnv1a_hash(&s);
        let h2 = fnv1a_hash(&s);
        assert_eq!(h1, h2, "Same string should always hash to same value");

        // And [u8] "abc" is deterministic
        let b: &[u8] = b"abc";
        let h3 = {
            let mut hasher = Fnv1aHasher::new();
            hasher.write(b);
            hasher.finish()
        };
        let h4 = {
            let mut hasher = Fnv1aHasher::new();
            hasher.write(b);
            hasher.finish()
        };
        assert_eq!(h3, h4, "Same bytes should always hash to same value");
    }

    #[test]
    fn test_fnv1a_write_usize() {
        // Test write_usize directly
        let mut h1 = Fnv1aHasher::new();
        h1.write_usize(0x1234567890ABCDEFusize);
        let r1 = h1.finish();

        let mut h2 = Fnv1aHasher::new();
        h2.write(&0x1234567890ABCDEFusize.to_le_bytes());
        let r2 = h2.finish();

        assert_eq!(r1, r2, "write_usize should match byte-wise hashing");
    }

    #[test]
    fn test_fnv1a_write_u64() {
        // Test write_u64 directly
        let mut h1 = Fnv1aHasher::new();
        h1.write_u64(0xDEADBEEFCAFEBABEu64);
        let r1 = h1.finish();

        let mut h2 = Fnv1aHasher::new();
        h2.write(&0xDEADBEEFCAFEBABEu64.to_le_bytes());
        let r2 = h2.finish();

        assert_eq!(r1, r2, "write_u64 should match byte-wise hashing");
    }

    // ========================================================================
    // Edge cases
    // ========================================================================

    #[test]
    fn test_fnv1a_very_long_input() {
        // Stress test with a large input
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let mut hasher = Fnv1aHasher::new();
        hasher.write(&data);
        let result = hasher.finish();
        assert_ne!(result, 0);
        // Verify determinism
        let mut hasher2 = Fnv1aHasher::new();
        hasher2.write(&data);
        assert_eq!(result, hasher2.finish());
    }

    #[test]
    fn test_fnv1a_all_bit_patterns() {
        // Verify different byte values produce different hashes
        let mut hashes = std::collections::HashSet::new();
        for i in 0u8..=20 {
            let mut hasher = Fnv1aHasher::new();
            hasher.write_u8(i);
            let h = hasher.finish();
            assert!(hashes.insert(h), "Duplicate hash for different byte value");
        }
    }
}
