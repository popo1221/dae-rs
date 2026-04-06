//! Shadowsocks AEAD 加密实现模块
//!
//! 提供 AEAD（Authenticated Encryption with Associated Data）加密算法的实现。
//!
//! # 支持的加密算法
//!
//! | 算法 | 密钥长度 | Nonce长度 | 认证标签长度 |
//! |------|----------|----------|-------------|
//! | chacha20-ietf-poly1305 | 32 bytes | 12 bytes | 16 bytes |
//! | aes-256-gcm | 32 bytes | 12 bytes | 16 bytes |
//! | aes-128-gcm | 16 bytes | 12 bytes | 16 bytes |
//!
//! # AEAD 工作模式
//!
//! AEAD 加密过程：
//! 1. 使用密钥和 nonce 加密明文
//! 2. 生成认证标签（tag）
//! 3. 密文 + 标签一起传输
//!
//! AEAD 解密过程：
//! 1. 验证认证标签
//! 2. 标签验证通过后解密
//! 3. 如果标签无效，丢弃数据（防篡改）
//!
//! # 注意事项
//!
//! 完整的 AEAD 加密/解密实现尚未完成。
//! 参见 GitHub Issue #78。

use super::protocol::SsCipherType;

/// AEAD 加密操作的结果类型
pub type AeadResult<T> = Result<T, AeadError>;

/// AEAD 加密错误类型
///
/// 包含 AEAD 加密/解密操作可能发生的各种错误。
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

/// AEAD 加密算法特征
///
/// 定义 Shadowsocks AEAD 加密器必须实现的行为。
///
/// # 设计原则
///
/// - `Send + Sync`: 实现必须是线程安全的
/// - 无状态: 加密器不保存连接状态，每次加密/解密独立进行
///
/// # 加密参数
///
/// - `key`: 加密密钥，长度由 `key_len()` 返回
/// - `nonce`: 初始化向量/计数器，长度由 `nonce_len()` 返回
/// - `tag`: 认证标签，用于验证数据完整性
///
/// # 使用示例
///
/// ```ignore
/// let cipher: Box<dyn AeadCipher> = ...;
/// let key = derive_key_from_password(password);
/// let nonce = generate_nonce();
/// let mut tag = [0u8; 16];
///
/// let ciphertext = cipher.encrypt(&key, &nonce, plaintext, &mut tag)?;
/// let plaintext = cipher.decrypt(&key, &nonce, &ciphertext, &tag)?;
/// ```
pub trait AeadCipher: Send + Sync {
    /// 获取加密算法类型
    ///
    /// # 返回值
    ///
    /// 返回 [`SsCipherType`] 枚举值，标识使用的具体算法。
    fn cipher_type(&self) -> SsCipherType;

    /// 获取密钥长度（字节）
    ///
    /// # 返回值
    ///
    /// 返回加密所需的密钥字节长度。
    fn key_len(&self) -> usize;

    /// 获取 nonce/IV 长度（字节）
    ///
    /// # 返回值
    ///
    /// 返回初始化向量的字节长度。AEAD 算法通常使用 12 字节 nonce。
    fn nonce_len(&self) -> usize;

    /// 加密数据
    ///
    /// # 参数
    ///
    /// - `key`: 加密密钥
    /// - `nonce`: 初始化向量
    /// - `plaintext`: 待加密的明文数据
    /// - `tag`: 输出参数，用于存储生成的认证标签（必须足够长）
    ///
    /// # 返回值
    ///
    /// - `Ok(Vec<u8>)`: 加密后的密文（不包含标签）
    /// - `Err(AeadError)`: 加密失败
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        tag: &mut [u8],
    ) -> AeadResult<Vec<u8>>;

    /// 解密数据
    ///
    /// # 参数
    ///
    /// - `key`: 解密密钥（必须与加密时相同）
    /// - `nonce`: 初始化向量（必须与加密时相同）
    /// - `ciphertext`: 待解密的密文
    /// - `tag`: 认证标签（用于验证数据完整性）
    ///
    /// # 返回值
    ///
    /// - `Ok(Vec<u8>)`: 解密后的明文
    /// - `Err(AeadError::TagVerificationFailed)`: 认证标签验证失败，数据被篡改
    /// - `Err(AeadError::DecryptionFailed)`: 解密失败
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
