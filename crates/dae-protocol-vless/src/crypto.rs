//! VLESS 加密工具模块
//!
//! 本模块提供 VLESS 协议所需的加密功能。
//!
//! # 加密说明
//! VLESS 协议使用 HMAC-SHA256 进行消息认证和密钥派生。

/// 计算 HMAC-SHA256
///
/// # 参数
/// - `key`: HMAC 密钥
/// - `data`: 待认证的数据
///
/// # 返回
/// 32 字节的 HMAC-SHA256 输出
///
/// # 用途
/// - 用于 VLESS 协议的请求认证
/// - 用于 Reality 密钥派生
/// - 用于消息完整性校验
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    let mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    let result = mac.chain_update(data).finalize();
    result.into_bytes().into()
}
