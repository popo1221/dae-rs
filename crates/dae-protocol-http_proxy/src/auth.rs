//! HTTP 代理认证模块
//!
//! 实现了 HTTP 代理的 Basic 认证功能，包括：
//! - 从 Proxy-Authorization 头解析 Base64 编码的用户名:密码
//! - 使用 constant-time 比较防止时序攻击
//! - 符合 RFC 7617 Basic 认证方案

use subtle::ConstantTimeEq;

/// Basic 认证凭证
///
/// 用于存储和验证 HTTP 代理的 Basic 认证信息。
/// 凭证由用户名和密码组成，符合 RFC 7617 标准。
///
/// # 安全特性
///
/// - `matches` 方法使用 constant-time 比较防止时序攻击
/// - 内部使用 `subtle::ConstantTimeEq` 进行字节级安全比较
///
/// # 示例
///
/// ```rust
/// use dae_protocol_http_proxy::BasicAuth;
///
/// // 从请求头解析
/// if let Some(auth) = BasicAuth::from_header("Basic YWRtaW46c2VjcmV0") {
///     if auth.matches("admin", "secret") {
///         println!("认证成功");
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct BasicAuth {
    username: String,
    password: String,
}

impl BasicAuth {
    /// 创建新的 BasicAuth 凭证
    ///
    /// # 参数
    ///
    /// - `username`: 用户名
    /// - `password`: 密码
    ///
    /// # 返回值
    ///
    /// 返回包含给定用户名和密码的 `BasicAuth` 实例
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    /// 从 Proxy-Authorization 头值解析 BasicAuth 凭证
    ///
    /// 解析 `Basic <base64>` 格式的认证头。
    /// Base64 解码后的格式应为 `用户名:密码`。
    ///
    /// # 参数
    ///
    /// - `value`: Proxy-Authorization 头的完整值
    ///
    /// # 返回值
    ///
    /// - `Some(BasicAuth)`: 解析成功
    /// - `None`: 解析失败（格式错误、Base64 无效等）
    ///
    /// # 支持的格式
    ///
    /// - `Basic YWRtaW46c2VjcmV0` (admin:secret 的 Base64)
    /// - 带有前导/尾随空格的格式
    ///
    /// # 不支持的格式
    ///
    /// - `Bearer token` (不是 Basic 认证)
    /// - 无效的 Base64 字符
    /// - 缺少冒号分隔符
    pub fn from_header(value: &str) -> Option<Self> {
        let value = value.trim();
        if !value.starts_with("Basic ") {
            return None;
        }

        let encoded = &value[6..];
        let decoded = base64_decode(encoded)?;

        let parts: Vec<&str> = decoded.splitn(2, ':').collect();
        if parts.len() != 2 {
            return None;
        }

        Some(Self {
            username: parts[0].to_string(),
            password: parts[1].to_string(),
        })
    }

    /// 使用 constant-time 比较验证凭证
    ///
    /// 防止时序攻击（timing attack），确保比较时间是恒定的，
    /// 不会因为匹配程度不同而产生时间差异。
    ///
    /// # 参数
    ///
    /// - `username`: 要验证的用户名
    /// - `password`: 要验证的密码
    ///
    /// # 返回值
    ///
    /// - `true`: 用户名和密码都匹配
    /// - `false`: 任一不匹配
    ///
    /// # 注意
    ///
    /// 此方法使用 `subtle::ConstantTimeEq` 进行字节级比较，
    /// 即使返回 `false` 也会执行完整的比较过程。
    pub fn matches(&self, username: &str, password: &str) -> bool {
        let user_match = self
            .username
            .as_bytes()
            .ct_eq(username.as_bytes())
            .unwrap_u8()
            == 1;
        let pass_match = self
            .password
            .as_bytes()
            .ct_eq(password.as_bytes())
            .unwrap_u8()
            == 1;
        user_match && pass_match
    }
}

/// Base64 解码器（RFC 4648 标准）
///
/// 将 Base64 编码的字符串解码为 UTF-8 字符串。
/// 仅支持标准的 Base64 字符集（A-Z, a-z, 0-9, +, /）。
///
/// # 参数
///
/// - `input`: Base64 编码的字符串
///
/// # 返回值
///
/// - `Some(String)`: 解码后的 UTF-8 字符串
/// - `None`: 输入包含无效的 Base64 字符或不是有效的 UTF-8
///
/// # 支持的字符
///
/// - `A-Z` (0-25)
/// - `a-z` (26-51)
/// - `0-9` (52-61)
/// - `+` (62)
/// - `/` (63)
/// - `=` (填充字符，自动处理)
///
/// # RFC 4648 说明
///
/// 这是标准的 Base64 编码，也称为 "base64"。
/// 不是 URL-safe 的 Base64（URL-safe 版本使用 `-` 和 `_`）。
fn base64_decode(input: &str) -> Option<String> {
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let input = input.as_bytes();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let mut i = 0;
    while i < input.len() {
        let mut block = [0u8; 4];
        let mut valid = 0u8;

        for j in 0..4 {
            if i + j >= input.len() {
                break;
            }
            let c = input[i + j];
            if c == b'=' {
                break;
            }
            let v = decode_char(c)?;
            block[j] = v;
            valid += 1;
        }

        if valid >= 2 {
            output.push((block[0] << 2) | (block[1] >> 4));
        }
        if valid >= 3 {
            output.push((block[1] << 4) | (block[2] >> 2));
        }
        if valid >= 4 {
            output.push((block[2] << 6) | block[3]);
        }

        i += 4;
    }

    String::from_utf8(output).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_auth_from_header() {
        // "admin:secret" in base64
        let auth = BasicAuth::from_header("Basic YWRtaW46c2VjcmV0").unwrap();
        assert!(auth.matches("admin", "secret"));
        assert!(!auth.matches("admin", "wrong"));
    }

    #[test]
    fn test_basic_auth_invalid_header() {
        let auth = BasicAuth::from_header("Bearer token");
        assert!(auth.is_none());

        let auth = BasicAuth::from_header("NotBase64");
        assert!(auth.is_none());
    }

    #[test]
    fn test_basic_auth_empty() {
        let auth = BasicAuth::from_header("Basic ");
        assert!(auth.is_none());
    }

    #[test]
    fn test_basic_auth_reject_empty_credentials() {
        let auth = BasicAuth::from_header("Basic ");
        assert!(auth.is_none());
    }

    #[test]
    fn test_basic_auth_matches_case_sensitive() {
        let auth = BasicAuth::from_header("Basic YWRtaW46U0VDUkVU").unwrap();
        assert!(auth.matches("admin", "SECRET"));
        assert!(!auth.matches("Admin", "secret"));
    }

    #[test]
    fn test_basic_auth_different_credentials() {
        let auth = BasicAuth::from_header("Basic YWRtaW46cGFzc3dvcmQ=").unwrap();
        assert!(auth.matches("admin", "password"));
        assert!(!auth.matches("admin", "other"));
        assert!(!auth.matches("other", "password"));
    }

    #[test]
    fn test_basic_auth_debug() {
        let auth = BasicAuth::from_header("Basic dXNlcjpwYXNz").unwrap();
        let debug_str = format!("{:?}", auth);
        assert!(debug_str.contains("BasicAuth"));
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("SGVsbG8=").unwrap(), "Hello");
        assert_eq!(base64_decode("V29ybGQ=").unwrap(), "World");
    }

    #[test]
    fn test_base64_decode_invalid() {
        let result = base64_decode("not-valid-base64!");
        assert!(result.is_none());
    }

    #[test]
    fn test_base64_decode_empty() {
        let result = base64_decode("");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "");
    }
}
