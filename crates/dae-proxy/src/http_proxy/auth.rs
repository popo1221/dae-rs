//! HTTP proxy authentication module
//!
//! Implements Basic authentication with constant-time credential comparison.

use subtle::ConstantTimeEq;

/// Basic authentication credentials
#[derive(Debug, Clone)]
pub struct BasicAuth {
    username: String,
    password: String,
}

impl BasicAuth {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    /// Parse from Proxy-Authorization header value
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

    /// Validate credentials using constant-time comparison to prevent timing attacks
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

/// Simple base64 decoder (RFC 4648)
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
