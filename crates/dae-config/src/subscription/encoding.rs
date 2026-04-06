//! Encoding utilities for subscription parsing
//!
//! This module provides base64 encoding/decoding utilities used by
//! subscription parsing functions.

use base64::Engine;

use super::SubscriptionError;

/// Parse a base64-encoded subscription
pub fn parse_base64_subscription(content: &[u8]) -> Result<Vec<String>, SubscriptionError> {
    // Try standard base64 first
    let decoded = match base64::engine::general_purpose::STANDARD.decode(content) {
        Ok(d) => d,
        Err(_) => {
            // Try URL-safe base64
            match base64::engine::general_purpose::URL_SAFE.decode(content) {
                Ok(d) => d,
                Err(e) => {
                    return Err(SubscriptionError::ParseError(format!(
                        "Failed to decode base64: {e}"
                    )));
                }
            }
        }
    };

    // Parse as string and split by lines
    let content_str = String::from_utf8(decoded)
        .map_err(|e| SubscriptionError::ParseError(format!("Invalid UTF-8: {e}")))?;

    super::parse_uri_list(&content_str)
}

/// Parse URI list from content
pub fn parse_uri_list(content: &str) -> Result<Vec<String>, SubscriptionError> {
    let mut links = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Filter to valid proxy URIs
        if trimmed.starts_with("ss://")
            || trimmed.starts_with("vmess://")
            || trimmed.starts_with("vless://")
            || trimmed.starts_with("trojan://")
        {
            links.push(trimmed.to_string());
        }
    }
    Ok(links)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uri_list() {
        let content = r#"
ss://example1
vmess://example2
vless://example3
trojan://example4
"#;
        let result = parse_uri_list(content).unwrap();
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_parse_uri_list_empty_content() {
        let result = parse_uri_list("").unwrap();
        assert!(result.is_empty());

        let result = parse_uri_list("   \n\n   ").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_uri_list_filters_invalid() {
        let content = "ss://valid\nhttp://invalid\nvmess://valid\nnot-a-proxy\nvless://valid";
        let result = parse_uri_list(content).unwrap();
        assert_eq!(result.len(), 3);
        assert!(result.iter().all(|l| l.starts_with("ss://")
            || l.starts_with("vmess://")
            || l.starts_with("vless://")));
    }

    #[test]
    fn test_parse_base64_subscription_empty_lines() {
        // Valid base64 encoded content with URI links and empty lines
        let raw_content = b"ss://link1\n\nss://link2";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw_content);
        let content = encoded.as_bytes();
        let result = parse_base64_subscription(content);
        assert!(result.is_ok());
        let links = result.unwrap();
        assert_eq!(links.len(), 2);
    }

    #[test]
    fn test_parse_base64_invalid_base64() {
        let content = b"not-valid-base64!!!";
        let result = parse_base64_subscription(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_subscription_url_safe_base64() {
        let raw = "ss://link1\nvmess://link2";
        let encoded = base64::engine::general_purpose::URL_SAFE.encode(raw.as_bytes());

        let result = parse_base64_subscription(encoded.as_bytes());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }
}
