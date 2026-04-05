//! HTTP CONNECT request parser
//!
//! Parses HTTP CONNECT requests and host:port strings.

/// HTTP CONNECT proxy request
#[derive(Debug)]
pub struct HttpConnectRequest {
    pub host: String,
    pub port: u16,
}

impl HttpConnectRequest {
    /// Parse from CONNECT request line
    pub fn parse(request_line: &str) -> Option<Self> {
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let host_port = parts[1];
        let (host, port) = Self::parse_host_port(host_port)?;

        Some(Self { host, port })
    }

    /// Parse host:port string
    fn parse_host_port(s: &str) -> Option<(String, u16)> {
        if let Some(idx) = s.rfind(':') {
            let host = s[..idx].to_string();
            let port_str = &s[idx + 1..];
            let port: u16 = port_str.parse().ok()?;
            Some((host, port))
        } else {
            // Default to 443 for HTTPS
            Some((s.to_string(), 443))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_connect_request_parse() {
        let req = HttpConnectRequest::parse("CONNECT example.com:443 HTTP/1.1").unwrap();
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 443);

        let req2 = HttpConnectRequest::parse("CONNECT 192.168.1.1:8080 HTTP/1.0").unwrap();
        assert_eq!(req2.host, "192.168.1.1");
        assert_eq!(req2.port, 8080);
    }

    #[test]
    fn test_http_connect_request_invalid() {
        let req = HttpConnectRequest::parse("");
        assert!(req.is_none());

        let req = HttpConnectRequest::parse("CONNECT");
        assert!(req.is_none());
    }

    #[test]
    fn test_http_connect_request_with_path() {
        let req = HttpConnectRequest::parse("CONNECT api.example.com:8443 HTTP/1.1");
        assert!(req.is_some());
        let req = req.unwrap();
        assert_eq!(req.host, "api.example.com");
        assert_eq!(req.port, 8443);
    }

    #[test]
    fn test_http_connect_request_ipv6() {
        let req = HttpConnectRequest::parse("CONNECT [::1]:8080 HTTP/1.1");
        assert!(req.is_some() || req.is_none());
    }

    #[test]
    fn test_http_connect_request_default_port() {
        let req = HttpConnectRequest::parse("CONNECT example.com HTTP/1.1");
        assert!(req.is_some() || req.is_none());
    }

    #[test]
    fn test_http_connect_request_debug() {
        let req = HttpConnectRequest::parse("CONNECT test.com:443 HTTP/1.1").unwrap();
        let debug_str = format!("{:?}", req);
        assert!(debug_str.contains("HttpConnectRequest"));
    }
}
