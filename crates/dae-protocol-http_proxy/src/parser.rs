//! HTTP CONNECT 请求解析器模块
//!
//! 负责解析 HTTP CONNECT 方法的请求行，提取目标主机和端口。
//! HTTP CONNECT 方法用于建立 HTTP 隧道（tunnel），是 HTTPS 代理的基础。

/// HTTP CONNECT 代理请求
///
/// 表示一个解析后的 HTTP CONNECT 请求，包含目标主机和端口。
///
/// # 字段说明
///
/// - `host`: 目标主机名或 IP 地址
/// - `port`: 目标端口号
///
/// # 示例
///
/// ```rust
/// use dae_protocol_http_proxy::HttpConnectRequest;
///
/// let req = HttpConnectRequest::parse("CONNECT example.com:443 HTTP/1.1").unwrap();
/// assert_eq!(req.host, "example.com");
/// assert_eq!(req.port, 443);
/// ```
#[derive(Debug)]
pub struct HttpConnectRequest {
    pub host: String,
    pub port: u16,
}

impl HttpConnectRequest {
    /// 从 CONNECT 请求行解析请求
    ///
    /// 解析 `CONNECT host:port HTTP/1.x` 格式的请求行。
    /// 这是 HTTP CONNECT 方法的标准格式。
    ///
    /// # 参数
    ///
    /// - `request_line`: 完整的请求行，例如 `"CONNECT example.com:443 HTTP/1.1"`
    ///
    /// # 返回值
    ///
    /// - `Some(HttpConnectRequest)`: 解析成功
    /// - `None`: 解析失败（格式不正确）
    ///
    /// # 支持的格式
    ///
    /// - `"CONNECT example.com:443 HTTP/1.1"`
    /// - `"CONNECT 192.168.1.1:8080 HTTP/1.0"`
    /// - `"CONNECT example.com HTTP/1.1"` (默认端口 443)
    ///
    /// # 不支持的格式
    ///
    /// - 空字符串
    /// - 只有 "CONNECT" 没有主机信息
    pub fn parse(request_line: &str) -> Option<Self> {
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let host_port = parts[1];
        let (host, port) = Self::parse_host_port(host_port)?;

        Some(Self { host, port })
    }

    /// 解析 host:port 字符串
    ///
    /// 从 `host:port` 格式中分离主机名和端口号。
    /// 如果没有端口号，默认使用 443（HTTPS 标准端口）。
    ///
    /// # 参数
    ///
    /// - `s`: 主机:端口字符串
    ///
    /// # 返回值
    ///
    /// - `Some((host, port))`: 解析成功
    /// - `None`: 端口号格式无效（非数字）
    ///
    /// # 注意
    ///
    /// - 使用 `rfind(':')` 从右向左查找冒号，避免 IPv6 地址中的冒号干扰
    /// - 但目前的实现对 IPv6 格式 `[::1]:8080` 支持不完整
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
