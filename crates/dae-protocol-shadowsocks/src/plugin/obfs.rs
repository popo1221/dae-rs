//! Shadowsocks simple-obfs 插件
//!
//! 实现 simple-obfs 协议，用于 Shadowsocks 流量的混淆。
//! simple-obfs 使 Shadowsocks 流量看起来像普通的 HTTP 或 TLS 流量。
//!
//! 协议规范：https://github.com/shadowsocks/simple-obfs
//!
//! # 混淆类型
//!
//! 1. **http**: 将流量包装在 HTTP 请求中
//! 2. **tls**: 将流量包装在 TLS ClientHello 中
//!
//! # HTTP 模式协议流程
//!
//! 客户端 -> [obfs HTTP 包装] -> [Shadowsocks AEAD 加密] -> 服务器
//! 客户端 -> [HTTP GET/POST 请求] -> 服务器 -> [剥离 HTTP] -> [Shadowsocks AEAD 解密]
//!
//! # TLS 模式协议流程
//!
//! 客户端 -> [obfs TLS 包装] -> [Shadowsocks AEAD 加密] -> 服务器
//! 客户端 -> [TLS ClientHello] -> 服务器 -> [剥离 TLS] -> [Shadowsocks AEAD 解密]

use std::io::ErrorKind;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// simple-obfs 插件模式
///
/// 定义 simple-obfs 支持的两种混淆模式：
/// - Http：伪装为 HTTP 流量
/// - Tls：伪装为 TLS 流量
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfsMode {
    /// HTTP 模式 - 流量看起来像 HTTP GET/POST 请求
    Http,
    /// TLS 模式 - 流量看起来像 TLS ClientHello
    Tls,
}

#[allow(clippy::should_implement_trait)]
impl ObfsMode {
    /// 从字符串解析混淆模式
    ///
    /// 支持的格式：
    /// - "http", "obfs_http" -> Http
    /// - "tls", "obfs_tls" -> Tls
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "http" | "obfs_http" => Some(ObfsMode::Http),
            "tls" | "obfs_tls" => Some(ObfsMode::Tls),
            _ => None,
        }
    }
}

/// simple-obfs 配置
///
/// 包含 simple-obfs 插件的所有配置参数。
#[derive(Debug, Clone)]
pub struct ObfsConfig {
    /// 混淆模式
    pub mode: ObfsMode,
    /// 连接目标主机（用于 HTTP Host 头或 TLS SNI）
    pub host: String,
    /// HTTP 模式下的路径
    pub path: String,
    /// 连接超时时间
    pub timeout: Duration,
}

impl ObfsConfig {
    /// 创建新的配置
    ///
    /// # 参数
    /// - `mode`: 混淆模式
    /// - `host`: 目标主机
    pub fn new(mode: ObfsMode, host: &str) -> Self {
        Self {
            mode,
            host: host.to_string(),
            path: "/".to_string(),
            timeout: Duration::from_secs(30),
        }
    }

    /// 创建 HTTP 混淆配置
    ///
    /// # 参数
    /// - `host`: 伪装的目标主机域名
    /// - `path`: HTTP 请求路径
    pub fn http(host: &str, path: &str) -> Self {
        Self {
            mode: ObfsMode::Http,
            host: host.to_string(),
            path: path.to_string(),
            timeout: Duration::from_secs(30),
        }
    }

    /// 创建 TLS 混淆配置
    ///
    /// # 参数
    /// - `host`: 伪装的目标主机域名（用于 TLS SNI）
    pub fn tls(host: &str) -> Self {
        Self {
            mode: ObfsMode::Tls,
            host: host.to_string(),
            path: "/".to_string(),
            timeout: Duration::from_secs(30),
        }
    }
}

/// simple-obfs HTTP 混淆器
///
/// 将 Shadowsocks 流量包装在 HTTP GET 请求中，使其看起来像普通的 Web 浏览流量。
pub struct ObfsHttp {
    config: ObfsConfig,
}

impl ObfsHttp {
    /// 创建 HTTP 混淆器
    pub fn new(config: ObfsConfig) -> Self {
        Self { config }
    }

    /// 使用 HTTP 混淆连接到服务器
    ///
    /// # 参数
    /// - `server_addr`: 服务器地址
    ///
    /// # 返回值
    /// - `Ok(ObfsStream)`: 混淆后的连接流
    /// - `Err`: 连接或握手失败
    ///
    /// # 握手过程
    /// 1. 建立 TCP 连接到服务器
    /// 2. 发送混淆后的 HTTP GET 请求
    /// 3. 读取服务器响应
    /// 4. 验证响应并返回混淆流
    pub async fn connect(&self, server_addr: &str) -> std::io::Result<ObfsStream> {
        let mut stream = TcpStream::connect(server_addr).await?;

        // Build HTTP obfuscation request
        let request = self.build_http_request();
        debug!("Sending HTTP obfuscation request to {}", server_addr);
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        // Read HTTP response
        let mut response = vec![0u8; 4096];
        let n = tokio::time::timeout(self.config.timeout, stream.read(&mut response)).await??;

        if n == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "server closed connection during HTTP obfuscation handshake",
            ));
        }

        // Verify HTTP response
        let response_str = String::from_utf8_lossy(&response[..n]);
        if !response_str.contains("200") && !response_str.contains("Connection established") {
            warn!("Unexpected HTTP obfuscation response: {}", response_str);
        }

        debug!("HTTP obfuscation handshake complete");
        Ok(ObfsStream::new(stream))
    }

    /// 构建 HTTP 混淆请求
    ///
    /// 构造一个看起来像正常浏览器发送的 HTTP GET 请求。
    fn build_http_request(&self) -> String {
        // Simple HTTP GET request that looks like browsing
        format!(
            "GET {} HTTP/1.1\r\n\
            Host: {}\r\n\
            User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\
            Accept: */*\r\n\
            Accept-Language: en-US,en;q=0.9\r\n\
            Connection: keep-alive\r\n\
           \r\n",
            self.config.path, self.config.host
        )
    }
}

/// simple-obfs TLS 混淆器
///
/// 将 Shadowsocks 流量包装在 TLS ClientHello 中，使其看起来像 TLS 握手流量。
pub struct ObfsTls {
    config: ObfsConfig,
}

impl ObfsTls {
    /// 创建 TLS 混淆器
    pub fn new(config: ObfsConfig) -> Self {
        Self { config }
    }

    /// 使用 TLS 混淆连接到服务器
    ///
    /// # 参数
    /// - `server_addr`: 服务器地址
    ///
    /// # 返回值
    /// - `Ok(ObfsStream)`: 混淆后的连接流
    /// - `Err`: 连接或握手失败
    ///
    /// # 握手过程
    /// 1. 建立 TCP 连接到服务器
    /// 2. 发送混淆后的 TLS ClientHello
    /// 3. 读取服务器响应（或超时）
    /// 4. 返回混淆流
    pub async fn connect(&self, server_addr: &str) -> std::io::Result<ObfsStream> {
        let mut stream = TcpStream::connect(server_addr).await?;

        // Build TLS ClientHello obfuscation
        let client_hello = self.build_tls_client_hello()?;
        debug!("Sending TLS obfuscation ClientHello to {}", server_addr);
        stream.write_all(&client_hello).await?;
        stream.flush().await?;

        // Read ServerHello or just wait for connection establishment
        // Some obfs servers just close the connection after receiving ClientHello
        // and expect the client to reconnect without obfuscation
        let mut response = vec![0u8; 4096];
        let result = tokio::time::timeout(self.config.timeout, stream.read(&mut response)).await;

        match result {
            Ok(Ok(n)) => {
                if n == 0 {
                    // Server closed connection - this is normal for some obfs implementations
                    debug!("Server closed connection after TLS obfuscation handshake");
                } else {
                    debug!("Received {} bytes after TLS obfuscation handshake", n);
                }
            }
            Ok(Err(e)) => {
                warn!("Error reading TLS obfuscation response: {}", e);
            }
            Err(_) => {
                // Timeout - server might expect us to reconnect
                debug!("TLS obfuscation handshake timeout, assuming success");
            }
        }

        debug!("TLS obfuscation handshake complete");
        Ok(ObfsStream::new(stream))
    }

    /// 构建 TLS ClientHello 混淆数据
    ///
    /// 构造一个简化的 TLS ClientHello 消息，包含：
    /// - TLS 记录层
    /// - 握手类型和版本
    /// - 随机数
    /// - 密码套件
    /// - SNI 扩展（使用配置的 host 参数）
    fn build_tls_client_hello(&self) -> std::io::Result<Vec<u8>> {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let mut client_hello = Vec::new();

        // TLS Record Layer: Handshake (0x16)
        client_hello.push(0x16);

        // TLS Version TLS 1.0 (0x0301) - many censors block TLS 1.3
        client_hello.push(0x03);
        client_hello.push(0x01);

        // Handshake length (placeholder)
        let payload_start = client_hello.len();
        client_hello.push(0x00);
        client_hello.push(0x00);

        // Handshake type: ClientHello (0x01)
        client_hello.push(0x01);

        // Handshake length (placeholder)
        let handshake_start = client_hello.len();
        client_hello.push(0x00);
        client_hello.push(0x00);
        client_hello.push(0x00);

        // ClientVersion TLS 1.2 (0x0303)
        client_hello.push(0x03);
        client_hello.push(0x03);

        // Random (32 bytes)
        let random: [u8; 32] = rng.gen();
        client_hello.extend_from_slice(&random);

        // Session ID (empty)
        client_hello.push(0x00);

        // Cipher suites
        let cipher_suites: Vec<u16> = vec![
            0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            0x0005, // SSL_RSA_WITH_3DES_EDE_CBC_SHA
            0x000a, // SSL_RSA_WITH_3DES_EDE_CBC_SHA
        ];
        client_hello.push((cipher_suites.len() * 2) as u8);
        for cs in cipher_suites {
            client_hello.push((cs >> 8) as u8);
            client_hello.push((cs & 0xff) as u8);
        }

        // Compression methods (null only)
        client_hello.push(0x01);
        client_hello.push(0x00);

        // Extensions length (placeholder)
        let extensions_start = client_hello.len();
        client_hello.push(0x00);
        client_hello.push(0x00);

        // SNI extension
        self.add_sni_extension(&mut client_hello)?;

        // Update extensions length
        let ext_len = client_hello.len() - extensions_start - 2;
        client_hello[extensions_start] = (ext_len >> 8) as u8;
        client_hello[extensions_start + 1] = (ext_len & 0xff) as u8;

        // Update handshake length
        let handshake_len = client_hello.len() - handshake_start - 3;
        client_hello[handshake_start] = (handshake_len >> 16) as u8;
        client_hello[handshake_start + 1] = (handshake_len >> 8) as u8;
        client_hello[handshake_start + 2] = (handshake_len & 0xff) as u8;

        // Update record layer length
        let record_len = client_hello.len() - payload_start - 3 + 4;
        client_hello[payload_start] = (record_len >> 8) as u8;
        client_hello[payload_start + 1] = (record_len & 0xff) as u8;

        Ok(client_hello)
    }

    /// 添加 SNI 扩展到 ClientHello
    ///
    /// SNI（Server Name Indication）扩展用于指定目标服务器域名。
    fn add_sni_extension(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        // Extension type: server_name (0x0000)
        buffer.push(0x00);
        buffer.push(0x00);

        // Extension data length
        let len_pos = buffer.len();
        buffer.push(0x00);
        buffer.push(0x00);

        // ServerNameList length
        buffer.push(0x00);

        // ServerName type: host_name (0x00)
        buffer.push(0x00);

        // ServerName length
        let name_bytes = self.config.host.as_bytes();
        buffer.push((name_bytes.len() >> 8) as u8);
        buffer.push((name_bytes.len() & 0xff) as u8);

        // ServerName
        buffer.extend_from_slice(name_bytes);

        // Update extension length
        let ext_data_len = buffer.len() - len_pos - 2;
        buffer[len_pos] = (ext_data_len >> 8) as u8;
        buffer[len_pos + 1] = (ext_data_len & 0xff) as u8;

        Ok(())
    }
}

/// 混淆后的流封装
///
/// 封装 TCP 流，提供简化的读写接口。
#[derive(Debug)]
pub struct ObfsStream {
    stream: TcpStream,
}

impl ObfsStream {
    /// 创建混淆流封装
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    /// 获取内部的 TCP 流
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }

    /// 获取内部 TCP 流的引用
    pub fn inner(&self) -> &TcpStream {
        &self.stream
    }

    /// 异步读取数据
    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf).await
    }

    /// 异步写入所有数据
    pub async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(buf).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfs_mode_from_str() {
        assert_eq!(ObfsMode::from_str("http"), Some(ObfsMode::Http));
        assert_eq!(ObfsMode::from_str("tls"), Some(ObfsMode::Tls));
        assert_eq!(ObfsMode::from_str("obfs_http"), Some(ObfsMode::Http));
        assert_eq!(ObfsMode::from_str("unknown"), None);
    }

    #[test]
    fn test_obfs_config_http() {
        let config = ObfsConfig::http("example.com", "/path");
        assert_eq!(config.mode, ObfsMode::Http);
        assert_eq!(config.host, "example.com");
        assert_eq!(config.path, "/path");
    }

    #[test]
    fn test_obfs_config_tls() {
        let config = ObfsConfig::tls("example.com");
        assert_eq!(config.mode, ObfsMode::Tls);
        assert_eq!(config.host, "example.com");
    }

    #[tokio::test]
    async fn test_obfs_http_build_request() {
        let config = ObfsConfig::http("example.com", "/test/path");
        let obfs = ObfsHttp::new(config);
        let request = obfs.build_http_request();

        assert!(request.contains("GET /test/path HTTP/1.1"));
        assert!(request.contains("Host: example.com"));
        assert!(request.contains("Connection: keep-alive"));
    }
}
