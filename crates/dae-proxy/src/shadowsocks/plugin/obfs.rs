//! Shadowsocks simple-obfs plugin
//!
//! Implements simple-obfs protocol for Shadowsocks traffic obfuscation.
//! simple-obfs makes Shadowsocks traffic look like regular HTTP or TLS.
//!
//! Protocol spec: https://github.com/shadowsocks/simple-obfs
//!
//! # Obfuscation Types
//!
//! 1. **http**: Wraps traffic in HTTP requests
//! 2. **tls**: Wraps traffic in TLS ClientHello
//!
//! # Protocol Flow (HTTP mode)
//!
//! Client -> [obfs HTTP] -> [Shadowsocks AEAD] -> Server
//! Client -> [HTTP GET/POST] -> Server -> [strip HTTP] -> [Shadowsocks AEAD]
//!
//! # Protocol Flow (TLS mode)
//!
//! Client -> [obfs TLS] -> [Shadowsocks AEAD] -> Server
//! Client -> [TLS ClientHello] -> Server -> [strip TLS] -> [Shadowsocks AEAD]

use std::io::ErrorKind;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// simple-obfs plugin mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfsMode {
    /// HTTP mode - traffic looks like HTTP GET/POST
    Http,
    /// TLS mode - traffic looks like TLS ClientHello
    Tls,
}

#[allow(clippy::should_implement_trait)]
impl ObfsMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "http" | "obfs_http" => Some(ObfsMode::Http),
            "tls" | "obfs_tls" => Some(ObfsMode::Tls),
            _ => None,
        }
    }
}

/// simple-obfs configuration
#[derive(Debug, Clone)]
pub struct ObfsConfig {
    /// Obfuscation mode
    pub mode: ObfsMode,
    /// Host to connect to (for HTTP Host header or TLS SNI)
    pub host: String,
    /// Path for HTTP mode
    pub path: String,
    /// Connection timeout
    pub timeout: Duration,
}

impl ObfsConfig {
    pub fn new(mode: ObfsMode, host: &str) -> Self {
        Self {
            mode,
            host: host.to_string(),
            path: "/".to_string(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn http(host: &str, path: &str) -> Self {
        Self {
            mode: ObfsMode::Http,
            host: host.to_string(),
            path: path.to_string(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn tls(host: &str) -> Self {
        Self {
            mode: ObfsMode::Tls,
            host: host.to_string(),
            path: "/".to_string(),
            timeout: Duration::from_secs(30),
        }
    }
}

/// simple-obfs HTTP obfuscator
pub struct ObfsHttp {
    config: ObfsConfig,
}

impl ObfsHttp {
    pub fn new(config: ObfsConfig) -> Self {
        Self { config }
    }

    /// Connect to server with HTTP obfuscation
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

/// simple-obfs TLS obfuscator
pub struct ObfsTls {
    config: ObfsConfig,
}

impl ObfsTls {
    pub fn new(config: ObfsConfig) -> Self {
        Self { config }
    }

    /// Connect to server with TLS obfuscation
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

/// Obfuscated stream wrapper
#[derive(Debug)]
pub struct ObfsStream {
    stream: TcpStream,
}

impl ObfsStream {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    pub fn into_inner(self) -> TcpStream {
        self.stream
    }

    pub fn inner(&self) -> &TcpStream {
        &self.stream
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf).await
    }

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
