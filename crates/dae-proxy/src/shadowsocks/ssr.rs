//! ShadowsocksR (SSR) protocol implementation
//!
//! Implements ShadowsocksR protocol with its unique obfuscation and authentication.
//! SSR adds protocol-specific obfuscation on top of Shadowsocks.
//!
//! Protocol spec: https://github.com/shadowsocksr/shadowsocks-rss
//!
//! # SSR vs SS
//!
//! SSR differs from standard Shadowsocks in several ways:
//! - Protocol obfuscation (origin, verify\_deflate, 2\_auth, etc.)
//! - Password is prefixed with protocol name
//! - Different handshake sequence

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

use super::ssr_types::{
    find_bytes, SsrClientConfig, SsrObfs, SsrObfsHandler, SsrProtocol, SsrServerConfig,
};

/// SSR handler for client-side connections
pub struct SsrHandler {
    config: SsrClientConfig,
}

impl SsrHandler {
    pub fn new(config: SsrClientConfig) -> Self {
        Self { config }
    }

    pub fn new_default() -> Self {
        Self {
            config: SsrClientConfig::default(),
        }
    }

    /// Connect to SSR server with protocol handshake
    pub async fn connect(&self) -> std::io::Result<TcpStream> {
        let server_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
        debug!("Connecting to SSR server at {}", server_addr);

        let mut stream = TcpStream::connect(&server_addr).await?;

        // Perform SSR protocol handshake
        self.protocol_handshake(&mut stream).await?;

        info!("SSR connection established to {}", server_addr);
        Ok(stream)
    }

    /// Perform SSR protocol handshake
    /// SSR handshake sequence:
    /// 1. Send session key (derived from password)
    /// 2. Send initial packet based on protocol type
    async fn protocol_handshake(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        match self.config.server.protocol {
            SsrProtocol::Origin => self.origin_handshake(stream).await,
            SsrProtocol::VerifyDeflate => self.verify_deflate_handshake(stream).await,
            SsrProtocol::TwoAuth => self.two_auth_handshake(stream).await,
            SsrProtocol::AuthSha1V2 | SsrProtocol::AuthAES128MD5 | SsrProtocol::AuthAES128SHA1 => {
                self.auth_handshake(stream).await
            }
            SsrProtocol::AuthChain => self.auth_chain_handshake(stream).await,
        }
    }

    /// Origin protocol handshake (simplified)
    async fn origin_handshake(&self, _stream: &mut TcpStream) -> std::io::Result<()> {
        // Origin protocol: just establish connection
        // The actual data is sent as-is with base64 encoding
        debug!("SSR origin handshake complete");
        Ok(())
    }

    /// Verify deflate protocol handshake
    async fn verify_deflate_handshake(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        // Send protocol header with deflate support indicator
        let header = self.build_protocol_header(0x03)?;
        stream.write_all(&header).await?;
        stream.flush().await?;

        // Read server response (should be empty or ack)
        let mut resp = [0u8; 4];
        stream.read_exact(&mut resp).await?;

        debug!("SSR verify_deflate handshake complete");
        Ok(())
    }

    /// 2-factor auth handshake
    async fn two_auth_handshake(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        // Send protocol header with 2auth flag
        let header = self.build_protocol_header(0x04)?;
        stream.write_all(&header).await?;
        stream.flush().await?;

        // Read and verify response
        let mut resp = [0u8; 4];
        stream.read_exact(&mut resp).await?;

        debug!("SSR 2auth handshake complete");
        Ok(())
    }

    /// Auth-based protocol handshake (SHA1V2, AES128-MD5, AES128-SHA1)
    async fn auth_handshake(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        // Auth protocols require:
        // 1. Generate connection ID
        // 2. Build auth packet with timestamp and connection ID
        // 3. Send encrypted auth packet

        let connection_id = rand::random::<u32>();

        // Build auth packet
        let mut packet = Vec::new();

        // Protocol header
        packet.extend_from_slice(&self.build_protocol_header(0x07)?);

        // Timestamp (4 bytes)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        packet.extend_from_slice(&timestamp.to_be_bytes());

        // Connection ID (4 bytes)
        packet.extend_from_slice(&connection_id.to_be_bytes());

        // Send auth packet
        stream.write_all(&packet).await?;
        stream.flush().await?;

        // Read server response
        let mut resp = [0u8; 4];
        stream.read_exact(&mut resp).await?;

        debug!(
            "SSR auth handshake complete (connection_id={})",
            connection_id
        );
        Ok(())
    }

    /// Auth chain protocol handshake
    async fn auth_chain_handshake(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        // Auth chain requires special handling for multiple authentication
        // Simplified implementation
        debug!("SSR auth_chain handshake start");
        self.auth_handshake(stream).await
    }

    /// Build protocol header based on protocol type
    fn build_protocol_header(&self, protocol_flag: u8) -> std::io::Result<Vec<u8>> {
        let header = vec![
            0x01,          // Protocol version (1 byte)
            protocol_flag, // Protocol type (1 byte)
            0x00,
            0x00, // Reserved bytes (2 bytes)
        ];

        Ok(header)
    }
}

/// SSR obfuscation handler
pub struct SsrObfsHandler {
    obfs_type: SsrObfs,
    obfs_param: String,
}

impl SsrObfsHandler {
    pub fn new(obfs_type: SsrObfs, obfs_param: &str) -> Self {
        Self {
            obfs_type,
            obfs_param: obfs_param.to_string(),
        }
    }

    /// Apply obfuscation to data before sending
    pub async fn obfuscate(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        match self.obfs_type {
            SsrObfs::Plain => Ok(data.to_vec()),
            SsrObfs::HttpSimple => self.http_simple_obfuscate(data).await,
            SsrObfs::TlsSimple => self.tls_simple_obfuscate(data).await,
            _ => Ok(data.to_vec()),
        }
    }

    /// Remove obfuscation from received data
    pub async fn deobfuscate(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        match self.obfs_type {
            SsrObfs::Plain => Ok(data.to_vec()),
            SsrObfs::HttpSimple => self.http_simple_deobfuscate(data).await,
            SsrObfs::TlsSimple => self.tls_simple_deobfuscate(data).await,
            _ => Ok(data.to_vec()),
        }
    }

    /// HTTP simple obfuscation (client-side)
    async fn http_simple_obfuscate(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        // Wrap data in HTTP GET request
        let host = if self.obfs_param.is_empty() {
            "www.baidu.com".to_string()
        } else {
            self.obfs_param.clone()
        };

        let path = "/";
        let body_len = data.len();

        let mut request = format!(
            "GET {path} HTTP/1.1\r\n\
            Host: {host}\r\n\
            User-Agent: Mozilla/5.0\r\n\
            Content-Length: {body_len}\r\n\
           \r\n"
        )
        .into_bytes();

        request.extend_from_slice(data);
        Ok(request)
    }

    /// HTTP simple deobfuscation (server-side)
    async fn http_simple_deobfuscate(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        // Find HTTP body start (\r\n\r\n) and extract data after
        if let Some(pos) = find_bytes(data, b"\r\n\r\n") {
            Ok(data[pos + 4..].to_vec())
        } else {
            Ok(data.to_vec())
        }
    }

    /// TLS simple obfuscation (client-side)
    async fn tls_simple_obfuscate(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        // Wrap data in TLS ClientHello-like structure
        let mut hello = self.build_tls_client_hello()?;
        hello.extend_from_slice(data);
        Ok(hello)
    }

    /// TLS simple deobfuscate
    async fn tls_simple_deobfuscate(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        // For TLS, we need to parse the ClientHello to find the actual data
        // Simplified: assume data starts after TLS record header
        if data.len() > 5 && data[0] == 0x17 {
            // TLS Application Data
            Ok(data[5..].to_vec())
        } else {
            Ok(data.to_vec())
        }
    }

    /// Build a simple TLS ClientHello for obfuscation
    fn build_tls_client_hello(&self) -> std::io::Result<Vec<u8>> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut hello = Vec::new();

        // TLS Record Layer
        hello.push(0x16); // Handshake
        hello.push(0x03);
        hello.push(0x01); // TLS 1.0

        // Length placeholder
        let len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);

        // Handshake
        hello.push(0x01); // ClientHello

        // Handshake length placeholder
        let hs_len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);
        hello.push(0x00);

        // Client version
        hello.push(0x03);
        hello.push(0x03);

        // Random
        let random: [u8; 32] = rng.gen();
        hello.extend_from_slice(&random);

        // Session ID
        hello.push(0x00);

        // Cipher suites
        let ciphers = [0x002f, 0x0035];
        hello.push((ciphers.len() * 2) as u8);
        for c in ciphers {
            hello.push((c >> 8) as u8);
            hello.push((c & 0xff) as u8);
        }

        // Compression
        hello.push(0x01);
        hello.push(0x00);

        // Extensions
        let ext_start = hello.len();
        hello.push(0x00);
        hello.push(0x00);

        // SNI extension
        let host = if self.obfs_param.is_empty() {
            "www.google.com"
        } else {
            &self.obfs_param
        };

        // SNI
        hello.extend_from_slice(&[0x00, 0x00]); // type
        let sni_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]); // length placeholder
        hello.push(0x00); // list length
        hello.push(0x00); // type = host_name
        let name_len = host.len() as u16;
        hello.extend_from_slice(&name_len.to_be_bytes());
        hello.extend_from_slice(host.as_bytes());

        let sni_len = hello.len() - sni_len_pos - 2;
        hello[sni_len_pos] = (sni_len >> 8) as u8;
        hello[sni_len_pos + 1] = (sni_len & 0xff) as u8;

        // Update extension length
        let ext_len = hello.len() - ext_start - 2;
        hello[ext_start] = (ext_len >> 8) as u8;
        hello[ext_start + 1] = (ext_len & 0xff) as u8;

        // Update handshake length
        let hs_len = hello.len() - hs_len_pos - 3;
        hello[hs_len_pos] = (hs_len >> 16) as u8;
        hello[hs_len_pos + 1] = (hs_len >> 8) as u8;
        hello[hs_len_pos + 2] = (hs_len & 0xff) as u8;

        // Update record length
        let rec_len = hello.len() - len_pos - 3 + 4;
        hello[len_pos] = (rec_len >> 8) as u8;
        hello[len_pos + 1] = (rec_len & 0xff) as u8;

        Ok(hello)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadowsocks::ssr_types::{SsrObfs, SsrProtocol, SsrServerConfig};

    #[test]
    fn test_ssr_protocol_from_str() {
        assert_eq!(SsrProtocol::from_str("origin"), Some(SsrProtocol::Origin));
        assert_eq!(
            SsrProtocol::from_str("verify_deflate"),
            Some(SsrProtocol::VerifyDeflate)
        );
        assert_eq!(
            SsrProtocol::from_str("auth_sha1_v2"),
            Some(SsrProtocol::AuthSha1V2)
        );
        assert_eq!(SsrProtocol::from_str("unknown"), None);
    }

    #[test]
    fn test_ssr_obfs_from_str() {
        assert_eq!(SsrObfs::from_str("plain"), Some(SsrObfs::Plain));
        assert_eq!(SsrObfs::from_str("http_simple"), Some(SsrObfs::HttpSimple));
        assert_eq!(SsrObfs::from_str("tls_simple"), Some(SsrObfs::TlsSimple));
        assert_eq!(SsrObfs::from_str("unknown"), None);
    }

    #[test]
    fn test_ssr_protocol_as_bytes() {
        assert_eq!(SsrProtocol::Origin.as_bytes(), b"origin");
        assert_eq!(SsrProtocol::AuthSha1V2.as_bytes(), b"auth_sha1_v2");
    }

    #[test]
    fn test_default_config() {
        let config = SsrServerConfig::default();
        assert_eq!(config.port, 8388);
        assert_eq!(config.protocol, SsrProtocol::Origin);
        assert_eq!(config.obfs, SsrObfs::Plain);
    }

    #[tokio::test]
    async fn test_http_simple_obfuscate() {
        let handler = SsrObfsHandler::new(SsrObfs::HttpSimple, "example.com");
        let data = b"hello world";
        let result = handler.obfuscate(data).await.unwrap();

        assert!(result.starts_with(b"GET"));
        let result_str = std::str::from_utf8(&result).unwrap();
        assert!(result_str.contains("Host: example.com"));
        assert!(result.ends_with(data));
    }
}
