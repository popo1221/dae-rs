//! SSR protocol types and enumerations

use std::time::Duration;

/// SSR protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrProtocol {
    /// Original protocol (no obfuscation)
    Origin,
    /// Verify deflate protocol
    VerifyDeflate,
    /// 2-factor authentication
    TwoAuth,
    /// Auth SHA1 V2
    AuthSha1V2,
    /// Auth AES128 MD5
    AuthAES128MD5,
    /// Auth AES128 SHA1
    AuthAES128SHA1,
    /// Auth chain
    AuthChain,
}

#[allow(clippy::should_implement_trait)]
impl SsrProtocol {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "origin" | "" => Some(SsrProtocol::Origin),
            "verify_deflate" | "verify-deflate" => Some(SsrProtocol::VerifyDeflate),
            "2_auth" | "2auth" => Some(SsrProtocol::TwoAuth),
            "auth_sha1_v2" | "auth-sha1-v2" => Some(SsrProtocol::AuthSha1V2),
            "auth_aes128_md5" | "auth-aes128-md5" => Some(SsrProtocol::AuthAES128MD5),
            "auth_aes128_sha1" | "auth-aes128-sha1" => Some(SsrProtocol::AuthAES128SHA1),
            "auth_chain" | "auth-chain" => Some(SsrProtocol::AuthChain),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            SsrProtocol::Origin => b"origin",
            SsrProtocol::VerifyDeflate => b"verify_deflate",
            SsrProtocol::TwoAuth => b"2_auth",
            SsrProtocol::AuthSha1V2 => b"auth_sha1_v2",
            SsrProtocol::AuthAES128MD5 => b"auth_aes128_md5",
            SsrProtocol::AuthAES128SHA1 => b"auth_aes128_sha1",
            SsrProtocol::AuthChain => b"auth_chain",
        }
    }
}

/// SSR obfuscation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrObfs {
    /// No obfuscation
    Plain,
    /// HTTP simple obfuscation
    HttpSimple,
    /// TLS simple obfuscation
    TlsSimple,
    /// HTTP post obfuscation
    HttpPost,
    /// TLS 1.2 ticket obfuscation
    Tls12Ticket,
    /// TLS 1.2 ticket auth obfuscation
    Tls12TicketAuth,
}

#[allow(clippy::should_implement_trait)]
impl SsrObfs {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "plain" | "" => Some(SsrObfs::Plain),
            "http_simple" | "http-simple" => Some(SsrObfs::HttpSimple),
            "tls_simple" | "tls-simple" => Some(SsrObfs::TlsSimple),
            "http_post" | "http-post" => Some(SsrObfs::HttpPost),
            "tls1.2_ticket" | "tls1.2-ticket" => Some(SsrObfs::Tls12Ticket),
            "tls1.2_ticket_auth" | "tls1.2-ticket-auth" => Some(SsrObfs::Tls12TicketAuth),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            SsrObfs::Plain => b"plain",
            SsrObfs::HttpSimple => b"http_simple",
            SsrObfs::TlsSimple => b"tls_simple",
            SsrObfs::HttpPost => b"http_post",
            SsrObfs::Tls12Ticket => b"tls1.2_ticket",
            SsrObfs::Tls12TicketAuth => b"tls1.2_ticket_auth",
        }
    }
}

/// SSR server configuration
#[derive(Debug, Clone)]
pub struct SsrServerConfig {
    /// Server address
    pub addr: String,
    /// Server port
    pub port: u16,
    /// Password (with protocol prefix)
    pub password: String,
    /// SSR protocol type
    pub protocol: SsrProtocol,
    /// SSR obfuscation type
    pub obfs: SsrObfs,
    /// Protocol parameters (optional)
    pub protocol_param: String,
    /// Obfs parameters (optional)
    pub obfs_param: String,
}

impl Default for SsrServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 8388,
            password: String::new(),
            protocol: SsrProtocol::Origin,
            obfs: SsrObfs::Plain,
            protocol_param: String::new(),
            obfs_param: String::new(),
        }
    }
}

/// SSR client configuration
#[derive(Debug, Clone)]
pub struct SsrClientConfig {
    /// Local listen address
    pub listen_addr: std::net::SocketAddr,
    /// Remote server configuration
    pub server: SsrServerConfig,
    /// TCP connection timeout
    pub tcp_timeout: Duration,
    /// UDP session timeout
    pub udp_timeout: Duration,
}

impl Default for SsrClientConfig {
    fn default() -> Self {
        Self {
            listen_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 1080)),
            server: SsrServerConfig::default(),
            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(30),
        }
    }
}

/// Find subslice in byte slice
pub fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
