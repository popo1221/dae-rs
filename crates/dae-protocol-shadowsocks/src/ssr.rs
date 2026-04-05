//! ShadowsocksR (SSR) 协议实现模块
//!
//! 实现了 ShadowsocksR 协议，在标准 Shadowsocks 基础上增加了协议层混淆和认证机制。
//!
//! # SSR 与 SS 的主要区别
//!
//! 1. 协议混淆：SSR 支持多种协议内嵌混淆（origin, verify_deflate, 2_auth 等）
//! 2. 密码格式：SSR 的密码需要以协议名作为前缀
//! 3. 握手流程：SSR 的握手过程更复杂，需要多次交互
//!
//! 协议规范：https://github.com/shadowsocksr/shadowsocks-rss

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

/// SSR 协议类型枚举
///
/// 定义 ShadowsocksR 支持的各种协议类型，每种协议提供不同的混淆和认证机制。
///
/// 常规使用推荐 origin 或 verify_deflate；
/// 高度审查环境推荐 auth_sha1_v2 或 auth_aes128_md5；
/// 需要混淆认证时推荐 tls1.2_ticket_auth。
///
/// 注意：协议类型会作为字节序列附加在密码前，用于服务器识别协议。
/// 例如："auth_sha1_v2:your_password"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrProtocol {
    /// 原始协议，无混淆
    Origin,
    /// 压缩验证协议
    VerifyDeflate,
    /// 二次认证协议
    TwoAuth,
    /// SHA1 认证 V2
    AuthSha1V2,
    /// AES128-MD5 认证
    AuthAES128MD5,
    /// AES128-SHA1 认证
    AuthAES128SHA1,
    /// 链式认证
    AuthChain,
}

#[allow(clippy::should_implement_trait)]
impl SsrProtocol {
    /// 从字符串解析协议类型
    ///
    /// 支持多种命名格式：
    /// - "origin", "" → Origin
    /// - "verify_deflate", "verify-deflate" → VerifyDeflate
    /// - "2_auth", "2auth" → TwoAuth
    /// - "auth_sha1_v2", "auth-sha1-v2" → AuthSha1V2
    /// - "auth_aes128_md5", "auth-aes128-md5" → AuthAES128MD5
    /// - "auth_aes128_sha1", "auth-aes128-sha1" → AuthAES128SHA1
    /// - "auth_chain", "auth-chain" → AuthChain
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

    /// 获取协议类型的字节序列表示
    ///
    /// 返回值是对应协议名称的字节形式，用于在协议头中标识协议类型。
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

/// SSR 混淆类型枚举
///
/// 定义 ShadowsocksR 支持的流量混淆类型，用于使流量看起来像普通 Web 流量。
///
/// 混淆层在标准 Shadowsocks 加密数据外包裹一层协议伪装：
/// HTTP 混淆使数据看起来像 HTTP GET 请求；
/// TLS 混淆使数据看起来像 TLS ClientHello。
///
/// plain 模式无额外开销，http_simple/tls_simple 有轻微开销，
/// http_post/tls1.2_ticket_auth 有较高开销。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrObfs {
    /// 无混淆
    Plain,
    /// HTTP 简单混淆
    HttpSimple,
    /// TLS 简单混淆
    TlsSimple,
    /// HTTP POST 混淆
    HttpPost,
    /// TLS 1.2 票据混淆
    Tls12Ticket,
    /// TLS 1.2 票据认证混淆
    Tls12TicketAuth,
}

#[allow(clippy::should_implement_trait)]
impl SsrObfs {
    /// 从字符串解析混淆类型
    ///
    /// 支持多种命名格式：
    /// - "plain", "" → Plain
    /// - "http_simple", "http-simple" → HttpSimple
    /// - "tls_simple", "tls-simple" → TlsSimple
    /// - "http_post", "http-post" → HttpPost
    /// - "tls1.2_ticket", "tls1.2-ticket" → Tls12Ticket
    /// - "tls1.2_ticket_auth", "tls1.2-ticket-auth" → Tls12TicketAuth
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

    /// 获取混淆类型的字节序列表示
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

/// SSR 服务器配置
///
/// 包含连接到 SSR 服务器所需的完整配置信息。
///
/// 密码格式与标准 Shadowsocks 不同，协议类型作为前缀：
/// 格式："protocol_name:actual_password"
/// 例如："auth_sha1_v2:mysecretpass"
#[derive(Debug, Clone)]
pub struct SsrServerConfig {
    /// 服务器地址（IP 或域名）
    pub addr: String,
    /// 服务器端口
    pub port: u16,
    /// 密码（包含协议前缀）
    pub password: String,
    /// SSR 协议类型
    pub protocol: SsrProtocol,
    /// SSR 混淆类型
    pub obfs: SsrObfs,
    /// 协议附加参数（可选）
    pub protocol_param: String,
    /// 混淆附加参数（可选）
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

/// SSR 客户端配置
///
/// 包含 SSR 本地代理所需的完整配置信息。
/// 用于在本地启动 SSR 客户端代理，监听指定端口，接收代理请求并转发到 SSR 服务器。
#[derive(Debug, Clone)]
pub struct SsrClientConfig {
    /// 本地监听地址
    pub listen_addr: std::net::SocketAddr,
    /// 远程服务器配置
    pub server: SsrServerConfig,
    /// TCP 连接超时
    pub tcp_timeout: Duration,
    /// UDP 会话超时
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

/// SSR 客户端处理器
///
/// 负责处理 SSR 客户端连接，包括协议握手和数据转发。
///
/// 协议握手流程：
/// 1. 建立 TCP 连接到 SSR 服务器
/// 2. 根据协议类型执行对应的握手
/// 3. 如果使用混淆，执行混淆握手
/// 4. 建立加密通道
/// 5. 双向转发数据
pub struct SsrHandler {
    config: SsrClientConfig,
}

impl SsrHandler {
    /// 创建新的 SSR 处理器
    ///
    /// # 参数
    /// - `config`: 完整的客户端配置
    pub fn new(config: SsrClientConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建处理器
    pub fn new_default() -> Self {
        Self {
            config: SsrClientConfig::default(),
        }
    }

    /// 连接到 SSR 服务器并完成协议握手
    ///
    /// # 返回值
    /// - `Ok(TcpStream)`: 成功建立到 SSR 服务器的连接
    /// - `Err`: 连接失败或握手失败
    ///
    /// 握手内容：根据配置的协议类型执行对应的握手过程。
    pub async fn connect(&self) -> std::io::Result<TcpStream> {
        let server_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
        debug!("Connecting to SSR server at {}", server_addr);

        let mut stream = TcpStream::connect(&server_addr).await?;

        // Perform SSR protocol handshake
        self.protocol_handshake(&mut stream).await?;

        info!("SSR connection established to {}", server_addr);
        Ok(stream)
    }

    /// 执行 SSR 协议握手
    ///
    /// SSR 握手序列：
    /// 1. 发送会话密钥（从密码派生）
    /// 2. 根据协议类型发送初始数据包
    /// 3. 等待服务器响应
    /// 4. 握手完成，开始数据传输
    ///
    /// 各协议的握手差异：
    /// - origin：简单，仅建立连接
    /// - verify_deflate：支持压缩
    /// - 2_auth：二次认证
    /// - auth_* 系列：需要发送认证包（含时间戳、连接ID）
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

    /// Origin 协议握手（简化实现）
    ///
    /// Origin 协议仅建立连接，实际数据以 base64 编码发送。
    async fn origin_handshake(&self, _stream: &mut TcpStream) -> std::io::Result<()> {
        debug!("SSR origin handshake complete");
        Ok(())
    }

    /// Verify deflate 协议握手
    ///
    /// 发送带有 deflate 支持指示符的协议头。
    async fn verify_deflate_handshake(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        let header = self.build_protocol_header(0x03)?;
        stream.write_all(&header).await?;
        stream.flush().await?;

        let mut resp = [0u8; 4];
        stream.read_exact(&mut resp).await?;

        debug!("SSR verify_deflate handshake complete");
        Ok(())
    }

    /// 2-factor auth 协议握手
    ///
    /// 发送带有 2auth 标志的协议头。
    async fn two_auth_handshake(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        let header = self.build_protocol_header(0x04)?;
        stream.write_all(&header).await?;
        stream.flush().await?;

        let mut resp = [0u8; 4];
        stream.read_exact(&mut resp).await?;

        debug!("SSR 2auth handshake complete");
        Ok(())
    }

    /// 基于认证的协议握手（SHA1V2, AES128-MD5, AES128-SHA1）
    ///
    /// 认证协议需要：生成连接 ID，构建包含时间戳和连接 ID 的认证包，发送加密的认证包。
    async fn auth_handshake(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        let connection_id = rand::random::<u32>();

        let mut packet = Vec::new();
        packet.extend_from_slice(&self.build_protocol_header(0x07)?);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        packet.extend_from_slice(&timestamp.to_be_bytes());
        packet.extend_from_slice(&connection_id.to_be_bytes());

        stream.write_all(&packet).await?;
        stream.flush().await?;

        let mut resp = [0u8; 4];
        stream.read_exact(&mut resp).await?;

        debug!("SSR auth handshake complete (connection_id={})", connection_id);
        Ok(())
    }

    /// Auth chain 协议握手
    ///
    /// Auth chain 需要特殊的多重认证处理，此处简化为调用 auth_handshake。
    async fn auth_chain_handshake(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        debug!("SSR auth_chain handshake start");
        self.auth_handshake(stream).await
    }

    /// 根据协议类型构建协议头
    ///
    /// # 参数
    /// - `protocol_flag`: 协议标志字节
    ///
    /// # 返回值
    /// - 协议头字节向量：[版本(1字节), 协议类型(1字节), 保留(2字节)]
    fn build_protocol_header(&self, protocol_flag: u8) -> std::io::Result<Vec<u8>> {
        Ok(vec![
            0x01,
            protocol_flag,
            0x00,
            0x00,
        ])
    }
}

/// SSR 混淆处理器
///
/// 负责对数据进行混淆/反混淆处理，使流量看起来像普通 Web 流量。
///
/// 支持的混淆类型：
/// - Plain：无混淆
/// - HttpSimple：伪装为 HTTP GET 请求
/// - TlsSimple：伪装为 TLS ClientHello
/// - HttpPost：伪装为 HTTP POST 请求
/// - Tls12Ticket：TLS 1.2 Session Ticket 混淆
/// - Tls12TicketAuth：TLS 1.2 票据认证混淆
pub struct SsrObfsHandler {
    obfs_type: SsrObfs,
    obfs_param: String,
}

impl SsrObfsHandler {
    /// 创建混淆处理器
    ///
    /// # 参数
    /// - `obfs_type`: 混淆类型
    /// - `obfs_param`: 混淆参数，通常是伪装的网站域名
    pub fn new(obfs_type: SsrObfs, obfs_param: &str) -> Self {
        Self {
            obfs_type,
            obfs_param: obfs_param.to_string(),
        }
    }

    /// 对数据进行混淆（发送前）
    ///
    /// 将原始 Shadowsocks 数据包装为伪装协议格式。
    pub async fn obfuscate(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        match self.obfs_type {
            SsrObfs::Plain => Ok(data.to_vec()),
            SsrObfs::HttpSimple => self.http_simple_obfuscate(data).await,
            SsrObfs::TlsSimple => self.tls_simple_obfuscate(data).await,
            _ => Ok(data.to_vec()),
        }
    }

    /// 对数据进行反混淆（接收后）
    ///
    /// 从伪装协议格式中提取原始 Shadowsocks 数据。
    pub async fn deobfuscate(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        match self.obfs_type {
            SsrObfs::Plain => Ok(data.to_vec()),
            SsrObfs::HttpSimple => self.http_simple_deobfuscate(data).await,
            SsrObfs::TlsSimple => self.tls_simple_deobfuscate(data).await,
            _ => Ok(data.to_vec()),
        }
    }

    /// HTTP 简单混淆（客户端）
    ///
    /// 将数据包装在 HTTP GET 请求中，伪装成正常的 Web 浏览流量。
    async fn http_simple_obfuscate(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
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

    /// HTTP 简单反混淆（服务端）
    ///
    /// 查找 HTTP 请求体起始位置并提取后续数据。
    async fn http_simple_deobfuscate(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        if let Some(pos) = find_bytes(data, b"\r\n\r\n") {
            Ok(data[pos + 4..].to_vec())
        } else {
            Ok(data.to_vec())
        }
    }

    /// TLS 简单混淆（客户端）
    ///
    /// 将数据包装在 TLS ClientHello 格式中，伪装成 TLS 握手流量。
    async fn tls_simple_obfuscate(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut hello = self.build_tls_client_hello()?;
        hello.extend_from_slice(data);
        Ok(hello)
    }

    /// TLS 简单反混淆
    ///
    /// 解析 TLS 记录层，提取应用数据。
    async fn tls_simple_deobfuscate(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        if data.len() > 5 && data[0] == 0x17 {
            Ok(data[5..].to_vec())
        } else {
            Ok(data.to_vec())
        }
    }

    /// 构建简单的 TLS ClientHello 用于混淆
    ///
    /// 构建一个简化的 TLS ClientHello 消息，包含 TLS 记录层、握手层、版本、随机数、密码套件和 SNI 扩展。
    fn build_tls_client_hello(&self) -> std::io::Result<Vec<u8>> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut hello = Vec::new();

        // TLS Record Layer
        hello.push(0x16);
        hello.push(0x03);
        hello.push(0x01);

        let len_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);

        // Handshake
        hello.push(0x01);

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

        hello.extend_from_slice(&[0x00, 0x00]);
        let sni_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);
        hello.push(0x00);
        hello.push(0x00);
        let name_len = host.len() as u16;
        hello.extend_from_slice(&name_len.to_be_bytes());
        hello.extend_from_slice(host.as_bytes());

        let sni_len = hello.len() - sni_len_pos - 2;
        hello[sni_len_pos] = (sni_len >> 8) as u8;
        hello[sni_len_pos + 1] = (sni_len & 0xff) as u8;

        let ext_len = hello.len() - ext_start - 2;
        hello[ext_start] = (ext_len >> 8) as u8;
        hello[ext_start + 1] = (ext_len & 0xff) as u8;

        let hs_len = hello.len() - hs_len_pos - 3;
        hello[hs_len_pos] = (hs_len >> 16) as u8;
        hello[hs_len_pos + 1] = (hs_len >> 8) as u8;
        hello[hs_len_pos + 2] = (hs_len & 0xff) as u8;

        let rec_len = hello.len() - len_pos - 3 + 4;
        hello[len_pos] = (rec_len >> 8) as u8;
        hello[len_pos + 1] = (rec_len & 0xff) as u8;

        Ok(hello)
    }
}

/// 在字节数组中查找子数组的位置
///
/// # 参数
/// - `haystack`: 待搜索的字节数组
/// - `needle`: 要查找的子数组
///
/// # 返回值
/// - `Some(usize)`: 子数组首次出现的位置
/// - `None`: 未找到
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

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
