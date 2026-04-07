//! VMess 处理器实现模块
//!
//! 本模块实现 VMess AEAD-2022 协议处理器：
//! - 头部加密/解密（AES-256-GCM）
//! - 密钥派生（HMAC-SHA256）
//! - TCP 连接处理
//! - UDP 数据包处理
//!
//! # VMess-AEAD-2022 工作原理
//! 1. 使用 HMAC-SHA256(user_id, "VMess AEAD") 派生 user_key
//! 2. 使用 nonce 和 user_key 派生 request_key 和 request_iv
//! 3. 使用 AES-256-GCM 解密请求头

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

use super::config::{VmessClientConfig, VmessTargetAddress};
use crate::VmessError;
use dae_protocol_core::{Handler, ProtocolType};

/// VMess 协议处理器
///
/// 负责处理 VMess AEAD-2022 协议的客户端连接。
///
/// # 字段说明
/// - `config`: VMess 客户端配置
pub struct VmessHandler {
    /// VMess 客户端配置
    config: VmessClientConfig,
}

impl VmessHandler {
    /// 创建新的 VMess 处理器
    ///
    /// # 参数
    /// - `config`: VMess 客户端配置
    pub fn new(config: VmessClientConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建处理器
    #[allow(dead_code)]
    pub fn new_default() -> Self {
        Self {
            config: VmessClientConfig::default(),
        }
    }

    /// 获取监听地址
    #[allow(dead_code)]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    /// 获取当前时间戳（自 Unix epoch 以来的秒数）
    #[allow(dead_code)]
    pub fn timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// 计算 HMAC-SHA256
    ///
    /// # 参数
    /// - `key`: HMAC 密钥
    /// - `data`: 待认证的数据
    ///
    /// # 返回
    /// 32 字节的 HMAC-SHA256 输出
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mac = HmacSha256::new_from_slice(key).expect("HMAC can take any key size");
        let result = mac.chain_update(data).finalize();
        result.into_bytes().into()
    }

    /// 从 user_id 派生 VMess AEAD-2022 user_key
    ///
    /// # VMess-AEAD-2022 密钥派生
    /// `user_key = HMAC-SHA256(user_id, "VMess AEAD")`
    ///
    /// # 参数
    /// - `user_id`: 用户 ID（UUID 字符串）
    ///
    /// # 返回
    /// 32 字节的 user_key
    ///
    /// # 说明
    /// 使用固定盐值 "VMess AEAD" 对 user_id 进行 HMAC-SHA256 运算，
    /// 得到用于后续密钥派生的 user_key。
    pub fn derive_user_key(user_id: &str) -> [u8; 32] {
        let key = Self::hmac_sha256(user_id.as_bytes(), b"VMess AEAD");
        key
    }

    /// 从 user_key 和 nonce 派生请求加密密钥和 IV
    ///
    /// # 密钥派生流程
    /// 1. `auth_result = HMAC-SHA256(user_key, nonce)`
    /// 2. `request_key = HKDF-Expand-SHA256(auth_result, "VMess header" || 0x01, 32)`
    /// 3. `request_iv = HMAC-SHA256(auth_result, nonce)[:12]`
    ///
    /// # 参数
    /// - `user_key`: 32 字节的用户密钥
    /// - `nonce`: 16 字节的随机数（Nonce）
    ///
    /// # 返回
    /// - `(request_key, request_iv)`: 请求加密密钥（32 字节）和 IV（12 字节）
    ///
    /// # 注意
    /// - request_key 用于 AES-256-GCM 加密/解密
    /// - request_iv 是 GCM 模式的初始化向量
    pub fn derive_request_key_iv(user_key: &[u8; 32], nonce: &[u8]) -> ([u8; 32], [u8; 12]) {
        // request_auth_key = HMAC-SHA256(user_key, nonce)
        let auth_result = Self::hmac_sha256(user_key, nonce);

        // request_key = HKDF-Expand-SHA256(auth_key, "VMess header", 32 bytes)
        let mut request_key = [0u8; 32];
        {
            use hmac::{Hmac, Mac};
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mac = HmacSha256::new_from_slice(&auth_result).expect("HMAC can take any key size");
            let mut info_with_tweak = [0u8; 13];
            info_with_tweak[..12].copy_from_slice(b"VMess header");
            info_with_tweak[12] = 0x01;
            let result = mac.chain_update(info_with_tweak).finalize();
            request_key.copy_from_slice(&result.into_bytes()[..32]);
        }

        // request_iv = HMAC-SHA256(auth_key, nonce) [first 12 bytes]
        let iv_result = Self::hmac_sha256(&auth_result, nonce);
        let mut request_iv = [0u8; 12];
        request_iv.copy_from_slice(&iv_result[..12]);

        (request_key, request_iv)
    }

    /// 解密 VMess AEAD-2022 头部
    ///
    /// # VMess AEAD 加密格式
    /// ```text
    /// [16-byte nonce][encrypted data][16-byte auth tag]
    /// ```
    ///
    /// # 参数
    /// - `user_key`: 32 字节的用户密钥
    /// - `encrypted`: 加密的头部数据（至少 32 字节）
    ///
    /// # 返回
    /// - `Ok(Vec<u8>)`: 解密后的头部数据
    /// - `Err(&str)`: 解密失败原因
    ///
    /// # 失败原因
    /// - `"encrypted header too short (< 32 bytes)"`: 数据太短
    /// - `"failed to create AES-GCM cipher"`: 密码创建失败
    /// - `"AES-GCM decryption failed (auth tag mismatch or corrupt data)"`: 认证标签不匹配
    ///
    /// # 安全说明
    /// GCM 模式的认证标签可防止头部被篡改。
    /// 如果数据被修改，解密会失败并返回错误。
    pub fn decrypt_header(user_key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, &'static str> {
        use aes_gcm::aead::KeyInit;

        if encrypted.len() < 32 {
            return Err("encrypted header too short (< 32 bytes)");
        }

        let nonce = &encrypted[..16];
        let ciphertext_with_tag = &encrypted[16..];

        // 派生 request_key 和 request_iv
        let (request_key, _) = Self::derive_request_key_iv(user_key, nonce);

        let cipher = Aes256Gcm::new_from_slice(&request_key)
            .map_err(|_| "failed to create AES-GCM cipher")?;

        let nonce_bytes: [u8; 12] = match nonce[..12].try_into() {
            Ok(n) => n,
            Err(_) => return Err("nonce is not 16 bytes"),
        };
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext_with_tag)
            .map_err(|_| "AES-GCM decryption failed (auth tag mismatch or corrupt data)")
    }

    /// 处理 VMess TCP 连接
    ///
    /// # VMess AEAD 协议处理流程
    /// 1. 读取 4 字节长度前缀（大端序）
    /// 2. 读取加密的头部数据
    /// 3. 派生 user_key 并解密头部
    /// 4. 解析目标地址和端口
    /// 5. 连接到上游 VMess 服务器
    /// 6. 转发数据
    ///
    /// # 参数
    /// - `client`: 客户端 TCP 连接
    ///
    /// # 头部格式
    /// 加密部分包含：address type + address + port + ...
    pub async fn handle(self: Arc<Self>, mut client: TcpStream) -> Result<(), VmessError> {
        let client_addr = client.peer_addr()?;

        // 读取长度前缀（4 字节，大端序）
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await?;
        let header_len = u32::from_be_bytes(len_buf) as usize;

        // 防止过大头部（DoS 防护）
        if header_len > 65535 {
            warn!(
                "VMess TCP: {} header_len {} too large",
                client_addr, header_len
            );
            return Err(VmessError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VMess header too large",
            )));
        }

        // 读取加密的头部
        let mut encrypted_header = vec![0u8; header_len];
        client.read_exact(&mut encrypted_header).await?;

        debug!("VMess TCP: {} header_len={}", client_addr, header_len);

        // 从 user_id 派生 user_key
        let user_key = Self::derive_user_key(&self.config.server.user_id);

        // 解密 VMess AEAD 头部
        let decrypted_header = match Self::decrypt_header(&user_key, &encrypted_header) {
            Ok(header) => header,
            Err(e) => {
                warn!(
                    "VMess TCP: {} header decryption failed: {} — dropping connection",
                    client_addr, e
                );
                return Err(VmessError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("VMess header decryption failed: {}", e),
                )));
            }
        };

        // 解析解密后的 VMess 头部
        let (target_addr, target_port) =
            match VmessTargetAddress::parse_from_bytes(&decrypted_header) {
                Some((addr, port)) => (addr, port),
                None => {
                    warn!(
                        "VMess TCP: {} standard header parsing failed, using fallback heuristic. \
                    First 16 bytes (hex): {:?}",
                        client_addr,
                        decrypted_header
                            .iter()
                            .take(16)
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                    );

                    // 回退解析：尝试在解密数据中查找地址类型标记
                    if let Some(pos) = decrypted_header
                        .iter()
                        .position(|&b| matches!(b, 0x01..=0x03))
                    {
                        debug!(
                            "VMess TCP: {} found address type marker 0x{:02x} at pos {}, \
                        trying fallback parse",
                            client_addr, decrypted_header[pos], pos
                        );

                        if let Some(result) =
                            VmessTargetAddress::parse_from_bytes(&decrypted_header[pos..])
                        {
                            debug!(
                                "VMess TCP: {} fallback parsing succeeded at pos {}",
                                client_addr, pos
                            );
                            (result.0, result.1)
                        } else {
                            error!(
                                "VMess TCP: {} fallback parsing at pos {} also failed.",
                                client_addr, pos
                            );
                            return Err(VmessError::Io(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid VMess decrypted header",
                            )));
                        }
                    } else {
                        error!(
                            "VMess TCP: {} no valid address type (0x01/0x02/0x03) found in \
                        decrypted header ({} bytes).",
                            client_addr,
                            decrypted_header.len()
                        );
                        return Err(VmessError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "no address in VMess header",
                        )));
                    }
                }
            };

        info!(
            "VMess TCP: {} -> {}:{} (via {}:{})",
            client_addr, target_addr, target_port, self.config.server.addr, self.config.server.port
        );

        // 连接到上游 VMess 服务器
        let remote_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
        let timeout = self.config.tcp_timeout;

        let remote = match tokio::time::timeout(timeout, TcpStream::connect(&remote_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(VmessError::Io(e)),
            Err(_) => {
                return Err(VmessError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection to VMess server timed out",
                )));
            }
        };

        debug!("Connected to VMess server {}", remote_addr);

        // 在客户端和服务器之间转发数据
        Ok(dae_relay::relay_bidirectional(client, remote).await?)
    }

    /// 处理 UDP 流量
    ///
    /// # 参数
    /// - `client`: 本地 UDP socket
    ///
    /// # 处理流程
    /// 1. 接收 UDP 数据包
    /// 2. 解析目标地址
    /// 3. 发送到上游 VMess 服务器
    /// 4. 接收响应并返回
    #[allow(dead_code)]
    pub async fn handle_udp(self: Arc<Self>, client: UdpSocket) -> std::io::Result<()> {
        const MAX_UDP_SIZE: usize = 65535;
        let mut buf = vec![0u8; MAX_UDP_SIZE];

        loop {
            let (n, client_addr) = client.recv_from(&mut buf).await?;

            if n < 5 {
                continue;
            }

            let (target_addr, target_port, payload_offset) =
                match VmessTargetAddress::parse_from_bytes(&buf) {
                    Some((addr, port)) => (addr, port, 0),
                    None => continue,
                };

            let payload = &buf[payload_offset..n];

            debug!(
                "VMess UDP: {} -> {}:{} ({} bytes)",
                client_addr,
                target_addr,
                target_port,
                payload.len()
            );

            let server_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
            let server_socket = UdpSocket::bind("0.0.0.0:0").await?;
            server_socket.send_to(payload, &server_addr).await?;

            let mut response_buf = vec![0u8; MAX_UDP_SIZE];
            if let Ok(Ok((m, _))) = tokio::time::timeout(
                self.config.udp_timeout,
                server_socket.recv_from(&mut response_buf),
            )
            .await
            {
                client.send_to(&response_buf[..m], &client_addr).await?;
            }
        }
    }
}

/// 为 VmessHandler 实现 Handler trait
#[async_trait]
impl Handler for VmessHandler {
    type Config = VmessClientConfig;

    fn name(&self) -> &'static str {
        "vmess"
    }

    fn protocol(&self) -> ProtocolType {
        ProtocolType::Vmess
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }

    async fn handle(self: Arc<Self>, stream: TcpStream) -> std::io::Result<()> {
        self.handle(stream).await.map_err(std::io::Error::from)
    }
}

/// VMess tracking information for protocol-specific tracking
#[derive(Debug, Default, Clone)]
pub struct VmessTrackingInfo {
    /// User ID (UUID)
    pub user_id: String,
    /// Security level
    pub security_level: String,
    /// Target address
    pub target_addr: String,
    /// Inbound bytes
    pub bytes_in: u64,
    /// Outbound bytes
    pub bytes_out: u64,
}

impl VmessTrackingInfo {
    /// Create a new VMess tracking info
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from user_id
    pub fn with_user_id(user_id: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            ..Default::default()
        }
    }

    /// Set security level
    pub fn with_security_level(mut self, level: &str) -> Self {
        self.security_level = level.to_string();
        self
    }

    /// Set target address
    pub fn with_target_addr(mut self, addr: &str) -> Self {
        self.target_addr = addr.to_string();
        self
    }

    /// Set bytes transferred
    pub fn with_bytes(mut self, bytes_in: u64, bytes_out: u64) -> Self {
        self.bytes_in = bytes_in;
        self.bytes_out = bytes_out;
        self
    }
}

impl VmessHandler {
    /// Handle VMess connection with protocol tracking
    ///
    /// This method extends `handle` by capturing protocol-specific
    /// tracking information including user_id, security level, and target address.
    ///
    /// # Returns
    ///
    /// - `Ok(((), VmessTrackingInfo))`: Success with tracking info
    /// - `Err(VmessError)`: Connection error
    pub async fn handle_with_tracking(
        self: Arc<Self>,
        mut client: TcpStream,
    ) -> Result<((), VmessTrackingInfo), VmessError> {
        let client_addr = client.peer_addr()?;

        // Read length prefix (4 bytes, big-endian)
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await?;
        let header_len = u32::from_be_bytes(len_buf) as usize;

        // Prevent oversized headers (DoS protection)
        if header_len > 65535 {
            warn!(
                "VMess TCP: {} header_len {} too large",
                client_addr, header_len
            );
            return Err(VmessError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VMess header too large",
            )));
        }

        // Read encrypted header
        let mut encrypted_header = vec![0u8; header_len];
        client.read_exact(&mut encrypted_header).await?;

        debug!("VMess TCP: {} header_len={}", client_addr, header_len);

        // Derive user_key from user_id
        let user_key = Self::derive_user_key(&self.config.server.user_id);

        // Decrypt VMess AEAD header
        let decrypted_header = match Self::decrypt_header(&user_key, &encrypted_header) {
            Ok(header) => header,
            Err(e) => {
                warn!(
                    "VMess TCP: {} header decryption failed: {} — dropping connection",
                    client_addr, e
                );
                return Err(VmessError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("VMess header decryption failed: {}", e),
                )));
            }
        };

        // Parse target address and port
        let (target_addr, target_port) =
            match VmessTargetAddress::parse_from_bytes(&decrypted_header) {
                Some((addr, port)) => (addr, port),
                None => {
                    warn!(
                        "VMess TCP: {} standard header parsing failed, using fallback heuristic.",
                        client_addr
                    );
                    // Fallback parsing
                    if let Some(pos) = decrypted_header
                        .iter()
                        .position(|&b| matches!(b, 0x01..=0x03))
                    {
                        if let Some(result) =
                            VmessTargetAddress::parse_from_bytes(&decrypted_header[pos..])
                        {
                            (result.0, result.1)
                        } else {
                            return Err(VmessError::Io(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid VMess decrypted header",
                            )));
                        }
                    } else {
                        return Err(VmessError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "no address in VMess header",
                        )));
                    }
                }
            };

        let target_str = format!("{}:{}", target_addr, target_port);

        info!(
            "VMess TCP: {} -> {} (via {}:{})",
            client_addr, target_str, self.config.server.addr, self.config.server.port
        );

        // Build tracking info
        let mut tracking_info = VmessTrackingInfo::with_user_id(&self.config.server.user_id)
            .with_target_addr(&target_str)
            .with_security_level("AEAD-2022");

        // Connect to upstream VMess server
        let remote_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
        let timeout = self.config.tcp_timeout;

        let remote = match tokio::time::timeout(timeout, TcpStream::connect(&remote_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(VmessError::Io(e)),
            Err(_) => {
                return Err(VmessError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection to VMess server timed out",
                )));
            }
        };

        debug!("Connected to VMess server {}", remote_addr);

        // Relay with stats
        let stats = match dae_relay::relay_bidirectional_with_stats(client, remote).await {
            Ok(s) => s,
            Err(e) => return Err(VmessError::Io(e)),
        };

        // Update tracking info with bytes
        tracking_info =
            tracking_info.with_bytes(stats.bytes_remote_to_client, stats.bytes_client_to_remote);

        Ok(((), tracking_info))
    }
}
