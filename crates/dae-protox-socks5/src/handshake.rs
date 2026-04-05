//! SOCKS5 握手和问候模块（RFC 1928）
//!
//! 处理 SOCKS5 的问候和认证方法协商（阶段1），以及可选的认证（阶段2）。

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::auth::AuthHandler;
use super::consts;

/// SOCKS5 握手处理器
///
/// 负责处理 SOCKS5 的问候和认证方法协商。
pub struct Handshake {
    /// 认证处理器
    auth_handler: Arc<dyn AuthHandler>,
}

impl Handshake {
    /// 创建新的握手处理器
    ///
    /// # 参数
    /// - `auth_handler`: 认证处理器
    pub fn new(auth_handler: Arc<dyn AuthHandler>) -> Self {
        Self { auth_handler }
    }

    /// 处理问候（阶段1）
    ///
    /// 接收客户端问候，选择认证方法，并发送响应。
    ///
    /// # 参数
    /// - `client`: 客户端 TCP 流
    ///
    /// # 返回值
    /// - `Ok(u8)`: 选择的认证方法
    /// - `Err`: 处理失败
    ///
    /// # 问候格式
    ///
    /// 客户端请求：
    /// ```
    /// +----+----------+----------+
    /// |VER | NMETHODS | METHODS  |
    /// +----+----------+----------+
    /// | 1  |    1     |  1-255   |
    /// +----+----------+----------+
    /// ```
    ///
    /// 服务器响应：
    /// ```
    /// +----+--------+
    /// |VER | METHOD |
    /// +----+--------+
    /// | 1  |   1    |
    /// +----+--------+
    /// ```
    pub async fn handle_greeting(&self, client: &mut TcpStream) -> std::io::Result<u8> {
        // Read greeting: VER (1) + NMETHODS (1) + METHODS (1-255)
        let mut header = [0u8; 2];
        client.read_exact(&mut header).await?;

        let ver = header[0];
        let nmethods = header[1];

        if ver != consts::VER {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid SOCKS version: {ver}"),
            ));
        }

        // Read methods
        let mut methods = vec![0u8; nmethods as usize];
        client.read_exact(&mut methods).await?;

        // Select auth method
        let selected = self.select_auth_method(&methods);

        // Send method selection response: VER (1) + METHOD (1)
        client.write_all(&[consts::VER, selected]).await?;

        Ok(selected)
    }

    /// 选择认证方法
    ///
    /// 根据客户端支持的方法和服务器配置，选择最优的认证方法。
    ///
    /// # 选择优先级
    ///
    /// 1. 如果客户端支持 NO_AUTH 且服务器允许无认证 → 选择 NO_AUTH
    /// 2. 如果客户端支持 USERNAME_PASSWORD 且服务器有用户名/密码配置 → 选择 USERNAME_PASSWORD
    /// 3. 否则 → 选择 NO_ACCEPTABLE
    ///
    /// # 参数
    /// - `client_methods`: 客户端支持的方法列表
    ///
    /// # 返回值
    /// - 选中的认证方法（NO_AUTH、USERNAME_PASSWORD 或 NO_ACCEPTABLE）
    fn select_auth_method(&self, client_methods: &[u8]) -> u8 {
        // Check if NO_AUTH is offered and allowed
        if client_methods.contains(&consts::NO_AUTH) && !self.auth_handler.requires_auth() {
            return consts::NO_AUTH;
        }

        // Check if username/password is offered and we support it
        if client_methods.contains(&consts::USERNAME_PASSWORD) {
            // Check if we have a username/password handler
            if self.auth_handler.requires_auth() {
                return consts::USERNAME_PASSWORD;
            }
        }

        // No acceptable method
        consts::NO_ACCEPTABLE
    }

    /// 处理用户名/密码认证（阶段2，RFC 1929）
    ///
    /// 验证客户端提供的用户名和密码。
    ///
    /// # 参数
    /// - `client`: 客户端 TCP 流
    ///
    /// # 返回值
    /// - `Ok(())`: 认证成功
    /// - `Err`: 认证失败
    ///
    /// # 认证格式
    ///
    /// 客户端请求：
    /// ```
    /// +----+------+----------+------+----------+
    /// |VER | ULEN |  UNAME   | PLEN |  PASSWD |
    /// +----+------+----------+------+----------+
    /// | 1  |  1   | 1-255   |  1   | 1-255   |
    /// +----+------+----------+------+----------+
    /// ```
    ///
    /// 服务器响应：
    /// ```
    /// +----+--------+
    /// |VER | STATUS |
    /// +----+--------+
    /// | 1  |   1    |
    /// +----+--------+
    /// ```
    pub async fn handle_authentication(&self, client: &mut TcpStream) -> std::io::Result<()> {
        // Read: VER (1) + USERNAME_LEN (1) + USERNAME + PASSWORD_LEN (1) + PASSWORD
        let mut version = [0u8; 1];
        client.read_exact(&mut version).await?;

        if version[0] != 0x01 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid auth protocol version",
            ));
        }

        let mut ulen = [0u8; 1];
        client.read_exact(&mut ulen).await?;
        let username_len = ulen[0] as usize;

        let mut username_buf = vec![0u8; username_len];
        client.read_exact(&mut username_buf).await?;
        let username = String::from_utf8(username_buf).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid username")
        })?;

        let mut plen = [0u8; 1];
        client.read_exact(&mut plen).await?;
        let password_len = plen[0] as usize;

        let mut password_buf = vec![0u8; password_len];
        client.read_exact(&mut password_buf).await?;
        let password = String::from_utf8(password_buf).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid password")
        })?;

        // Validate credentials
        let valid = self.auth_handler.validate_credentials(&username, &password);

        // Send response: VER (1) + STATUS (1)
        if valid {
            client.write_all(&[0x01, 0x00]).await?; // Success
            Ok(())
        } else {
            client.write_all(&[0x01, 0x01]).await?; // Failure
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid credentials",
            ))
        }
    }
}
