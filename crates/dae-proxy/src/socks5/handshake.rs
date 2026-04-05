//! SOCKS5 handshake and greeting (RFC 1928)
//!
//! Phase 1: Greeting and authentication method selection
//! Phase 2: Authentication (if required)

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::auth::AuthHandler;
use super::consts;

/// SOCKS5 handshake handler
pub struct Handshake {
    auth_handler: Arc<dyn AuthHandler>,
}

impl Handshake {
    pub fn new(auth_handler: Arc<dyn AuthHandler>) -> Self {
        Self { auth_handler }
    }

    /// Handle SOCKS5 greeting (phase 1)
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

    /// Select authentication method based on client preferences
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

    /// Handle username/password authentication (RFC 1929)
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
