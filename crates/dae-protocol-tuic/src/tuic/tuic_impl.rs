//! TUIC 协议类型定义
//!
//! TUIC 协议的核心类型定义和处理器实现。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpStream;
use tracing::debug;

use dae_protocol_core::{Handler, HandlerConfig, ProtocolType};

use super::consts::{Context, ProxyResult, TuicError};

/// TUIC 配置
///
/// 配置 TUIC 代理客户端或服务器的运行参数。
#[derive(Debug, Clone)]
pub struct TuicConfig {
    pub token: String,
    pub uuid: String,
    pub server_name: String,
    pub congestion_control: String,
    pub max_idle_timeout: u32,
    pub max_udp_packet_size: u32,
    pub flow_control_window: u32,
}

impl Default for TuicConfig {
    fn default() -> Self {
        Self {
            token: String::new(),
            uuid: String::new(),
            server_name: "tuic.cloud".to_string(),
            congestion_control: "bbr".to_string(),
            max_idle_timeout: 15,
            max_udp_packet_size: 1400,
            flow_control_window: 8388608,
        }
    }
}

impl TuicConfig {
    /// 创建新的 TUIC 配置
    pub fn new(token: String, uuid: String) -> Self {
        Self {
            token,
            uuid,
            ..Default::default()
        }
    }

    /// 验证配置是否有效
    pub fn validate(&self) -> Result<(), TuicError> {
        if self.token.is_empty() {
            return Err(TuicError::InvalidConfig(
                "token cannot be empty".to_string(),
            ));
        }
        if self.uuid.is_empty() {
            return Err(TuicError::InvalidConfig("uuid cannot be empty".to_string()));
        }
        Ok(())
    }
}

/// TUIC 处理器
///
/// 提供 TUIC 协议入站/出站处理能力。
#[derive(Debug, Clone)]
pub struct TuicHandler {
    #[allow(dead_code)]
    config: TuicConfig,
}

impl TuicHandler {
    /// 创建新的 TUIC 处理器
    pub fn new(config: TuicConfig) -> Self {
        Self { config }
    }

    /// 处理入站连接
    pub async fn handle_inbound(&self, _ctx: &mut Context) -> ProxyResult {
        debug!("TUIC handler processing inbound connection");
        Ok(())
    }

    /// 处理出站连接
    pub async fn handle_outbound(&self, _ctx: &mut Context) -> ProxyResult {
        debug!("TUIC handler processing outbound connection");
        Ok(())
    }
}

/// 实现 Handler trait for TuicHandler
#[async_trait]
impl Handler for TuicHandler {
    type Config = TuicConfig;

    fn name(&self) -> &'static str {
        "tuic"
    }

    fn protocol(&self) -> ProtocolType {
        ProtocolType::Tuic
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }

    async fn handle(self: Arc<Self>, _stream: TcpStream) -> std::io::Result<()> {
        // TUIC uses QUIC, not raw TCP
        Ok(())
    }
}

/// TuicConfig 实现 HandlerConfig trait
impl HandlerConfig for TuicConfig {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tuic::TuicCommandType;

    #[test]
    fn test_tuic_command_type_conversion() {
        assert_eq!(TuicCommandType::from_u8(0x01), Some(TuicCommandType::Auth));
        assert_eq!(
            TuicCommandType::from_u8(0x02),
            Some(TuicCommandType::Connect)
        );
        assert_eq!(
            TuicCommandType::from_u8(0x03),
            Some(TuicCommandType::Disconnect)
        );
        assert_eq!(
            TuicCommandType::from_u8(0x04),
            Some(TuicCommandType::Heartbeat)
        );
        assert_eq!(TuicCommandType::from_u8(0xFF), None);
        assert_eq!(TuicCommandType::Auth.as_u8(), 0x01);
        assert_eq!(TuicCommandType::Connect.as_u8(), 0x02);
    }

    #[test]
    fn test_tuic_config_validation() {
        let valid = TuicConfig::new("token123".to_string(), "uuid456".to_string());
        assert!(valid.validate().is_ok());
        let empty_token = TuicConfig::new("".to_string(), "uuid456".to_string());
        assert!(empty_token.validate().is_err());
        let empty_uuid = TuicConfig::new("token123".to_string(), "".to_string());
        assert!(empty_uuid.validate().is_err());
    }

    #[test]
    fn test_tuic_error_display() {
        let err = TuicError::InvalidProtocol("bad proto".to_string());
        assert!(format!("{}", err).contains("bad proto"));
    }
}
