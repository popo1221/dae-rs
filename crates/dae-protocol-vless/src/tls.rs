//! TLS ClientHello 构建模块
//!
//! 本模块实现 VLESS Reality Vision 的 TLS ClientHello 构建功能，
//! 包括各种 TLS 扩展的构建。

use crate::errors::VlessError;

/// TLS 记录层类型：Handshake
pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;

/// TLS 协议版本
pub const TLS_VERSION: u8 = 0x03;

/// TLS 1.3 版本号
pub const TLS_VERSION_1_3: u8 = 0x03;

/// TLS 握手类型：ClientHello
pub const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// TLS 扩展类型：SNI (Server Name Indication)
pub const TLS_EXT_SNI: u16 = 0x0000;

/// TLS 扩展类型：ALPN (Application-Layer Protocol Negotiation)
pub const TLS_EXT_ALPN: u16 = 0x0010;

/// TLS 扩展类型：supported_versions
pub const TLS_EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// TLS 扩展类型：psk_modes
pub const TLS_EXT_PSK_MODES: u16 = 0x002d;

/// TLS 扩展类型：key_share
pub const TLS_EXT_KEY_SHARE: u16 = 0x0033;

/// TLS 密钥交换算法：X25519
pub const TLS_KEY_SHARE_X25519: u16 = 0x001d;

/// TLS 1.3 支持的密码套件
pub const TLS_CIPHER_SUITES: &[u16] = &[0x1301, 0x1302, 0x1303];

/// ALPN 协议列表
pub const TLS_ALPN_LIST: &[&str] = &["h2", "http/1.1"];

/// 构建 TLS ClientHello（带 Reality chrome 扩展）
///
/// # 参数
/// - `client_public`: 客户端临时公钥（32 字节）
/// - `request`: Reality 请求数据（48 字节）
/// - `destination`: SNI 伪装目标
///
/// # 返回
/// 完整的 TLS ClientHello 字节
///
/// # 扩展列表
/// - SNI (server_name)
/// - ALPN
/// - supported_versions
/// - psk_modes
/// - key_share (Reality 密钥共享)
pub fn build_reality_client_hello(
    client_public: &[u8; 32],
    _request: &[u8; 48],
    destination: &str,
) -> Result<Vec<u8>, VlessError> {
    let mut client_hello = Vec::new();

    // TLS Record Layer: Handshake
    client_hello.push(TLS_RECORD_HANDSHAKE);
    client_hello.push(TLS_VERSION);
    client_hello.push(TLS_VERSION_1_3); // TLS 1.3

    let payload_start = client_hello.len();
    client_hello.push(0x00);
    client_hello.push(0x00);
    client_hello.push(0x00);

    // Handshake type: ClientHello
    client_hello.push(TLS_HANDSHAKE_CLIENT_HELLO);

    let handshake_len_pos = client_hello.len();
    client_hello.push(0x00);
    client_hello.push(0x00);
    client_hello.push(0x00);

    // ClientVersion TLS 1.3
    client_hello.push(TLS_VERSION);
    client_hello.push(TLS_VERSION_1_3);

    // Random (32 bytes)
    let random: [u8; 32] = rand::random();
    client_hello.extend_from_slice(&random);

    // Session ID empty
    client_hello.push(0x00);

    // Cipher suites
    client_hello.push((TLS_CIPHER_SUITES.len() * 2) as u8);
    for &cs in TLS_CIPHER_SUITES {
        client_hello.push((cs >> 8) as u8);
        client_hello.push((cs & 0xff) as u8);
    }

    // Compression methods
    client_hello.push(0x01);
    client_hello.push(0x00);

    // Extensions
    let extensions_start = client_hello.len();
    client_hello.push(0x00);
    client_hello.push(0x00);

    add_sni_extension(&mut client_hello, destination)?;
    add_alpn_extension(&mut client_hello)?;
    add_supported_versions_extension(&mut client_hello)?;
    add_psk_modes_extension(&mut client_hello)?;
    add_reality_key_share(&mut client_hello, client_public)?;

    // 填充扩展长度
    let ext_len = client_hello.len() - extensions_start - 2;
    client_hello[extensions_start] = (ext_len >> 8) as u8;
    client_hello[extensions_start + 1] = (ext_len & 0xff) as u8;

    // 填充握手长度
    let handshake_len = client_hello.len() - handshake_len_pos - 3;
    client_hello[handshake_len_pos] = (handshake_len >> 16) as u8;
    client_hello[handshake_len_pos + 1] = (handshake_len >> 8) as u8;
    client_hello[handshake_len_pos + 2] = (handshake_len & 0xff) as u8;

    // 填充记录层长度
    let record_len = client_hello.len() - payload_start - 3 + 4;
    client_hello[payload_start] = (record_len >> 8) as u8;
    client_hello[payload_start + 1] = (record_len & 0xff) as u8;
    client_hello[payload_start + 2] = (record_len & 0xff) as u8;

    Ok(client_hello)
}

/// 添加 SNI 扩展
fn add_sni_extension(buffer: &mut Vec<u8>, destination: &str) -> Result<(), VlessError> {
    // Extension type: SNI
    buffer.push((TLS_EXT_SNI >> 8) as u8);
    buffer.push((TLS_EXT_SNI & 0xff) as u8);

    let len_pos = buffer.len();
    buffer.push(0x00);
    buffer.push(0x00);

    // SNI list
    buffer.push(0x00);
    buffer.push(0x00);

    // Server name
    let name_bytes = destination.as_bytes();
    buffer.push((name_bytes.len() >> 8) as u8);
    buffer.push((name_bytes.len() & 0xff) as u8);
    buffer.extend_from_slice(name_bytes);

    // Extension data length
    let ext_data_len = buffer.len() - len_pos - 2;
    buffer[len_pos] = (ext_data_len >> 8) as u8;
    buffer[len_pos + 1] = (ext_data_len & 0xff) as u8;

    Ok(())
}

/// 添加 ALPN 扩展
fn add_alpn_extension(buffer: &mut Vec<u8>) -> Result<(), VlessError> {
    // Extension type: ALPN
    buffer.push((TLS_EXT_ALPN >> 8) as u8);
    buffer.push((TLS_EXT_ALPN & 0xff) as u8);

    let len_pos = buffer.len();
    buffer.push(0x00);
    buffer.push(0x00);

    // ALPN list
    let list_start = buffer.len();
    buffer.push(0x00);
    buffer.push(0x00);

    for alpn in TLS_ALPN_LIST {
        buffer.push(alpn.len() as u8);
        buffer.extend_from_slice(alpn.as_bytes());
    }

    let list_len = buffer.len() - list_start - 2;
    buffer[list_start] = (list_len >> 8) as u8;
    buffer[list_start + 1] = (list_len & 0xff) as u8;

    let ext_data_len = buffer.len() - len_pos - 2;
    buffer[len_pos] = (ext_data_len >> 8) as u8;
    buffer[len_pos + 1] = (ext_data_len & 0xff) as u8;

    Ok(())
}

/// 添加 supported_versions 扩展（TLS 1.3）
fn add_supported_versions_extension(buffer: &mut Vec<u8>) -> Result<(), VlessError> {
    buffer.push((TLS_EXT_SUPPORTED_VERSIONS >> 8) as u8);
    buffer.push((TLS_EXT_SUPPORTED_VERSIONS & 0xff) as u8);
    buffer.push(0x02);
    buffer.push(0x03);
    buffer.push(TLS_VERSION_1_3);
    Ok(())
}

/// 添加 psk_modes 扩展
fn add_psk_modes_extension(buffer: &mut Vec<u8>) -> Result<(), VlessError> {
    buffer.push((TLS_EXT_PSK_MODES >> 8) as u8);
    buffer.push((TLS_EXT_PSK_MODES & 0xff) as u8);
    buffer.push(0x02);
    buffer.push(0x01);
    buffer.push(0x01);
    Ok(())
}

/// 添加 Reality key_share 扩展
fn add_reality_key_share(
    buffer: &mut Vec<u8>,
    client_public: &[u8; 32],
) -> Result<(), VlessError> {
    // Extension type: key_share
    buffer.push((TLS_EXT_KEY_SHARE >> 8) as u8);
    buffer.push((TLS_EXT_KEY_SHARE & 0xff) as u8);

    let len_pos = buffer.len();
    buffer.push(0x00);
    buffer.push(0x00);

    let entry_len_pos = buffer.len();
    buffer.push(0x00);
    buffer.push(0x00);

    // Key exchange entry: group(2) + length(1) + key(32)
    buffer.push((TLS_KEY_SHARE_X25519 >> 8) as u8);
    buffer.push((TLS_KEY_SHARE_X25519 & 0xff) as u8);
    buffer.push(0x20);
    buffer.extend_from_slice(client_public);

    let entry_len = buffer.len() - entry_len_pos - 2;
    buffer[entry_len_pos] = (entry_len >> 8) as u8;
    buffer[entry_len_pos + 1] = (entry_len & 0xff) as u8;

    let ext_data_len = buffer.len() - len_pos - 2;
    buffer[len_pos] = (ext_data_len >> 8) as u8;
    buffer[len_pos + 1] = (ext_data_len & 0xff) as u8;

    Ok(())
}
