//! VLESS TLS utilities
//!
//! TLS constants and helper functions for VLESS Reality Vision.

/// TLS record type: Handshake
pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
/// TLS version TLS 1.3
pub const TLS_VERSION: [u8; 2] = [0x03, 0x03];
/// TLS version TLS 1.2
pub const TLS_VERSION_1_2: [u8; 2] = [0x03, 0x03];

/// TLS cipher suites for TLS 1.3
pub const TLS_CIPHER_SUITES: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
];

/// TLS extension types
pub mod extension {
    /// Extension type: server_name (SNI)
    pub const SERVER_NAME: u16 = 0x0000;
    /// Extension type: application_layer_protocol_negotiation (ALPN)
    pub const ALPN: u16 = 0x0010;
    /// Extension type: supported_versions
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    /// Extension type: psk_key_exchange_modes
    pub const PSK_MODES: u16 = 0x002d;
    /// Extension type: key_share
    pub const KEY_SHARE: u16 = 0x0033;
    /// Named group: x25519
    pub const NAMED_GROUP_X25519: u16 = 0x001d;
}

/// ALPN protocols
pub const ALPN_LIST: &[&str] = &["h2", "http/1.1"];

/// PSK mode: psk_dhe_ke
pub const PSK_MODE_DHE_KE: u8 = 0x01;

/// UDP-related constants
pub const MAX_UDP_SIZE: usize = 65535;
/// Minimum UDP header size: v1(1) + uuid(16) + ver(1) + cmd(1) + port(4) + atyp(1) + iv(16)
pub const MIN_UDP_HEADER_SIZE: usize = 40;

/// Build a TLS ClientHello with Reality chrome extension
///
/// Returns the complete TLS record containing the ClientHello.
pub fn build_reality_client_hello(
    client_public: &[u8; 32],
    request: &[u8; 48],
    destination: &str,
) -> std::io::Result<Vec<u8>> {
    use std::io::Write;

    let mut client_hello = Vec::new();

    // TLS Record Layer: Handshake (0x16)
    client_hello.push(TLS_RECORD_HANDSHAKE);

    // TLS Version TLS 1.3 (0x0303)
    client_hello.extend_from_slice(&TLS_VERSION);

    // Handshake payload placeholder (3 bytes for length)
    let payload_start = client_hello.len();
    client_hello.extend_from_slice(&[0x00, 0x00, 0x00]);

    // Handshake type: ClientHello (0x01)
    client_hello.push(0x01);

    // Handshake length (placeholder, 3 bytes)
    let handshake_len_pos = client_hello.len();
    client_hello.extend_from_slice(&[0x00, 0x00, 0x00]);

    // ClientVersion TLS 1.3 (0x0303)
    client_hello.extend_from_slice(&TLS_VERSION);

    // Random (32 bytes)
    let random: [u8; 32] = rand::random();
    client_hello.extend_from_slice(&random);

    // Session ID (empty)
    client_hello.push(0x00);

    // Cipher suites
    client_hello.push((TLS_CIPHER_SUITES.len() * 2) as u8);
    for &cs in TLS_CIPHER_SUITES {
        client_hello.extend_from_slice(&cs.to_be_bytes());
    }

    // Compression methods (null only)
    client_hello.extend_from_slice(&[0x01, 0x00]);

    // Extensions
    build_extensions(&mut client_hello, client_public, destination)?;

    // Update record layer length
    let record_len = client_hello.len() - payload_start - 3 + 4; // +4 for record header
    client_hello[payload_start..payload_start + 3].copy_from_slice(&record_len.to_be_bytes()[1..4]);

    // Update handshake length
    let handshake_len = client_hello.len() - handshake_len_pos - 3;
    client_hello[handshake_len_pos..handshake_len_pos + 3].copy_from_slice(&handshake_len.to_be_bytes()[1..4]);

    Ok(client_hello)
}

fn build_extensions(
    buffer: &mut Vec<u8>,
    client_public: &[u8; 32],
    destination: &str,
) -> std::io::Result<()> {
    // Extensions length placeholder
    let extensions_start = buffer.len();
    buffer.extend_from_slice(&[0x00, 0x00]);

    // Add extensions
    add_sni_extension(buffer, destination)?;
    add_alpn_extension(buffer)?;
    add_supported_versions_extension(buffer)?;
    add_psk_modes_extension(buffer)?;
    add_reality_key_share(buffer, client_public)?;

    // Update extensions length
    let ext_len = (buffer.len() - extensions_start - 2) as u16;
    buffer[extensions_start..extensions_start + 2].copy_from_slice(&ext_len.to_be_bytes());

    Ok(())
}

fn add_sni_extension(buffer: &mut Vec<u8>, destination: &str) -> std::io::Result<()> {
    buffer.extend_from_slice(&extension::SERVER_NAME.to_be_bytes());

    // Extension data length (placeholder)
    let len_pos = buffer.len();
    buffer.extend_from_slice(&[0x00, 0x00]);

    // ServerNameList length
    buffer.push(0x00);

    // ServerName type: host_name (0x00)
    buffer.push(0x00);

    // ServerName
    let name_bytes = destination.as_bytes();
    buffer.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    buffer.extend_from_slice(name_bytes);

    // Update extension length
    let ext_data_len = (buffer.len() - len_pos - 2) as u16;
    buffer[len_pos..len_pos + 2].copy_from_slice(&ext_data_len.to_be_bytes());

    Ok(())
}

fn add_alpn_extension(buffer: &mut Vec<u8>) -> std::io::Result<()> {
    buffer.extend_from_slice(&extension::ALPN.to_be_bytes());

    // Extension data length (placeholder)
    let len_pos = buffer.len();
    buffer.extend_from_slice(&[0x00, 0x00]);

    // Protocol name list length (placeholder)
    let list_start = buffer.len();
    buffer.extend_from_slice(&[0x00, 0x00]);

    for alpn in ALPN_LIST {
        buffer.push(*alpn as u8);
        buffer.extend_from_slice(alpn.as_bytes());
    }

    // Update list length
    let list_len = (buffer.len() - list_start - 2) as u16;
    buffer[list_start..list_start + 2].copy_from_slice(&list_len.to_be_bytes());

    // Update extension length
    let ext_data_len = (buffer.len() - len_pos - 2) as u16;
    buffer[len_pos..len_pos + 2].copy_from_slice(&ext_data_len.to_be_bytes());

    Ok(())
}

fn add_supported_versions_extension(buffer: &mut Vec<u8>) -> std::io::Result<()> {
    buffer.extend_from_slice(&extension::SUPPORTED_VERSIONS.to_be_bytes());

    // Extension data length
    buffer.push(0x02);

    // Client: supported version TLS 1.3
    buffer.extend_from_slice(&TLS_VERSION);

    Ok(())
}

fn add_psk_modes_extension(buffer: &mut Vec<u8>) -> std::io::Result<()> {
    buffer.extend_from_slice(&extension::PSK_MODES.to_be_bytes());

    // Extension data length
    buffer.push(0x02);

    // PSK modes: psk_dhe_ke (0x01)
    buffer.extend_from_slice(&[PSK_MODE_DHE_KE, PSK_MODE_DHE_KE]);

    Ok(())
}

fn add_reality_key_share(
    buffer: &mut Vec<u8>,
    client_public: &[u8; 32],
) -> std::io::Result<()> {
    buffer.extend_from_slice(&extension::KEY_SHARE.to_be_bytes());

    // Extension data length (placeholder)
    let len_pos = buffer.len();
    buffer.extend_from_slice(&[0x00, 0x00]);

    // Key share entry length (placeholder)
    let entry_len_pos = buffer.len();
    buffer.extend_from_slice(&[0x00, 0x00]);

    // Key share entry:
    // - 2 bytes: named group (x25519 = 0x001d)
    buffer.extend_from_slice(&extension::NAMED_GROUP_X25519.to_be_bytes());

    // - 1 byte: key exchange length (32 bytes)
    buffer.push(0x20);

    // - 32 bytes: key exchange value (client public)
    buffer.extend_from_slice(client_public);

    // Update key share entry length
    let entry_len = (buffer.len() - entry_len_pos - 2) as u16;
    buffer[entry_len_pos..entry_len_pos + 2].copy_from_slice(&entry_len.to_be_bytes());

    // Update extension length
    let ext_data_len = (buffer.len() - len_pos - 2) as u16;
    buffer[len_pos..len_pos + 2].copy_from_slice(&ext_data_len.to_be_bytes());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_constants() {
        assert_eq!(TLS_RECORD_HANDSHAKE, 0x16);
        assert_eq!(TLS_VERSION, [0x03, 0x03]);
        assert_eq!(MAX_UDP_SIZE, 65535);
        assert_eq!(MIN_UDP_HEADER_SIZE, 40);
    }

    #[test]
    fn test_client_hello_build() {
        let client_public = [0u8; 32];
        let request = [0u8; 48];
        let result = build_reality_client_hello(&client_public, &request, "example.com");
        assert!(result.is_ok());
        let hello = result.unwrap();
        // Should have TLS record header + ClientHello
        assert!(hello.len() > 50);
    }
}
