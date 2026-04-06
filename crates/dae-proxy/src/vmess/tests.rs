//! VMess module tests
//!
//! Tests for VMess protocol implementation including:
//! - Security type parsing and display
//! - Target address parsing and serialization
//! - AEAD-2022 cryptographic operations
//! - Handler and configuration tests

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;

use crate::vmess::protocol::{VmessSecurity, VmessServerConfig};
use crate::vmess::{VmessClientConfig, VmessHandler, VmessTargetAddress, VmessAddressType};

#[test]
fn test_security_from_str() {
    assert_eq!(
        VmessSecurity::from_str("aes-128-gcm-aead"),
        Some(VmessSecurity::Aes128GcmAead)
    );
    assert_eq!(
        VmessSecurity::from_str("chacha20-poly1305-aead"),
        Some(VmessSecurity::ChaCha20Poly1305Aead)
    );
    assert_eq!(
        VmessSecurity::from_str("aes-128-cfb"),
        Some(VmessSecurity::Aes128Cfb)
    );
    assert_eq!(VmessSecurity::from_str("auto"), Some(VmessSecurity::None));
    assert_eq!(VmessSecurity::from_str("invalid"), None);
}

#[test]
fn test_security_display() {
    assert_eq!(VmessSecurity::Aes128GcmAead.to_string(), "aes-128-gcm-aead");
    assert_eq!(
        VmessSecurity::ChaCha20Poly1305Aead.to_string(),
        "chacha20-poly1305-aead"
    );
    assert_eq!(VmessSecurity::Aes128Cfb.to_string(), "aes-128-cfb");
}

#[test]
fn test_default_config() {
    let config = VmessClientConfig::default();
    assert_eq!(config.listen_addr, SocketAddr::from(([127, 0, 0, 1], 1080)));
    assert_eq!(config.server.port, 10086);
    assert_eq!(config.server.security, VmessSecurity::Aes128GcmAead);
    assert!(config.server.enable_aead);
}

#[test]
fn test_target_address_parse_ipv4() {
    let payload = [
        0x01, 192, 168, 1, 1, 0x1F, 0x90, // 192.168.1.1:8080
    ];
    let result = VmessTargetAddress::parse_from_bytes(&payload);
    assert!(result.is_some());
    let (addr, port) = result.unwrap();
    match addr {
        VmessTargetAddress::Ipv4(ip) => {
            assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        }
        _ => unreachable!(),
    }
    assert_eq!(port, 8080);
}

#[test]
fn test_target_address_parse_domain() {
    // Domain format: ATYP(1) + LEN(1) + DOMAIN(LEN) + PORT(2)
    let payload = [
        0x02, // ATYP_DOMAIN
        0x0b, // domain length = 11
        b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', // "example.com"
        0x00, 0x50, // port = 80
    ];
    let result = VmessTargetAddress::parse_from_bytes(&payload);
    assert!(result.is_some());
    let (addr, port) = result.unwrap();
    match addr {
        VmessTargetAddress::Domain(domain, _) => {
            assert_eq!(domain, "example.com");
        }
        _ => unreachable!(),
    }
    assert_eq!(port, 80);
}

#[test]
fn test_target_address_to_bytes_ipv4() {
    let addr = VmessTargetAddress::Ipv4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    let bytes = addr.to_bytes();
    assert_eq!(bytes, vec![0x01, 192, 168, 1, 1]);
}

#[test]
fn test_timestamp() {
    let ts = VmessHandler::timestamp();
    assert!(ts > 0);
    // Should be roughly current time (after 2020)
    assert!(ts > 1577836800);
}

#[test]
fn test_target_address_to_bytes_domain() {
    let addr = VmessTargetAddress::Domain("example.com".to_string(), 443);
    let bytes = addr.to_bytes();
    assert_eq!(bytes[0], 0x02); // ATYP_DOMAIN
    assert_eq!(bytes[1], 11); // length
}

#[test]
fn test_target_address_parse_ipv6() {
    let payload = [
        0x03, // ATYP_IPV6 (VMess uses 0x03 for IPv6)
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x50, // [2001:db8::1]:80
    ];
    let result = VmessTargetAddress::parse_from_bytes(&payload);
    assert!(result.is_some());
    let (addr, port) = result.unwrap();
    match addr {
        VmessTargetAddress::Ipv6(ip) => {
            if let IpAddr::V6(ipv6) = ip {
                assert_eq!(ipv6.segments()[0], 0x2001);
            }
        }
        _ => unreachable!(),
    }
    assert_eq!(port, 80);
}

#[test]
fn test_target_address_parse_invalid_type() {
    let payload = [0x05, 0x00]; // Invalid type
    let result = VmessTargetAddress::parse_from_bytes(&payload);
    assert!(result.is_none());
}

#[test]
fn test_target_address_parse_truncated() {
    // IPv4 requires 7 bytes, only 3 provided
    let payload = [0x01, 192, 168];
    let result = VmessTargetAddress::parse_from_bytes(&payload);
    assert!(result.is_none());
}

#[test]
fn test_target_address_parse_domain_truncated() {
    // Domain with length 11 but only 2 bytes provided
    let payload = [0x02, 0x0b, 0x65]; // "e" but no full domain
    let result = VmessTargetAddress::parse_from_bytes(&payload);
    assert!(result.is_none());
}

#[test]
fn test_vmess_security_all_variants() {
    // Check that from_str returns Some for valid security types
    assert!(VmessSecurity::from_str("aes-128-cfb").is_some());
    assert!(VmessSecurity::from_str("chacha20-poly1305").is_some());
    assert!(VmessSecurity::from_str("auto").is_some());
    assert!(VmessSecurity::from_str("invalid-scheme").is_none());
}

#[test]
fn test_vmess_security_to_string() {
    assert_eq!(VmessSecurity::Aes128GcmAead.to_string(), "aes-128-gcm-aead");
    assert_eq!(
        VmessSecurity::ChaCha20Poly1305Aead.to_string(),
        "chacha20-poly1305-aead"
    );
    // None maps to "none" not "auto"
    assert_eq!(VmessSecurity::None.to_string(), "none");
}

#[test]
fn test_vmess_address_type() {
    assert_eq!(VmessAddressType::Ipv4 as u8, 0x01);
    assert_eq!(VmessAddressType::Domain as u8, 0x02);
    assert_eq!(VmessAddressType::Ipv6 as u8, 0x03);
}

#[test]
fn test_target_address_debug() {
    let addr = VmessTargetAddress::Ipv4(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    let debug_str = format!("{:?}", addr);
    assert!(debug_str.contains("Ipv4"));
}

#[test]
fn test_target_address_clone() {
    let addr = VmessTargetAddress::Domain("test.com".to_string(), 443);
    let cloned = addr.clone();
    match (&addr, &cloned) {
        (VmessTargetAddress::Domain(d1, p1), VmessTargetAddress::Domain(d2, p2)) => {
            assert_eq!(d1, d2);
            assert_eq!(p1, p2);
        }
        _ => unreachable!(),
    }
}

#[test]
fn test_target_address_to_bytes_ipv6() {
    let addr = VmessTargetAddress::Ipv6(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
    let bytes = addr.to_bytes();
    assert_eq!(bytes[0], 0x03); // ATYP_IPV6
}

#[test]
fn test_vmess_client_config_default() {
    let config = VmessClientConfig::default();
    assert!(config.server.enable_aead);
    assert_eq!(config.server.security, VmessSecurity::Aes128GcmAead);
}

#[test]
fn test_vmess_client_config_clone() {
    let config = VmessClientConfig::default();
    let cloned = config.clone();
    assert_eq!(cloned.server.user_id, config.server.user_id);
}

#[test]
fn test_vmess_handler_timestamp_range() {
    let ts1 = VmessHandler::timestamp();
    let ts2 = VmessHandler::timestamp();
    // Timestamps should be increasing or same
    assert!(ts2 >= ts1);
}

#[test]
fn test_vmess_address_type_variants() {
    let addr_type = VmessAddressType::Ipv4;
    assert_eq!(addr_type as u8, 0x01);
}

#[test]
fn test_vmess_security_from_str_case_insensitive() {
    assert!(VmessSecurity::from_str("AES-128-GCM-AEAD").is_some());
    assert!(VmessSecurity::from_str("ChaCha20-Poly1305-AEAD").is_some());
}

// ============================================================
// VMess AEAD-2022 Cryptographic Tests
// ============================================================

/// Test that derive_user_key produces a 32-byte key via HMAC-SHA256
#[test]
fn test_derive_user_key_length_and_determinism() {
    let user_id = "test-user-uuid";

    // Test that HMAC-SHA256 always produces 32 bytes
    let key1 = VmessHandler::hmac_sha256(user_id.as_bytes(), b"VMess AEAD");
    let key2 = VmessHandler::hmac_sha256(user_id.as_bytes(), b"VMess AEAD");
    assert_eq!(key1.len(), 32, "HMAC-SHA256 should produce 32 bytes");
    assert_eq!(key1, key2, "Same input should produce same HMAC output");

    // Different input should produce different output
    let key3 = VmessHandler::hmac_sha256(b"different-user".as_slice(), b"VMess AEAD");
    assert_ne!(
        key1, key3,
        "Different input should produce different HMAC output"
    );
}

/// Test HMAC-SHA256 derivation for derive_user_key
#[test]
fn test_derive_user_key_different_user_ids() {
    let user_ids = [
        "user-1",
        "another-user",
        "550e8400-e29b-41d4-a716-446655440000",
    ];
    let mut keys: Vec<[u8; 32]> = Vec::new();

    for uid in &user_ids {
        let key = VmessHandler::hmac_sha256(uid.as_bytes(), b"VMess AEAD");
        assert_eq!(key.len(), 32);

        // Ensure no duplicate keys
        for existing in &keys {
            assert_ne!(
                &key, existing,
                "Different user IDs should produce different keys"
            );
        }
        keys.push(key);
    }
}

/// Test that derive_request_key_iv produces correct sized outputs
#[test]
fn test_derive_request_key_iv_output_sizes() {
    let user_key = [0x42u8; 32];
    let nonce = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10,
    ];

    let (request_key, request_iv) = VmessHandler::derive_request_key_iv(&user_key, &nonce);

    assert_eq!(request_key.len(), 32, "request_key should be 32 bytes");
    assert_eq!(request_iv.len(), 12, "request_iv should be 12 bytes");
}

/// Test derive_request_key_iv determinism
#[test]
fn test_derive_request_key_iv_determinism() {
    let user_key = [0xAB_u8; 32];
    let nonce: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x00,
    ];

    let (key1, iv1) = VmessHandler::derive_request_key_iv(&user_key, &nonce);
    let (key2, iv2) = VmessHandler::derive_request_key_iv(&user_key, &nonce);

    assert_eq!(key1, key2, "Same inputs should produce same request_key");
    assert_eq!(iv1, iv2, "Same inputs should produce same request_iv");
}

/// Test that different nonces produce different key/IV pairs
#[test]
fn test_derive_request_key_iv_nonce_sensitivity() {
    let user_key = [0x42u8; 32];
    let nonce1: [u8; 16] = [0x00; 16];
    let nonce2: [u8; 16] = [0xFF; 16];

    let (key1, iv1) = VmessHandler::derive_request_key_iv(&user_key, &nonce1);
    let (key2, iv2) = VmessHandler::derive_request_key_iv(&user_key, &nonce2);

    assert_ne!(key1, key2, "Different nonces should produce different keys");
    assert_ne!(iv1, iv2, "Different nonces should produce different IVs");
}

/// Test that different user_keys produce different key/IV pairs
#[test]
fn test_derive_request_key_iv_key_sensitivity() {
    let user_key1 = [0x11u8; 32];
    let user_key2 = [0x22u8; 32];
    let nonce: [u8; 16] = [0xAA; 16];

    let (k1, iv1) = VmessHandler::derive_request_key_iv(&user_key1, &nonce);
    let (k2, iv2) = VmessHandler::derive_request_key_iv(&user_key2, &nonce);

    assert_ne!(
        k1, k2,
        "Different user keys should produce different request keys"
    );
    assert_ne!(iv1, iv2, "Different user keys should produce different IVs");
}

/// Test full AEAD-2022 roundtrip: encrypt header then decrypt it
#[test]
fn test_decrypt_header_roundtrip() {
    // Setup
    let user_id = "test-uuid-1234";
    let user_key = VmessHandler::hmac_sha256(user_id.as_bytes(), b"VMess AEAD");

    // Build a valid VMess AEAD header payload
    // Header format: [version(1)][option(1)][port(2)][atyp(1)][addr(var)][timestamp(4)][random(4)][checksum(4)]
    // We'll build a simple header targeting an IPv4 address
    let mut header = Vec::new();
    header.push(0x01); // version
    header.push(0x00); // option
    header.extend_from_slice(&8080u16.to_be_bytes()); // port 8080
    header.push(0x01); // atyp = IPv4
    header.extend_from_slice(&[192, 168, 1, 1]); // 192.168.1.1
                                                 // timestamp + random + checksum (12 bytes extra)
    header.extend_from_slice(&[0x00; 12]);

    // Nonce for this session (16 bytes)
    let nonce: [u8; 16] = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88,
    ];

    // Derive request key and IV from user_key + nonce
    let (request_key, _request_iv) = VmessHandler::derive_request_key_iv(&user_key, &nonce);

    // Encrypt the header using AES-256-GCM
    // Use first 12 bytes of the 16-byte nonce as GCM nonce
    let cipher = Aes256Gcm::new_from_slice(&request_key).unwrap();
    let gcm_nonce_arr: [u8; 12] = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44,
    ];
    let gcm_nonce = Nonce::from_slice(&gcm_nonce_arr);
    let ciphertext = cipher.encrypt(gcm_nonce, header.as_slice()).unwrap();

    // Build encrypted payload: [nonce(16)][ciphertext_with_tag]
    // The decrypt_header function expects first 16 bytes as nonce for key derivation
    let mut encrypted = Vec::new();
    encrypted.extend_from_slice(&nonce);
    encrypted.extend_from_slice(&ciphertext);

    // Decrypt using our function
    let decrypted = VmessHandler::decrypt_header(&user_key, &encrypted).unwrap();

    // Verify decrypted header matches original
    assert_eq!(&decrypted[..], &header[..]);
}

/// Test decrypt_header rejects too-short input
#[test]
fn test_decrypt_header_too_short() {
    let user_key = [0x42u8; 32];

    // Less than 32 bytes (16-byte nonce + minimum tag)
    let encrypted = vec![0u8; 16];
    let result = VmessHandler::decrypt_header(&user_key, &encrypted);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "encrypted header too short (< 32 bytes)"
    );
}

/// Test decrypt_header rejects wrong auth tag (tampered data)
#[test]
fn test_decrypt_header_wrong_tag() {
    let user_key = VmessHandler::hmac_sha256(b"test-user".as_slice(), b"VMess AEAD");
    let nonce: [u8; 16] = [0xAA; 16];
    let (request_key, _) = VmessHandler::derive_request_key_iv(&user_key, &nonce);

    // Encrypt some data
    let header =
        b"\x01\x00\x00\x50\x01\xc0\xa8\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let cipher = Aes256Gcm::new_from_slice(&request_key).unwrap();
    let gcm_nonce: [u8; 12] = [0xAA; 12];
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&gcm_nonce), header.as_slice())
        .unwrap();

    // Tamper with the last byte (auth tag)
    let mut encrypted = Vec::new();
    encrypted.extend_from_slice(&nonce);
    encrypted.extend_from_slice(&ciphertext);
    if let Some(last) = encrypted.last_mut() {
        *last ^= 0xFF; // Flip all bits in last byte
    }

    let result = VmessHandler::decrypt_header(&user_key, &encrypted);
    let err_msg = *result.as_ref().unwrap_err();
    assert!(
        err_msg.contains("AES-GCM decryption failed") || err_msg.contains("AES-GCM"),
        "Unexpected error: {}",
        err_msg
    );
}

/// Test decrypt_header rejects data encrypted with wrong key
#[test]
fn test_decrypt_header_wrong_key() {
    let user_key1 = VmessHandler::hmac_sha256(b"user1".as_slice(), b"VMess AEAD");
    let user_key2 = VmessHandler::hmac_sha256(b"user2".as_slice(), b"VMess AEAD");

    let nonce: [u8; 16] = [0xBB; 16];

    // Encrypt with key derived from user1
    let (request_key, _) = VmessHandler::derive_request_key_iv(&user_key1, &nonce);
    let header =
        b"\x01\x00\x00\x50\x01\xc0\xa8\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let cipher = Aes256Gcm::new_from_slice(&request_key).unwrap();
    let gcm_nonce_arr: [u8; 12] = [0xBB; 12];
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&gcm_nonce_arr), header.as_slice())
        .unwrap();

    let mut encrypted = Vec::new();
    encrypted.extend_from_slice(&nonce);
    encrypted.extend_from_slice(&ciphertext);

    // Try to decrypt with user2's key (should fail auth tag check)
    let result = VmessHandler::decrypt_header(&user_key2, &encrypted);
    assert!(result.is_err());
}

/// Test VmessTargetAddress parsing and roundtrip for IPv4
#[test]
fn test_target_address_parse_to_bytes_ipv4_roundtrip() {
    let original = VmessTargetAddress::Ipv4(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let bytes = original.to_bytes();

    // Parse the bytes back
    // Need to include port in payload for parse_from_bytes
    let mut payload_with_port = bytes.clone();
    payload_with_port.extend_from_slice(&443u16.to_be_bytes()); // port 443

    let result = VmessTargetAddress::parse_from_bytes(&payload_with_port);
    assert!(result.is_some());
    let (parsed, port) = result.unwrap();

    match (&original, &parsed) {
        (VmessTargetAddress::Ipv4(ip1), VmessTargetAddress::Ipv4(ip2)) => {
            assert_eq!(ip1, ip2);
        }
        _ => unreachable!(),
    }
    assert_eq!(port, 443);
}

/// Test VmessTargetAddress parsing and roundtrip for domain
#[test]
fn test_target_address_parse_to_bytes_domain_roundtrip() {
    let original = VmessTargetAddress::Domain("test.example.org".to_string(), 8443);
    let mut bytes = original.to_bytes();
    bytes.extend_from_slice(&8443u16.to_be_bytes());

    let result = VmessTargetAddress::parse_from_bytes(&bytes);
    assert!(result.is_some());
    let (parsed, port) = result.unwrap();

    match (&original, &parsed) {
        (VmessTargetAddress::Domain(d1, p1), VmessTargetAddress::Domain(d2, p2)) => {
            assert_eq!(d1, d2);
            assert_eq!(p1, p2);
        }
        _ => unreachable!(),
    }
    assert_eq!(port, 8443);
}

/// Test VmessTargetAddress Display impl
#[test]
fn test_target_address_display() {
    let ipv4 = VmessTargetAddress::Ipv4(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(format!("{}", ipv4), "8.8.8.8");

    let domain = VmessTargetAddress::Domain("google.com".to_string(), 443);
    assert_eq!(format!("{}", domain), "google.com");

    let ipv6 = VmessTargetAddress::Ipv6(IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(format!("{}", ipv6), "::1");
}

/// Test VmessSecurity default is Aes128GcmAead
#[test]
fn test_vmess_security_default() {
    let security = VmessSecurity::default();
    assert_eq!(security, VmessSecurity::Aes128GcmAead);
}

/// Test VmessSecurity is_valid pattern (check all known valid values work)
#[test]
fn test_vmess_security_all_valid_types() {
    // All these security types should parse correctly and are considered "valid" AEAD types
    let valid_types = [
        ("aes-128-cfb", VmessSecurity::Aes128Cfb),
        ("aes-128-gcm", VmessSecurity::Aes128Gcm),
        ("chacha20-poly1305", VmessSecurity::ChaCha20Poly1305),
        ("none", VmessSecurity::None),
        ("aes-128-gcm-aead", VmessSecurity::Aes128GcmAead),
        (
            "chacha20-poly1305-aead",
            VmessSecurity::ChaCha20Poly1305Aead,
        ),
    ];

    for (name, expected) in valid_types {
        let parsed = VmessSecurity::from_str(name);
        assert_eq!(parsed, Some(expected), "Failed to parse: {}", name);
    }
}

/// Test VmessSecurity invalid strings return None
#[test]
fn test_vmess_security_invalid_strings() {
    let invalid = ["", "invalid", "aes-256-gcm", "tls", "reality", "xtls"];
    for s in invalid {
        assert_eq!(
            VmessSecurity::from_str(s),
            None,
            "Should be None for: {}",
            s
        );
    }
}

/// Test VmessServerConfig default values
#[test]
fn test_vmess_server_config_default() {
    let config = VmessServerConfig::default();
    assert_eq!(config.addr, "127.0.0.1");
    assert_eq!(config.port, 10086);
    assert!(config.user_id.is_empty());
    assert_eq!(config.security, VmessSecurity::Aes128GcmAead);
    assert!(config.enable_aead);
}

/// Test VmessHandler construction and listen_addr access
#[test]
fn test_vmess_handler_listen_addr() {
    let handler = VmessHandler::new_default();
    let addr = handler.listen_addr();
    assert_eq!(addr, SocketAddr::from(([127, 0, 0, 1], 1080)));
}

/// Test VmessHandler with custom config
#[test]
fn test_vmess_handler_custom_config() {
    let config = VmessClientConfig {
        listen_addr: SocketAddr::from(([0, 0, 0, 0], 2080)),
        server: VmessServerConfig {
            addr: "192.168.1.100".to_string(),
            port: 443,
            user_id: "custom-user-id".to_string(),
            security: VmessSecurity::ChaCha20Poly1305Aead,
            enable_aead: true,
        },
        tcp_timeout: Duration::from_secs(120),
        udp_timeout: Duration::from_secs(60),
    };

    let handler = VmessHandler::new(config);
    assert_eq!(
        handler.listen_addr(),
        SocketAddr::from(([0, 0, 0, 0], 2080))
    );
}
