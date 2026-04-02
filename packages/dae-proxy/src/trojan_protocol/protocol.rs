//! Trojan protocol types and parsing
//!
//! This module contains all protocol-level types for Trojan,
//! including commands, address types, and parsing logic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Trojan protocol command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanCommand {
    /// TCP connection
    Proxy = 0x01,
    /// UDP (Trojan-Go style)
    UdpAssociate = 0x02,
}

/// Trojan address type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanAddressType {
    /// IPv4
    Ipv4 = 0x01,
    /// Domain
    Domain = 0x02,
    /// IPv6
    Ipv6 = 0x03,
}

/// Trojan target address
#[derive(Debug, Clone)]
pub enum TrojanTargetAddress {
    /// IPv4 address
    Ipv4(IpAddr),
    /// Domain name with port
    Domain(String, u16),
    /// IPv6 address
    Ipv6(IpAddr),
}

impl std::fmt::Display for TrojanTargetAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrojanTargetAddress::Ipv4(ip) => write!(f, "{ip}"),
            TrojanTargetAddress::Domain(domain, _) => write!(f, "{domain}"),
            TrojanTargetAddress::Ipv6(ip) => write!(f, "{ip}"),
        }
    }
}

impl TrojanTargetAddress {
    /// Parse target address from Trojan header bytes
    pub fn parse_from_bytes(payload: &[u8]) -> Option<(Self, u16)> {
        if payload.is_empty() {
            return None;
        }

        let atyp = payload[0];
        match atyp {
            0x01 => {
                // IPv4: 1 byte type + 4 bytes IP + 2 bytes port
                if payload.len() < 7 {
                    return None;
                }
                let ip = IpAddr::V4(Ipv4Addr::new(payload[1], payload[2], payload[3], payload[4]));
                let port = u16::from_be_bytes([payload[5], payload[6]]);
                Some((TrojanTargetAddress::Ipv4(ip), port))
            }
            0x02 => {
                // Domain: 1 byte type + 1 byte length + domain + 2 bytes port
                if payload.len() < 4 {
                    return None;
                }
                let domain_len = payload[1] as usize;
                if payload.len() < 4 + domain_len {
                    return None;
                }
                let domain = String::from_utf8(payload[2..2+domain_len].to_vec()).ok()?;
                let port = u16::from_be_bytes([payload[2+domain_len], payload[3+domain_len]]);
                Some((TrojanTargetAddress::Domain(domain, port), port))
            }
            0x03 => {
                // IPv6: 1 byte type + 16 bytes IP + 2 bytes port
                if payload.len() < 18 {
                    return None;
                }
                let ip = IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([payload[1], payload[2]]),
                    u16::from_be_bytes([payload[3], payload[4]]),
                    u16::from_be_bytes([payload[5], payload[6]]),
                    u16::from_be_bytes([payload[7], payload[8]]),
                    u16::from_be_bytes([payload[9], payload[10]]),
                    u16::from_be_bytes([payload[11], payload[12]]),
                    u16::from_be_bytes([payload[13], payload[14]]),
                    u16::from_be_bytes([payload[15], payload[16]]),
                ));
                let port = u16::from_be_bytes([payload[17], payload[18]]);
                Some((TrojanTargetAddress::Ipv6(ip), port))
            }
            _ => None,
        }
    }

    /// Convert address to bytes for Trojan protocol
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TrojanTargetAddress::Ipv4(ip) => {
                let mut bytes = vec![0x01]; // ATYP IPv4
                if let IpAddr::V4(ipv4) = ip {
                    bytes.extend_from_slice(&ipv4.octets());
                }
                bytes
            }
            TrojanTargetAddress::Ipv6(ip) => {
                let mut bytes = vec![0x03]; // ATYP IPv6
                if let IpAddr::V6(ipv6) = ip {
                    for &segment in &ipv6.segments() {
                        bytes.extend_from_slice(&segment.to_be_bytes());
                    }
                }
                bytes
            }
            TrojanTargetAddress::Domain(domain, _) => {
                let mut bytes = vec![0x02, domain.len() as u8];
                bytes.extend_from_slice(domain.as_bytes());
                bytes
            }
        }
    }
}

/// CRLF constant for Trojan protocol
pub const TROJAN_CRLF: &[u8] = b"\r\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_values() {
        assert_eq!(TrojanCommand::Proxy as u8, 0x01);
        assert_eq!(TrojanCommand::UdpAssociate as u8, 0x02);
    }

    #[test]
    fn test_address_type_values() {
        assert_eq!(TrojanAddressType::Ipv4 as u8, 0x01);
        assert_eq!(TrojanAddressType::Domain as u8, 0x02);
        assert_eq!(TrojanAddressType::Ipv6 as u8, 0x03);
    }

    #[test]
    fn test_target_address_parse_ipv4() {
        let payload = [
            0x01, 192, 168, 1, 1, 0x1F, 0x90  // 192.168.1.1:8080
        ];
        let result = TrojanTargetAddress::parse_from_bytes(&payload);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        match addr {
            TrojanTargetAddress::Ipv4(ip) => {
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            }
            _ => panic!("Expected IPv4"),
        }
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_target_address_parse_domain() {
        // Domain format: ATYP(1) + LEN(1) + DOMAIN(LEN) + PORT(2)
        let payload = [
            0x02,       // ATYP_DOMAIN
            0x0b,       // domain length = 11
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',  // "example.com"
            0x00, 0x50  // port = 80
        ];
        let result = TrojanTargetAddress::parse_from_bytes(&payload);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        match addr {
            TrojanTargetAddress::Domain(domain, _) => {
                assert_eq!(domain, "example.com");
            }
            _ => panic!("Expected Domain"),
        }
        assert_eq!(port, 80);
    }

    #[test]
    fn test_target_address_to_bytes_ipv4() {
        let addr = TrojanTargetAddress::Ipv4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let bytes = addr.to_bytes();
        assert_eq!(bytes, vec![0x01, 192, 168, 1, 1]);
    }
}
