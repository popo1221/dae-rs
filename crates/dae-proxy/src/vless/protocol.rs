//! VLESS protocol types
//!
//! Core protocol definitions for VLESS protocol.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// VLESS protocol version
pub const VLESS_VERSION: u8 = 0x01;

/// VLESS header size constants
pub const VLESS_HEADER_MIN_SIZE: usize = 38; // v1 + uuid(16) + ver(1) + cmd(1) + port(4) + atyp(1) + iv(16)
#[allow(dead_code)]
pub const VLESS_REQUEST_HEADER_SIZE: usize = 22; // port(4) + atyp(1) + addr + iv(16)

/// Maximum domain name length per VLESS protocol (255 bytes as u8)
/// This is the protocol limit for the domain length field.
const MAX_DOMAIN_LEN: usize = 255;

/// VLESS command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    /// TCP connection
    Tcp = 0x01,
    /// UDP (mux)
    Udp = 0x02,
    /// XTLS Vision (Reality)
    XtlsVision = 0x03,
}

impl VlessCommand {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(VlessCommand::Tcp),
            0x02 => Some(VlessCommand::Udp),
            0x03 => Some(VlessCommand::XtlsVision),
            _ => None,
        }
    }
}

/// VLESS address type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessAddressType {
    /// IPv4
    Ipv4 = 0x01,
    /// Domain
    Domain = 0x02,
    /// IPv6
    Ipv6 = 0x03,
}

impl VlessAddressType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(VlessAddressType::Ipv4),
            0x02 => Some(VlessAddressType::Domain),
            0x03 => Some(VlessAddressType::Ipv6),
            _ => None,
        }
    }
}

/// VLESS target address
#[derive(Debug, Clone)]
pub enum VlessTargetAddress {
    /// IPv4 address
    Ipv4(IpAddr),
    /// Domain name with port
    Domain(String, u16),
    /// IPv6 address
    Ipv6(IpAddr),
}

impl std::fmt::Display for VlessTargetAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VlessTargetAddress::Ipv4(ip) => write!(f, "{ip}"),
            VlessTargetAddress::Domain(domain, _) => write!(f, "{domain}"),
            VlessTargetAddress::Ipv6(ip) => write!(f, "{ip}"),
        }
    }
}

impl VlessTargetAddress {
    /// Parse target address from VLESS header bytes
    /// Returns (address, port, bytes_consumed)
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
                let ip = IpAddr::V4(Ipv4Addr::new(
                    payload[1], payload[2], payload[3], payload[4],
                ));
                let port = u16::from_be_bytes([payload[5], payload[6]]);
                Some((VlessTargetAddress::Ipv4(ip), port))
            }
            0x02 => {
                // Domain: 1 byte type + 1 byte length + domain + 2 bytes port
                if payload.len() < 4 {
                    return None;
                }
                let domain_len = payload[1] as usize;
                // Reject empty domains (domain_len == 0) for security
                if domain_len == 0 {
                    return None;
                }
                if payload.len() < 4 + domain_len {
                    return None;
                }
                let domain = String::from_utf8(payload[2..2 + domain_len].to_vec()).ok()?;
                let port = u16::from_be_bytes([payload[2 + domain_len], payload[3 + domain_len]]);
                Some((VlessTargetAddress::Domain(domain, port), port))
            }
            0x03 => {
                // IPv6: 1 byte type + 16 bytes IP + 2 bytes port
                if payload.len() < 19 {
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
                Some((VlessTargetAddress::Ipv6(ip), port))
            }
            _ => None,
        }
    }

    /// Convert address to bytes for VLESS protocol
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            VlessTargetAddress::Ipv4(ip) => {
                let mut bytes = vec![0x01]; // ATYP IPv4
                if let IpAddr::V4(ipv4) = ip {
                    bytes.extend_from_slice(&ipv4.octets());
                }
                bytes
            }
            VlessTargetAddress::Ipv6(ip) => {
                let mut bytes = vec![0x03]; // ATYP IPv6
                if let IpAddr::V6(ipv6) = ip {
                    for &segment in &ipv6.segments() {
                        bytes.extend_from_slice(&segment.to_be_bytes());
                    }
                }
                bytes
            }
            VlessTargetAddress::Domain(domain, _) => {
                // Validate domain length before encoding to prevent truncation
                // VLESS protocol uses u8 for domain length field (max 255)
                if domain.len() > MAX_DOMAIN_LEN {
                    // Domain too long - cannot encode safely
                    // Return a Vec that will cause parsing to fail downstream
                    // This prevents silent truncation which would corrupt data
                    return vec![0x02, 0x00]; // Invalid encoding - empty domain
                }
                let mut bytes = vec![0x02, domain.len() as u8];
                bytes.extend_from_slice(domain.as_bytes());
                bytes
            }
        }
    }
}
