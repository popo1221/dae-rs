//! dae-ebpf-direct - Real Direct eBPF Mode for dae-rs
//!
//! This crate implements a true direct eBPF mode that bypasses iptables.
//! It uses sockmap-based transparent proxy to redirect traffic directly
//! without requiring any iptables rules.

#![deny(warnings)]
// Allow strict clippy lints for eBPF code patterns
#![allow(clippy::field_reassign_with_default)]

pub mod maps;
pub mod programs;
pub mod sockmap;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EbpfError {
    #[error("Map error: {0}")]
    Map(String),

    #[error("Program error: {0}")]
    Program(String),

    #[error("Sockmap error: {0}")]
    Sockmap(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
}

/// Connection 5-tuple key for connection identification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct ConnectionKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl ConnectionKey {
    /// Create a new connection key
    pub fn new(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    /// Create from raw bytes (network order)
    pub fn from_bytes(bytes: &[u8; 13]) -> Self {
        let src_ip = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let dst_ip = u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let src_port = u16::from_be_bytes([bytes[8], bytes[9]]);
        let dst_port = u16::from_be_bytes([bytes[10], bytes[11]]);
        let protocol = bytes[12];

        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    /// Convert to bytes (network order)
    pub fn to_bytes(&self) -> [u8; 13] {
        let src_ip = self.src_ip.to_ne_bytes();
        let dst_ip = self.dst_ip.to_ne_bytes();
        let src_port = self.src_port.to_be_bytes();
        let dst_port = self.dst_port.to_be_bytes();

        [
            src_ip[0],
            src_ip[1],
            src_ip[2],
            src_ip[3],
            dst_ip[0],
            dst_ip[1],
            dst_ip[2],
            dst_ip[3],
            src_port[0],
            src_port[1],
            dst_port[0],
            dst_port[1],
            self.protocol,
        ]
    }
}

/// Connection information stored in eBPF map
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ConnectionInfo {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub pid: u32,
}

impl ConnectionInfo {
    /// Create a new connection info
    pub fn new(
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        pid: u32,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            pid,
        }
    }
}

/// Direct mode configuration
#[derive(Debug, Clone)]
pub struct DirectConfig {
    /// Enable direct mode
    pub enabled: bool,
    /// Local proxy port for redirect
    pub proxy_port: u16,
    /// Cgroup path to attach to
    pub cgroup_path: String,
}

impl Default for DirectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy_port: 12345,
            cgroup_path: "/sys/fs/cgroup".to_string(),
        }
    }
}
