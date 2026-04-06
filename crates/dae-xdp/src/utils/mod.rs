//! dae-xdp 工具模块
//!
//! 本模块包含数据包解析工具和协议常量定义，供 dae-xdp eBPF 程序内部使用。
//!
//! # 子模块
//!
//! - [`packet`]：数据包头部解析（Ethernet、IPv4、TCP、UDP、VLAN）

pub mod packet;
