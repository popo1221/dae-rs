//! TUN 透明代理实现
//!
//! 提供 TUN 设备管理和 IP 数据包路由，用于透明代理。
//!
//! 本模块在 IP 层拦截网络流量，根据规则引擎的决策路由数据包——
//! 要么通过代理，要么直接连接。
//!
//! # 架构设计
//!
//! - `TunDevice`: 使用 tokio-tun 的 TUN 设备封装
//! - `TunPacketParser`: 从原始数据包解析 IP/TCP/UDP 头部
//! - `DnsHijacker`: 处理 DNS 劫持以实现基于域名的路由
//! - `TunRouter`: 根据规则引擎决策路由数据包
//!
//! # 使用示例
//!
//! ```ignore
//! let config = TunConfig {
//!     enabled: true,
//!     interface: "dae0".to_string(),
//!     tun_ip: "10.0.0.1".to_string(),
//!     tun_netmask: "255.255.255.0".to_string(),
//!     dns_hijack: vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()],
//!     mtu: 1500,
//! };
//!
//! let tun = TunProxy::new(config, rule_engine, connection_pool, dns_hijacker);
//! tun.start().await?;
//! ```

mod device;
mod dns;
mod packet;
mod routing;
mod tcp;
mod udp;

// Re-export public types
pub use device::{TunConfig, TunProxy, TunStats};
pub use dns::{new_dns_hijacker, DnsHijackEntry, DnsHijacker, SharedDnsHijacker};
pub use packet::{
    DnsQuery, IpHeader, IpProtocol, PacketDirection, TcpFlags, TcpHeader, TunPacket, UdpHeader, U4,
};
pub use routing::RouteResult;
pub use tcp::{TcpSessionState, TcpTunSession};
pub use udp::UdpSessionData;

#[cfg(test)]
mod tests {
    use crate::connection_pool::ConnectionKey;
    use crate::rule_engine::{new_rule_engine, RuleEngineConfig};
    use crate::tun::device::{TunConfig, TunProxy};
    use crate::tun::dns::new_dns_hijacker;
    use crate::tun::packet::{DnsQuery, IpHeader, PacketDirection, TcpHeader, TunPacket};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    #[test]
    fn test_ip_header_parse() {
        // IPv4 packet: 20 bytes header + data
        let packet = vec![
            0x45, // Version 4, IHL 5
            0x00, // DSCP/ECN
            0x00, 0x28, // Total length: 40 bytes
            0x00, 0x00, // ID
            0x00, 0x00, // Flags/Fragment
            0x40, // TTL: 64
            0x06, // Protocol: TCP
            0x00, 0x00, // Checksum (zero for test)
            0xC0, 0xA8, 0x01, 0x64, // Source: 192.168.1.100
            0x08, 0x08, 0x08, 0x08, // Dest: 8.8.8.8
        ];

        let header = IpHeader::parse_ipv4(&packet);
        assert!(header.is_some());

        let header = header.unwrap();
        assert_eq!(header.version, crate::tun::packet::U4::new(4));
        assert_eq!(header.header_length, 20);
        assert_eq!(header.total_length, 40);
        assert_eq!(header.protocol, crate::tun::packet::IpProtocol::Tcp);
        assert_eq!(header.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(header.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_tcp_header_parse() {
        let tcp_header = vec![
            0xC0, 0xA8, // Source port: 49320
            0x00, 0x50, // Dest port: 80
            0x00, 0x00, 0x00, 0x01, // Sequence: 1
            0x00, 0x00, 0x00, 0x00, // Ack: 0
            0x50, // Data offset: 5 (20 bytes)
            0x02, // Flags: SYN
            0xFF, 0xFF, // Window: 65535
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
        ];

        let header = TcpHeader::parse(&tcp_header);
        assert!(header.is_some());

        let header = header.unwrap();
        assert_eq!(header.src_port, 49320);
        assert_eq!(header.dst_port, 80);
        assert!(header.is_syn());
        assert!(!header.is_syn_ack());
    }

    #[test]
    fn test_udp_header_parse() {
        let udp_header = vec![
            0xC0, 0xA8, // Source port: 49320
            0x00, 0x35, // Dest port: 53 (DNS)
            0x00, 0x1C, // Length: 28
            0x00, 0x00, // Checksum
        ];

        let header = crate::tun::packet::UdpHeader::parse(&udp_header);
        assert!(header.is_some());

        let header = header.unwrap();
        assert_eq!(header.src_port, 49320);
        assert_eq!(header.dst_port, 53);
        assert_eq!(header.length, 28);
    }

    #[test]
    fn test_dns_query_parse() {
        // Simplified DNS query for "example.com"
        let dns_query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: recursion desired
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            0x07, // "example" length
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, // "com" length
            b'c', b'o', b'm', // "com"
            0x00, // End
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];

        let query = DnsQuery::parse(&dns_query);
        assert!(query.is_some());

        let query = query.unwrap();
        assert_eq!(query.id, 0x1234);
        assert_eq!(query.domain, "example.com");
        assert_eq!(query.qtype, 1);
    }

    #[tokio::test]
    async fn test_tun_config_default() {
        let config = TunConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.interface, "dae0");
        assert_eq!(config.tun_ip, "10.0.0.1");
        assert_eq!(config.tun_netmask, "255.255.255.0");
        assert_eq!(config.mtu, 1500);
        assert_eq!(config.dns_hijack.len(), 2);
    }

    #[tokio::test]
    async fn test_dns_hijacker_cache() {
        let hijacker = new_dns_hijacker(vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        )]);

        // Check initial cache miss
        assert!(hijacker.lookup("example.com").await.is_none());

        // Cache an entry
        hijacker
            .cache_entry(
                "example.com".to_string(),
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            )
            .await;

        // Check cache hit
        let ip = hijacker.lookup("example.com").await;
        assert!(ip.is_some());
        assert_eq!(ip.unwrap(), IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));

        // Case insensitive lookup
        let ip = hijacker.lookup("EXAMPLE.COM").await;
        assert!(ip.is_some());
    }

    #[tokio::test]
    async fn test_dns_hijacker_is_hijacked_ip() {
        let hijacker = new_dns_hijacker(vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
        ]);

        assert!(hijacker.is_hijacked_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(hijacker.is_hijacked_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))));
        assert!(!hijacker.is_hijacked_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn test_tun_packet_parsing() {
        // Build a simple IPv4 + UDP + DNS packet
        // Total: 20 (IP) + 8 (UDP) + 25 (DNS) = 53 bytes
        let packet = vec![
            0x45, // Version 4, IHL 5
            0x00, // DSCP/ECN
            0x00, 0x35, // Total length: 53
            0x00, 0x00, // ID
            0x00, 0x00, // Flags/Fragment
            0x40, // TTL: 64
            0x11, // Protocol: UDP
            0x00, 0x00, // Checksum
            0xC0, 0xA8, 0x01, 0x64, // Source: 192.168.1.100
            0x08, 0x08, 0x08, 0x08, // Dest: 8.8.8.8
            // UDP header (8 bytes)
            0xC0, 0xA8, // Source port: 49320
            0x00, 0x35, // Dest port: 53
            0x00, 0x19, // Length: 25 (DNS payload only)
            0x00, 0x00, // Checksum
            // DNS query (25 bytes total: 12 header + 8 domain + 1 null + 2 QTYPE + 2 QCLASS)
            0x12, 0x34, // ID
            0x01, 0x00, // Flags
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            0x03, // "foo" length
            b'f', b'o', b'o', // "foo"
            0x03, // "bar" length
            b'b', b'a', b'r', // "bar"
            0x00, // End
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];

        let tun_packet = TunPacket::parse(packet.clone(), PacketDirection::Outbound);
        assert!(tun_packet.is_some());

        let tun_packet = tun_packet.unwrap();
        assert_eq!(tun_packet.dst_port(), 53);
        assert!(tun_packet.is_dns());
        assert!(tun_packet.is_udp());
        assert!(!tun_packet.is_tcp());

        // Verify DNS query was parsed successfully
        let dns = tun_packet
            .dns_query
            .expect("DNS query should be parsed - check DNS packet format in test");
        assert_eq!(dns.domain, "foo.bar");
        assert_eq!(dns.qtype, 1);
    }

    #[test]
    fn test_tcp_session_flags() {
        let syn_packet = vec![
            0xC0, 0xA8, // src port: 49320 (0xC0A8)
            0x00, 0x50, // dst port: 80
            0x00, 0x00, 0x00, 0x01, // seq: 1
            0x00, 0x00, 0x00, 0x00, // ack: 0
            0x50, // data offset: 5 (20 bytes header)
            0x02, // SYN flag
            0xFF, 0xFF, // window: 65535
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent pointer
        ];

        let header = TcpHeader::parse(&syn_packet).unwrap();
        assert_eq!(header.src_port, 49320);
        assert_eq!(header.dst_port, 80);
        assert!(header.is_syn());
        assert!(!header.is_syn_ack());
        assert!(!header.is_fin());
        assert!(!header.is_rst());
    }

    #[test]
    fn test_connection_key_from_raw() {
        let key = ConnectionKey::from_raw(
            u32::from_be_bytes([192, 168, 1, 100]),
            u32::from_be_bytes([8, 8, 8, 8]),
            49320,
            80,
            6,
        );

        assert_eq!(key.protocol(), crate::connection::Protocol::Tcp);

        let (src, dst) = key.to_socket_addrs().unwrap();
        assert_eq!(src.port(), 49320);
        assert_eq!(dst.port(), 80);
    }

    #[tokio::test]
    async fn test_tun_proxy_stats() {
        let rule_engine = new_rule_engine(RuleEngineConfig::default());
        let connection_pool = crate::connection_pool::new_connection_pool(
            Duration::from_secs(60),
            Duration::from_secs(30),
            Duration::from_secs(10),
        );
        let dns_hijacker = new_dns_hijacker(vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        )]);

        let config = TunConfig::default();
        let proxy = TunProxy::new(config, rule_engine, connection_pool, dns_hijacker);

        let stats = proxy.stats().await;
        assert_eq!(stats.active_tcp_sessions, 0);
        assert_eq!(stats.active_udp_sessions, 0);
        assert_eq!(stats.dns_cache_size, 0);
    }
}
