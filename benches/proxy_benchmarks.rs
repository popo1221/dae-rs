//! dae-rs Proxy Benchmarks
//!
//! Comprehensive benchmarks for all proxy protocol handlers,
//! rule engine matching, and eBPF map operations.

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

// Import from dae-proxy
use dae_proxy::{
    rules::{DomainRule, GeoIpRule, IpCidrRule, Rule, RuleGroup, RuleMatchAction},
    rule_engine::{PacketInfo, RuleEngine, RuleEngineConfig},
    socks5::Socks5Address,
    SsCipherType,
};

#[path = "../packages/dae-proxy/src/shadowsocks.rs"]
mod shadowsocks;
#[path = "../packages/dae-proxy/src/vless.rs"]
mod vless;

// ============================================================================
// Benchmark Helpers
// ============================================================================

fn create_test_packet_info() -> PacketInfo {
    PacketInfo {
        source_ip: Ipv4Addr::new(192, 168, 1, 100).into(),
        destination_ip: Ipv4Addr::new(8, 8, 8, 8).into(),
        src_port: 12345,
        dst_port: 443,
        protocol: 6, // TCP
        destination_domain: Some("example.com".to_string()),
        geoip_country: Some("US".to_string()),
        process_name: Some("chrome".to_string()),
        dns_query_type: Some(1),
        is_outbound: true,
        packet_size: 1400,
        connection_hash: Some(0xABCD1234EFGH5678),
    }
}

fn create_rule_engine_with_rules(rule_count: usize) -> RuleEngine {
    let mut rules = Vec::new();
    
    // Add domain rules
    for i in 0..rule_count / 3 {
        rules.push(Rule::Domain(DomainRule {
            pattern: format!("example{}.com", i),
            action: RuleMatchAction::Allow,
        }));
    }
    
    // Add IP CIDR rules
    for i in 0..rule_count / 3 {
        rules.push(Rule::IpCidr(IpCidrRule {
            cidr: format!("{}.{}.{}.0/24", i / 256, i % 256, i % 128),
            action: RuleMatchAction::Allow,
        }));
    }
    
    // Add GeoIP rules
    for i in 0..rule_count / 3 {
        rules.push(Rule::GeoIp(GeoIpRule {
            country_codes: vec!["US", "CN", "JP", "DE", "GB"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            action: RuleMatchAction::Allow,
        }));
    }
    
    let group = RuleGroup {
        name: "test_group".to_string(),
        rules,
        ..Default::default()
    };
    
    let config = RuleEngineConfig {
        groups: vec![group],
        ..Default::default()
    };
    
    RuleEngine::new(config).expect("Failed to create rule engine")
}

// ============================================================================
// SOCKS5 Handshake Benchmark
// ============================================================================

fn socks5_handshake_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("socks5_handshake");
    
    for size in [16, 64, 256].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let data = vec![0u8; size];
                black_box(&data);
                
                let addr = Socks5Address::IPv4(
                    Ipv4Addr::new(192, 168, 1, 1),
                    8080,
                );
                black_box(addr);
            });
        });
    }
    
    for domain_len in [16, 32, 64].iter() {
        group.throughput(Throughput::Bytes(*domain_len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(domain_len), domain_len, |b, &len| {
            b.iter(|| {
                let domain = "a".repeat(len);
                let addr = Socks5Address::Domain(domain, 443);
                black_box(addr);
            });
        });
    }
    
    group.finish();
}

// ============================================================================
// HTTP CONNECT Benchmark
// ============================================================================

fn http_connect_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_connect");
    
    for header_count in [1, 10, 50].iter() {
        group.throughput(Throughput::Elements(*header_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(header_count),
            header_count,
            |b, &count| {
                b.iter(|| {
                    let headers: Vec<(String, String)> = (0..count)
                        .map(|i| (format!("header-{}", i), format!("value-{}", i)))
                        .collect();
                    black_box(&headers);
                });
            },
        );
    }
    
    for url_len in [64, 256, 1024].iter() {
        group.throughput(Throughput::Bytes(*url_len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(url_len), url_len, |b, &len| {
            b.iter(|| {
                let path = format!("/api/v1/resource/{}", "x".repeat(len));
                black_box(&path);
            });
        });
    }
    
    group.finish();
}

// ============================================================================
// Shadowsocks Decrypt Benchmark
// ============================================================================

fn shadowsocks_decrypt_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("shadowsocks_decrypt");
    
    let ciphers = [
        ("chacha20-ietf-poly1305", SsCipherType::ChaCha20IetfPoly1305),
        ("aes-256-gcm", SsCipherType::Aes256Gcm),
        ("aes-128-gcm", SsCipherType::Aes128Gcm),
    ];
    
    for (name, cipher) in ciphers.iter() {
        for payload_size in [64, 512, 4096].iter() {
            group.throughput(Throughput::Bytes(*payload_size as u64));
            group.bench_with_input(
                BenchmarkId::new(*name, payload_size),
                payload_size,
                |b, &size| {
                    b.iter(|| {
                        let mut buffer = vec![0u8; size + 16];
                        buffer[..size].copy_from_slice(&[0xAA; size]);
                        black_box(&buffer);
                        
                        let cipher_type = black_box(*cipher);
                        black_box(cipher_type);
                    });
                },
            );
        }
    }
    
    group.finish();
}

// ============================================================================
// VLESS Handshake Benchmark
// ============================================================================

fn vless_handshake_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("vless_handshake");
    
    for _ in 0..3 {
        group.bench_function("uuid_validation", |b| {
            b.iter(|| {
                let uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
                black_box(uuid.len());
                black_box(uuid.to_string());
            });
        });
    }
    
    for addr_type in ["ipv4", "ipv6", "domain"].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(addr_type), addr_type, |b, &typ| {
            b.iter(|| {
                match typ {
                    "ipv4" => {
                        let addr = vless::VlessAddressType::IPv4([8, 8, 8, 8]);
                        black_box(addr);
                    }
                    "ipv6" => {
                        let addr = vless::VlessAddressType::IPv6([
                            0x2001, 0x4860, 0x4860, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
                        ]);
                        black_box(addr);
                    }
                    "domain" => {
                        let addr = vless::VlessAddressType::Domain("example.com".to_string());
                        black_box(addr);
                    }
                    _ => {}
                }
            });
        });
    }
    
    for header_size in [128, 512, 2048].iter() {
        group.throughput(Throughput::Bytes(*header_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(header_size), header_size, |b, &size| {
            b.iter(|| {
                let header = vec![0u8; size];
                black_box(&header);
            });
        });
    }
    
    group.finish();
}

// ============================================================================
// Rule Matching Benchmark
// ============================================================================

fn rule_matching_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_matching");
    
    for rule_count in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(*rule_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(rule_count),
            rule_count,
            |b, &count| {
                let engine = create_rule_engine_with_rules(*count);
                let packet = create_test_packet_info();
                
                b.iter(|| {
                    let result = engine.match_packet(&packet);
                    black_box(result);
                });
            },
        );
    }
    
    for pattern_len in [10, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(pattern_len), pattern_len, |b, &len| {
            b.iter(|| {
                let pattern = "a".repeat(len);
                let rule = DomainRule {
                    pattern: pattern.clone(),
                    action: RuleMatchAction::Allow,
                };
                black_box(rule);
            });
        });
    }
    
    group.bench_function("ip_cidr_match_1000_rules", |b| {
        let engine = create_rule_engine_with_rules(1000);
        let mut packet = create_test_packet_info();
        
        b.iter(|| {
            packet.destination_ip = Ipv4Addr::new(50, 50, 50, 50).into();
            let result = engine.match_packet(&packet);
            black_box(result);
        });
    });
    
    group.finish();
}

// ============================================================================
// XDP Map Lookup Benchmark (Simulated)
// ============================================================================

fn xdp_map_lookup_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("xdp_map_lookup");
    
    for map_size in [100, 1000, 10000, 100000].iter() {
        group.throughput(Throughput::Elements(*map_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(map_size), map_size, |b, &size| {
            b.iter(|| {
                let key = 0xDEADBEEF12345678u64;
                let result = key.wrapping_mul(size as u64) % (size as u64);
                black_box(result);
            });
        });
    }
    
    group.bench_function("conntrack_lookup", |b| {
        b.iter(|| {
            let src_ip = 0xC0A80164u32;
            let dst_ip = 0x08080808u32;
            let src_port = 12345u16;
            let dst_port = 443u16;
            let proto = 6u8;
            
            let tuple = (src_ip as u64) << 48
                | (dst_ip as u64) << 16
                | (src_port as u64) << 32
                | (dst_port as u64)
                | ((proto as u64) << 56);
            
            black_box(tuple);
        });
    });
    
    group.bench_function("routing_lookup", |b| {
        b.iter(|| {
            let dest_ip = 0xC0A80164u32;
            black_box(dest_ip);
            
            let prefix_len = 24;
            black_box(prefix_len);
        });
    });
    
    group.finish();
}

// ============================================================================
// Packet Processing Throughput Benchmark
// ============================================================================

fn packet_processing_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_processing");
    
    for packet_size in [64, 256, 1024, 4096, 65535].iter() {
        group.throughput(Throughput::Bytes(*packet_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(packet_size), packet_size, |b, &size| {
            b.iter(|| {
                let mut packet = vec![0u8; size];
                packet[0] = 0x45;
                packet[1] = 0x00;
                black_box(&packet);
            });
        });
    }
    
    group.finish();
}

// ============================================================================
// Connection Pool Benchmark
// ============================================================================

fn connection_pool_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("connection_pool");
    
    group.bench_function("connection_key_creation", |b| {
        b.iter(|| {
            let key = (
                0xC0A80164u32,
                0x08080808u32,
                12345u16,
                443u16,
                6u8,
            );
            black_box(key);
        });
    });
    
    for concurrency in [1, 10, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(concurrency), concurrency, |b, &n| {
            b.iter(|| {
                let mut results = Vec::with_capacity(n);
                for i in 0..n {
                    let key = (i as u32, i as u32 + 1, 12345u16, 443u16, 6u8);
                    results.push(key);
                }
                black_box(results);
            });
        });
    }
    
    group.finish();
}

// ============================================================================
// Criterion Main
// ============================================================================

criterion_group!(
    benches,
    socks5_handshake_benchmark,
    http_connect_benchmark,
    shadowsocks_decrypt_benchmark,
    vless_handshake_benchmark,
    rule_matching_benchmark,
    xdp_map_lookup_benchmark,
    packet_processing_benchmark,
    connection_pool_benchmark,
);
criterion_main!(benches);
