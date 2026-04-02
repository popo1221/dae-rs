//! dae-rs Proxy Benchmarks

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use std::net::Ipv4Addr;

// Import from dae-proxy
use dae_proxy::{
    rules::{DomainRule, IpCidrRule, Rule, RuleWithAction, RuleMatchAction},
    socks5::Socks5Address,
    SsCipherType,
};

// ============================================================================
// Benchmark Helpers
// ============================================================================

fn create_rule_with_actions(count: usize) -> Vec<RuleWithAction> {
    let mut rules = Vec::new();
    
    for i in 0..count {
        let rule = Rule::Domain(DomainRule::new(&format!("example{i}.com")));
        rules.push(RuleWithAction {
            rule,
            action: RuleMatchAction::Pass,
            priority: i as u32,
        });
    }
    
    rules
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
                
                let addr = Socks5Address::IPv4(Ipv4Addr::new(192, 168, 1, 1), 8080);
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
        group.bench_with_input(BenchmarkId::from_parameter(header_count), header_count, |b, &count| {
            b.iter(|| {
                let headers: Vec<(String, String)> = (0..count)
                    .map(|i| (format!("header-{i}"), format!("value-{i}")))
                    .collect();
                black_box(&headers);
            });
        });
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
        ("chacha20-ietf-poly1305", SsCipherType::Chacha20IetfPoly1305),
        ("aes-256-gcm", SsCipherType::Aes256Gcm),
        ("aes-128-gcm", SsCipherType::Aes128Gcm),
    ];
    
    for (name, cipher) in ciphers.iter() {
        for payload_size in [64, 512, 4096].iter() {
            group.throughput(Throughput::Bytes(*payload_size as u64));
            group.bench_with_input(BenchmarkId::new(*name, payload_size), payload_size, |b, &size| {
                b.iter(|| {
                    // Fixed size buffer for benchmarking
                    let buffer = vec![0u8; 4100];
                    black_box(&buffer);
                    let cipher_type = black_box(*cipher);
                    black_box(cipher_type);
                });
            });
        }
    }
    
    group.finish();
}

// ============================================================================
// Rule Matching Benchmark (Synchronous)
// ============================================================================

fn rule_matching_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_matching");
    
    for rule_count in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(*rule_count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(rule_count), rule_count, |b, &count| {
            let rules = create_rule_with_actions(count);
            
            let packet_info = dae_proxy::rule_engine::PacketInfo::new(
                Ipv4Addr::new(192, 168, 1, 100).into(),
                Ipv4Addr::new(8, 8, 8, 8).into(),
                12345,
                443,
                6,
            );
            
            b.iter(|| {
                // Simple linear search matching
                for rule in &rules {
                    if rule.rule.matches(&packet_info) {
                        black_box(Some(rule.action));
                        break;
                    }
                }
                black_box(None::<RuleMatchAction>);
            });
        });
    }
    
    // Benchmark domain pattern matching
    for pattern_len in [10, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(pattern_len), pattern_len, |b, &len| {
            b.iter(|| {
                let pattern = "a".repeat(len);
                let rule = DomainRule::new(&pattern);
                black_box(rule);
            });
        });
    }
    
    // Benchmark IPCIDR matching setup
    for cidr_count in [100, 1000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(cidr_count), cidr_count, |b, &count| {
            b.iter(|| {
                let mut rules = Vec::new();
                for i in 0..count {
                    if let Ok(rule) = IpCidrRule::new(&format!("{}.{}.{}.0/24", i / 256, i % 256, i % 128)) {
                        rules.push(rule);
                    }
                }
                black_box(rules);
            });
        });
    }
    
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
            let tuple = (0xC0A80164u64) << 48 | (0x08080808u64) << 16 | (12345u64) << 32 | 443u64 | (6u64) << 56;
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
            let key = (0xC0A80164u32, 0x08080808u32, 12345u16, 443u16, 6u8);
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
// Packet Info Creation Benchmark
// ============================================================================

fn packet_info_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_info");
    
    for _size in [64, 256, 1024].iter() {
        group.bench_function("create_packet_info", |b| {
            b.iter(|| {
                let packet = dae_proxy::rule_engine::PacketInfo::new(
                    Ipv4Addr::new(192, 168, 1, 100).into(),
                    Ipv4Addr::new(8, 8, 8, 8).into(),
                    12345,
                    443,
                    6,
                )
                .with_domain("example.com")
                .with_geoip("US");
                black_box(packet);
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
    rule_matching_benchmark,
    xdp_map_lookup_benchmark,
    packet_processing_benchmark,
    connection_pool_benchmark,
    packet_info_benchmark,
);
criterion_main!(benches);
