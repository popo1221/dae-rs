# dae-rs 压力测试指南

本文档介绍如何对 dae-rs 进行压力测试和内存泄漏检测。

## 1. 运行基准测试

### 前置条件

```bash
# 安装 Rust 和 cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 确保在项目根目录
cd /root/Projects/dae-rs
```

### 运行基准测试

```bash
# 运行所有基准测试
cargo bench

# 运行特定基准测试
cargo bench -- socks5_handshake
cargo bench -- rule_matching
cargo bench -- xdp_map_lookup

# 生成 HTML 报告
# 报告位于 target/criterion/html/index.html
```

## 2. 基准测试说明

### SOCKS5 Handshake 基准测试
- 测试不同地址类型（IPv4/IPv6/Domain）的解析性能
- 测试不同数据大小的处理能力

### HTTP CONNECT 基准测试
- 测试 HTTP 头部解析性能
- 测试 URL 解析性能

### Shadowsocks 解密基准测试
- 测试不同加密算法（chacha20-ietf-poly1305, aes-256-gcm, aes-128-gcm）
- 测试不同负载大小的处理能力

### VLESS Handshake 基准测试
- UUID 验证性能
- 不同地址类型解析性能

### 规则匹配基准测试
- 100/1000/10000 条规则下的匹配性能
- Domain/IPCidr/GeoIP 匹配性能

### XDP Map Lookup 基准测试
- 不同 Map 大小（100/1000/10000/100000）的查找性能
- 连接跟踪查找性能
- 路由查找性能

### 数据包处理基准测试
- 不同数据包大小（64/256/1024/4096/65535 字节）的处理吞吐量

### 连接池基准测试
- 连接键创建性能
- 并发访问性能

## 3. 内存泄漏检测

### 运行内存测试

```bash
# 运行所有内存泄漏测试
cargo test -p dae-proxy --test memory_leak_tests

# 运行特定内存测试
cargo test -p dae-proxy --test memory_leak_tests test_arc_drop_on_scope_exit

# 运行忽略的长期测试
cargo test -p dae-proxy --test memory_leak_tests -- --ignored
```

### 内存测试说明

| 测试名称 | 说明 |
|---------|------|
| `test_arc_drop_on_scope_exit` | 验证 Arc 在作用域退出时正确释放 |
| `test_rule_engine_arc_sharing` | 验证规则引擎 Arc 共享和引用计数 |
| `test_connection_arc_cleanup` | 验证连接 Arc 正确清理 |
| `test_box_heap_allocation` | 验证 Box 堆分配正确释放 |
| `test_boxed_trait_objects` | 验证 trait object 正确清理 |
| `test_connection_pool_no_leak_on_insert` | 验证连接池插入不泄漏 |
| `test_connection_pool_concurrent_access` | 验证并发访问无泄漏 |
| `test_rule_engine_no_leak_on_reload` | 验证配置热重载无泄漏 |
| `test_rule_matching_no_allocation` | 验证规则匹配热路径不分配 |
| `test_abandoned_task_no_leak` | 验证废弃任务不泄漏 |
| `test_cancelled_task_cleanup` | 验证取消任务正确清理 |
| `test_long_running_memory_stability` | 30秒内存稳定性测试 |
| `test_high_concurrency_no_leak` | 高并发无泄漏测试 |
| `test_shadowsocks_handler_no_leak` | Shadowsocks 处理器无泄漏 |
| `test_rwlock_no_leak_on_contention` | RwLock 竞争无泄漏 |

## 4. 集成测试

### 运行集成测试

```bash
# 运行所有集成测试
cargo test -p dae-proxy --test integration_tests

# 运行特定集成测试
cargo test -p dae-proxy --test integration_tests test_concurrent_connection_insertions

# 运行忽略的长期测试
cargo test -p dae-proxy --test integration_tests -- --ignored
```

### 集成测试说明

| 测试名称 | 说明 |
|---------|------|
| `test_socks5_handler_basic` | SOCKS5 处理器基本功能 |
| `test_shadowsocks_handler_creation` | Shadowsocks 处理器创建 |
| `test_rule_engine_basic_matching` | 规则引擎基本匹配 |
| `test_connection_pool_basic_ops` | 连接池基本操作 |
| `test_concurrent_connection_insertions` | 50 并发任务 × 200 连接 |
| `test_concurrent_read_write` | 并发读写测试 |
| `test_rule_engine_many_rules` | 10000 条规则压力测试 |
| `test_rule_engine_concurrent_matching` | 20 并发任务规则匹配 |
| `test_connection_expiration` | 连接过期测试 |
| `test_connection_pool_max_size_enforcement` | 连接池大小限制 |
| `test_thirty_second_memory_stability` | 30秒内存稳定性 |
| `test_config_hot_reload_stability` | 10次配置热重载稳定性 |
| `test_ipv6_connections` | IPv6 连接测试 |
| `test_packet_info_creation` | 数据包信息创建 |
| `test_packet_info_with_domain` | 带域名的数据包信息 |
| `test_packet_info_with_geoip` | 带 GeoIP 的数据包信息 |

## 5. 性能指标参考

### 预期性能范围

| 组件 | 指标 | 预期范围 |
|-----|------|---------|
| SOCKS5 Handshake | 延迟 | < 1ms |
| HTTP CONNECT | 延迟 | < 2ms |
| Shadowsocks (chacha20) | 吞吐量 | 500-800 Mbps |
| Shadowsocks (aes-128-gcm) | 吞吐量 | 1-2 Gbps |
| Shadowsocks (aes-256-gcm) | 吞吐量 | 800 Mbps - 1.5 Gbps |
| Rule Matching (100 rules) | 延迟 | < 10μs |
| Rule Matching (1000 rules) | 延迟 | < 100μs |
| Rule Matching (10000 rules) | 延迟 | < 1ms |
| XDP Map Lookup | 延迟 | < 1μs |

### 内存使用参考

| 场景 | 预期内存 |
|-----|---------|
| 空闲状态 | < 10 MB |
| 10000 连接 | 50-100 MB |
| 10000 规则 | 20-50 MB |
| 峰值（压力测试） | < 500 MB |

## 6. 使用 valgrind 检测内存泄漏（Linux）

```bash
# 安装 valgrind
sudo apt-get install valgrind

# 运行内存检查
valgrind --leak-check=full --show-leak-kinds=all cargo test -p dae-proxy

# 检测未初始化的内存
valgrind --track-origins=yes cargo test -p dae-proxy
```

## 7. 使用 miri 进行内存安全检测

```bash
# 安装 miri
rustup component add miri

# 运行 miri 检测
cargo miri test -p dae-proxy
```

## 8. 持续压力测试

### 长时间运行测试

```bash
# 运行 30 秒内存稳定性测试
cargo test -p dae-proxy --test integration_tests -- test_thirty_second_memory_stability --ignored --nocapture

# 运行 10 次配置热重载测试
cargo test -p dae-proxy --test integration_tests -- test_config_hot_reload_stability --ignored --nocapture
```

### 并发连接压力测试

```bash
# 100 并发任务各创建 100 连接 = 10000 连接
cargo test -p dae-proxy --test integration_tests test_concurrent_connection_insertions -- --nocapture
```

## 9. 性能分析

### 使用 flamegraph

```bash
# 安装 cargo-flamegraph
cargo install cargo-flamegraph

# 生成火焰图
cargo flamegraph --bench proxy_benchmarks -- socks5_handshake
```

### 使用 perf

```bash
# Linux perf 分析
perf record -g cargo bench -- socks5_handshake
perf report
```

## 10. 常见问题

### Q: 基准测试运行时间过长？
A: 使用 `--profile-time` 选项减少迭代次数：
```bash
cargo bench -- --profile-time 5
```

### Q: 内存测试失败？
A: 确保运行 release 模式以获得准确结果：
```bash
cargo test --release -p dae-proxy --test memory_leak_tests
```

### Q: 并发测试不稳定？
A: 在具有足够 CPU 核心的机器上运行，并避免在虚拟机中运行。
