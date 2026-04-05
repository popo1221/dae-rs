# CHANGELOG - CORR-3: IPv6 Fallback Connection Pool Bug

## v0.1.1 | 2026-04-05

### 🐛 修复

**CORR-3: IPv6 fallback 连接池静默降级到 0.0.0.0:0 导致连接失败**

**问题描述：**
连接池中 IPv6 连接静默降级到 `0.0.0.0:0`，导致连接失败。代码注释明确指出："This silently drops IPv6 connections"。

**根本原因：**
`ConnectionKey::to_socket_addrs()` 方法在遇到无效 IPv6 地址或格式错误的地址时，返回 `None` 并通过 `unwrap_or_else` 静默回退到 `0.0.0.0:0`。这导致：

1. 有效的 IPv6 连接被错误地替换为无效地址
2. 连接被创建但立即失败
3. 错误被隐藏在日志中，难以诊断

**修复方案：**

1. **改进 `to_socket_addrs()` 验证逻辑：**
   - 添加对 `src_ip` 和 `dst_ip` 的 `is_unspecified()` 检查
   - 如果任一地址是未指定地址（`0.0.0.0` 或 `::`），返回 `None` 而非静默替换
   - 添加详细文档说明返回值 `None` 表示地址无效

2. **移除危险的静默回退：**
   - 将 `unwrap_or_else` 替换为 `expect`
   - 当 `to_socket_addrs()` 返回 `None` 时，程序现在会立即 panic 并显示清晰的错误消息
   - 错误消息指出这表明地址处理或 eBPF 集成中存在 bug

**修复前：**
```rust
let (src, dst) = key.to_socket_addrs().unwrap_or_else(|| {
    warn!("IPv6 address conversion failed, falling back to 0.0.0.0:0");
    (SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
     SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
});
```

**修复后：**
```rust
let (src, dst) = key.to_socket_addrs().expect(
    "ConnectionKey has invalid IP addresses (possibly corrupted IPv6 data)"
);
```

**影响：**
- 此修复将把之前静默失败的 IPv6 连接转变为明显的 panic
- 这有助于快速识别数据损坏或地址处理中的 bug
- 不再有连接静默降级到无效地址的情况

**相关文件：**
- `packages/dae-proxy/src/connection_pool.rs`

**关联问题：**
- Code Review v3 (2026-04-05) 发现
- Issue: CORR-3
