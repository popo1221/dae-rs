# CHANGELOG-SEC-1: TLS Reality Handshake Security Fix

## v0.1.1 | 2026-04-05

### 🐛 修复

- **SEC-1: TLS Reality 握手验证缺失 (Critical Security Fix)**
  - 文件: `packages/dae-proxy/src/transport/tls.rs`
  - 位置: `reality_handshake` 函数 (Step 6)
  - 问题: 客户端计算了 `_expected_mac` 但从未验证服务器响应，攻击者可以伪装服务器响应而无需正确签名
  - 修复: 
    1. 使用 `subtle::ConstantTimeEq` 进行时序安全的 MAC 比较
    2. 验证服务器响应的 MAC 与预期 MAC 匹配
    3. 验证失败时返回 `PermissionDenied` 错误而非继续连接
  - 影响: 防止中间人攻击者伪装 Reality 服务器

### 修复详情

**修复前 (漏洞代码):**
```rust
let _expected_mac = hmac_sha256(&shared_bytes, &verify_data);

// The last 32 bytes of ServerHello contain encrypted header
// which we would need to decrypt and verify
// For now, we trust the handshake if we get a valid ServerHello

Ok(stream)  // ❌ 漏洞: 从未验证 MAC
```

**修复后 (安全代码):**
```rust
let expected_mac = hmac_sha256(&shared_bytes, &verify_data);

// SEC-1 FIX: Verify the server's response using the expected MAC
let echoed_mac_offset = 12;
let echoed_mac = &server_response[echoed_mac_offset..echoed_mac_offset + 32];

use subtle::ConstantTimeEq;
if expected_mac.ct_eq(echoed_mac).into() {
    Ok(stream)
} else {
    Err(IoError::new(
        ErrorKind::PermissionDenied,
        "Reality handshake failed: server MAC verification failed",
    ))
}
```

### 安全影响

| 影响类别 | 描述 |
|---------|------|
| **攻击向量** | 攻击者可以在 TLS Reality 握手期间伪装服务器响应 |
| **利用条件** | 攻击者需要能够拦截客户端与服务器之间的流量 |
| **影响后果** | 攻击者可以在不知道共享密钥的情况下建立伪造连接 |
| **修复效果** | 服务器响应必须包含正确的 MAC，攻击者无法伪造 |

### 参考

- Reality 协议规范: [VLESS Reality](../../docs/01-vless-reality.md)
- Go dae 实现: `component/handler/vless.go`
- 原始问题: SEC-1 in `REVIEW_v3.md`

### 变更摘要

```
packages/dae-proxy/src/transport/tls.rs:
- 添加 MAC 验证逻辑
- 使用 subtle::ConstantTimeEq 进行时序安全比较
- 验证失败时返回 PermissionDenied 错误
- 移除 "trust handshake" 的不安全注释
```

---

*修复日期: 2026-04-05*
*修复者: dae-rs Security Subagent
*漏洞等级: Critical (CVE 级别)*
