# 💻 费曼代码笔记：vmess.rs — VMess AEAD-2022 协议实现

> 📅 学习日期：2026-04-04
> 📂 来源：packages/dae-proxy/src/vmess.rs
> 🏷️ 代码语言：Rust
> 📏 总行数：1229（含测试）
> ⭐ Value_Score：9/10（密码学密集，协议实现完整，测试覆盖全面）

---

## 一句话总结（10岁版本）

> VMess 是 V2Ray 的"加密快递协议"——客户端把要访问的地址和内容加密成一个"密封包裹"发给 dae-rs，dae-rs 用密码打开包裹、读出目的地址，再帮客户端把请求送到目的地。

---

## 简化法则自检

- [ ] 口语化讲解区全篇没有专业术语吗？
- [ ] 每个概念都有生活类比吗？
- [ ] 外婆能听懂吗？
- [ ] 数据流每个环节都能说清吗？
- [ ] 设计取舍（为什么这样做）讲清楚了吗？
- [ ] 副作用都列清楚了吗？

---

## 口语化讲解区（外婆版）

### VMess 是什么？

想象你要寄一封**加密信**给远方的朋友：

1. **你（客户端）**：把信放进一个锁盒子里，锁好，寄给 dae-rs
2. **dae-rs（快递站）**：用你给的钥匙（user_id）打开盒子，读出里面的目的地址，再帮你把信寄过去
3. **目标服务器**：只收到从 dae-rs 发来的信，不知道是你寄的

VMess 就是规定"怎么锁盒子"、"钥匙什么样"、"盒子里信的内容格式"的协议手册。

---

### VMess AEAD-2022（最新版）是怎么锁盒子的？

这版本用了三层密码学加固（外婆级解释）：

```
第一步：造钥匙
  user_id + "VMess AEAD" → 塞进 HMAC-SHA256 机器 → 出来 32 字节的"主钥匙"
  
第二步：用 nonce 再造一把临时钥匙
  主钥匙 + 16字节随机数(nonce) → HMAC-SHA256 → 造出"信封钥匙"(32字节) + "信封开口器"(12字节)
  
第三步：锁盒子
  用 AES-256-GCM + 信封钥匙 + 信封开口器 → 把原始内容锁进密文
  密文 = [nonce(16字节)][加密内容+认证标签(16字节)]
```

为什么这么复杂？因为每封信的 nonce 都不同，即使两封信内容完全相同，密文也完全不同——攻击者无法发现"这是两封相同的信"。

---

### 数据包长什么样？

```
┌─────────────────────────────────────────────────┐
│  [4字节: 长度]                                   │
│  [16字节: nonce（随机数）]                       │ ← 这个用来解锁
│  [加密内容 + 16字节认证标签]                      │ ← 锁着的信内容
└─────────────────────────────────────────────────┘
```

解密后盒子里的内容格式：
```
[1字节版本][1字节选项][2字节端口][1字节地址类型][可变长地址][4字节时间戳][4字节随机][4字节校验和]
```

地址类型（0x01=IPv4, 0x02=域名, 0x03=IPv6）和 SOCKS5 一样，但多了一层加密。

---

### 三种加密等级（从旧到新）

| 加密类型 | 代码值 | 安全等级 | 说明 |
|---------|--------|---------|------|
| AES-128-CFB | 0x01 | ⚠️ 弱 | 旧版，已不推荐 |
| AES-128-GCM | 0x02 | ✅ 好 | 常规 GCM 模式 |
| AES-128-GCM-AEAD | 0x11 | ✅✅ 最强 | **2022年新版**，默认选项 |

默认值：`VmessSecurity::Aes128GcmAead`

---

## 专业结构区（同行版）

### 类型层次

```
VmessServerConfig        — 上游 VMess 服务器配置（地址/端口/user_id/加密类型）
VmessClientConfig        — 本地 VMess 客户端配置（监听地址/服务器配置/超时）
VmessTargetAddress       — 目标地址（Ipv4/Domain/Ipv6）+ 端口解析
VmessHandler             — 实际处理逻辑（密钥派生/头解密/TCP中继）
VmessServer              — TCP 监听服务器（accept + 分发到 Handler）
```

### AEAD-2022 密钥派生链

```
user_id (UUID 字符串)
    │
    ▼ HMAC-SHA256("VMess AEAD")
user_key [32 bytes]
    │
    ▼ HMAC-SHA256(user_key, nonce)
auth_result [32 bytes]
    │
    ├──▼ HKDF-Expand(auth_result, "VMess header"||0x01) → request_key [32 bytes]
    │
    └──▼ HMAC-SHA256(auth_result, nonce)[..12] → request_iv [12 bytes]
              │
              ▼ AES-256-GCM(key=request_key, nonce=request_iv)
         解密后的 header 明文
```

### 头解密流程（handle() 主逻辑）

```
1. client.read_exact(&mut len_buf[4])      // 读 4 字节长度前缀
2. header_len = u32::BE 解码
3. if header_len > 65535 → reject
4. client.read_exact(&mut encrypted_header) // 读 encrypted_header[header_len]
5. user_key = derive_user_key(&self.config.server.user_id)
6. decrypted_header = decrypt_header(&user_key, &encrypted_header)
   └─ decrypt_header:
       ├─ nonce = encrypted[..16]
       ├─ (request_key, _) = derive_request_key_iv(user_key, nonce)
       ├─ cipher = Aes256Gcm::new(&request_key)
       └─ cipher.decrypt(nonce, ciphertext_with_tag) → 明文
7. VmessTargetAddress::parse_from_bytes(&decrypted_header) → target
8. TcpStream::connect(remote_addr) → remote
9. relay(client, remote) → tokio::io::copy 双向拷贝
```

### relay() 双向拷贝（异步并行）

```rust
let (mut cr, mut cw) = client.split();
let (mut rr, mut rw) = remote.split();
tokio::try_join!(
    tokio::io::copy(&mut cr, &mut rw),  // 客户端 → 远程
    tokio::io::copy(&mut rr, &mut cw),  // 远程 → 客户端
)?;
```

### VmessTargetAddress 解析规则

| ATYP | 格式 | 字节数 |
|------|------|--------|
| 0x01 | IPv4: `[1字节类型][4字节IP][2字节端口]` | 7 |
| 0x02 | 域名: `[1字节类型][1字节长度][域名][2字节端口]` | 4+域名长 |
| 0x03 | IPv6: `[1字节类型][16字节IP][2字节端口]` | 19 |

### fallback heuristic（兼容性设计）

当标准解析失败时（非标准 VMess 实现），代码在解密后的数据中搜索 `0x01..=0x03` 字节作为地址类型标记，然后从该位置重新解析。这是个"尽力而为"的降级路径，代码自己也标注了"fragile"。

---

## 关键调用链追溯

### 从 VmessServer::start 开始

```
VmessServer::start (Arc<Self>)
    └─ loop {
           listener.accept() → (client, addr)
               └─ tokio::spawn → handler.handle(client)
                   ├─ read 4-byte length prefix
                   ├─ read encrypted_header
                   ├─ derive_user_key(user_id)          // HMAC-SHA256
                   ├─ decrypt_header(user_key, enc)     // AES-256-GCM
                   ├─ VmessTargetAddress::parse          // 从解密数据读目标地址
                   ├─ TcpStream::connect(remote)        // 连上游 VMess 服务器
                   └─ relay(client, remote)             // tokio::io::copy 双向中继
       }
```

### 密钥派生调用路径

```
derive_user_key(user_id: &str)
    └─ hmac_sha256(user_id.as_bytes(), b"VMess AEAD") → [u8; 32]

derive_request_key_iv(user_key: &[u8; 32], nonce: &[u8])
    ├─ auth_result = hmac_sha256(user_key, nonce)
    ├─ request_key = hkdf_expand_sha256(auth_result, "VMess header")
    └─ request_iv  = hmac_sha256(auth_result, nonce)[..12]

decrypt_header(user_key, encrypted)
    └─ Aes256Gcm::new(derive_request_key_iv(...).0)
        └─ cipher.decrypt(...) → Vec<u8>
```

---

## 设计取舍说明

### 1. VMessAEAD-2022 而非旧版 VMess

**为什么**：旧版 VMess 的头部是明文传输的（除内容外），可以被被动审计识别。AEAD-2022 将整个请求头加密，提供了更好的协议混淆和机密性。

**取舍**：CPU 开销稍高，但安全性提升显著。代码默认 `enable_aead: true`。

### 2. AES-256-GCM 而非 ChaCha20-Poly1305

**为什么**：代码优先使用 AES-256-GCM（`VmessSecurity::default() = Aes128GcmAead`）。这是因为在现代 x86_64 CPU 上，AES-NI 硬件指令使 AES 速度远快于 ChaCha20。

**取舍**：ChaCha20 在没有 AES-NI 的 ARM 设备上更优，但默认值保守地选择了 AES 系列。

### 3. 16字节 nonce + 12字节 IV

**为什么**：AES-GCM 标准要求 12 字节 nonce 生成 12 字节 IV。代码在 16 字节 nonce 中取前 12 字节给 AES-GCM，这是 VMess AEAD-2022 规范规定的。

**取舍**：nonce 前 12 字节用于 AES-GCM，后 4 字节被截断（规范行为）。

### 4. tokio::io::copy 双向拷贝

**为什么**：使用 tokio 的异步 I/O 拷贝而非手动 buffer 循环，可以充分享受异步调度的好处。

**取舍**：无法精细控制流量（无法在此层做流量整形或延迟注入），但代码简洁高效。

### 5. UDP handle_udp 未标记为 #[cfg(test)] 但标记了 #[allow(dead_code)]

**为什么**：UDP 处理逻辑存在但未被调用。这可能是为未来 UDP 支持预留的。

**取舍**：存在死代码，诚实标记 `#[allow(dead_code)]` 而非删除。

### 6. fallback heuristic

**为什么**：某些 VMess 客户端实现不遵循标准头格式，标准解析失败时需要降级尝试。

**取舍**：降级路径是"暴力搜索地址类型字节"，在密文/随机数据中可能误匹配。但这是兼容性的必要代价，代码有警告日志。

### 7. HMAC-SHA256 手动 HKDF-Expand 实现

**为什么**：代码没有使用 `hkdf` crate，而是手动实现 HKDF-Expand 的单次迭代。

**取舍**：少了一个依赖，代码更可控。HKDF-Expand 本身定义就是一次 HMAC，代码实现是正确的。

---

## 大白话总结（外婆版）

> vmess.rs 就是"加密快递站的作业手册"。
>
> 它告诉 dae-rs 怎么：
> 1. **收快递**：接收客户端发来的密封加密包裹（VMess AEAD-2022 格式）
> 2. **开锁**：用客户给的钥匙（user_id 通过 HMAC-SHA256 派生）打开锁（AES-256-GCM 解密）
> 3. **读地址**：从包裹里拿出目的地址（IPv4/域名/IPv6）
> 4. **发快递**：帮客户把东西送到目的地（TCP relay），目的地只知道 dae-rs，不知道原始客户
>
> 最厉害的是这个锁用了"一次一密"——每次快递的锁芯都不一样，即使两个客户寄同样的东西，包裹看起来完全不一样。
