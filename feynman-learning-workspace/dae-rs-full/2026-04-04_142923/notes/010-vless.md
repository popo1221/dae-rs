# 💻 费曼代码笔记：vless.rs — VLESS 协议 + Reality Vision 实现

> 📅 学习日期：2026-04-04
> 📂 来源：packages/dae-proxy/src/vless.rs
> 🏷️ 代码语言：Rust
> ⭐ Value_Score：9/10

## 一句话总结（10岁版本）

> 这个文件实现了 VLESS 协议——一种"加密快递"协议。它不仅能做普通 TCP/UDP 转发，还支持 Reality Vision 这种"伪装术"，能把你的流量假装成正常浏览 Google 的 HTTPS 流量，让审查者根本看不出你在翻墙。

---

## 简化法则自检

- [ ] 口语化讲解区全篇没有专业术语吗？❌（不可避免地保留了协议术语，但都做了类比）
- [ ] 每个概念都有生活类比吗？✅
- [ ] 外婆能听懂吗？✅（有"快递"和"伪装"类比）
- [ ] 数据流每个环节都能说清吗？✅
- [ ] 设计取舍（为什么这样做）讲清楚了吗？✅
- [ ] 副作用都列清楚了吗？✅

---

## 口语化讲解区（外婆版）

### VLESS 是什么？

想象你要寄一个**加密包裹**给远方的朋友：

1. **普通快递（TCP）**：你把包裹交给快递员，快递员帮你送到。包裹是加密的，但快递员知道你寄给谁。
2. **VLESS UDP**：你寄的是明信片大小的包裹（UDP），每张明信片上都有固定格式的抬头格式。
3. **Reality Vision（终极伪装）**：你把包裹伪装成从"美国纽约 Google 公司"寄出的正常退货包裹。快递员看了都以为是正常退货，完全不知道里面是你的翻墙流量。

### 三个命令（Command）

VLESS 协议有三种"命令"：

| 命令值 | 名称 | 比喻 |
|--------|------|------|
| 0x01 | TCP | 寄普通包裹，需要建立连接 |
| 0x02 | UDP | 寄明信片，不用建立连接 |
| 0x03 | XTLS Vision | 伪装成国际快递公司的退货包裹 |

### Reality Vision 的工作原理（重点！）

```
外婆，Reality Vision 就像这样：

1. 你先去买一个"一次性伪装身份"（X25519 临时密钥对）
2. 用这个临时身份和"国际快递公司"（目标服务器）的公钥
   算出一个只有你们俩知道的秘密
3. 制作一张假发票（TLS ClientHello），假装是 Google 的退货部门
4. 快递公司看到发票就放行了，因为看起来完全合法
5. 实际上你的包裹被悄悄转接到了"翻墙服务器"
```

### UDP 包格式（比 TCP 复杂！）

```
┌────────┬──────────┬────┬────┬────────┬───────┬─────────┬────────┬──────────┐
│ v1=1B  │ UUID=16B │ver │cmd │ port=4B│ atyp  │ address │ iv=16B │ payload  │
└────────┴──────────┴────┴────┴────────┴───────┴─────────┴────────┴──────────┘
```

注意！port 是**4字节**（其他协议通常是2字节），iv（初始向量）是16字节用于加密。

### 地址类型

| ATYP值 | 类型 | 格式 |
|--------|------|------|
| 0x01 | IPv4 | 1B类型 + 4B IP + 2B端口 |
| 0x02 | 域名 | 1B类型 + 1B长度 + 域名 + 2B端口 |
| 0x03 | IPv6 | 1B类型 + 16B IP + 2B端口 |

### UUID 验证（身份认证）

VLESS 用 UUID（16字节）来识别用户。每次连接都会验证 UUID 是否匹配配置。就像：
> 快递员说："你的工牌号是 XXX 吗？" → 匹配才收件

---

## 专业结构区（同行版）

### 核心数据结构

```rust
// VLESS 命令类型
pub enum VlessCommand {
    Tcp = 0x01,
    Udp = 0x02,
    XtlsVision = 0x03,
}

// 地址类型
pub enum VlessAddressType {
    Ipv4 = 0x01,
    Domain = 0x02,
    Ipv6 = 0x03,
}

// Reality 配置
pub struct VlessRealityConfig {
    pub private_key: Vec<u8>,   // X25519 私钥（32字节）
    pub public_key: Vec<u8>,    // 服务器公钥（32字节）
    pub short_id: Vec<u8>,      // 短ID（8字节，用于识别目标服务器）
    pub destination: String,    // 伪装的 SNI（通常是 google.com）
    pub flow: String,           // 通常是 "vision"
}
```

### Reality Vision 密钥交换流程

```
Client                              Server
  │                                    │
  │  1. 生成 X25519 临时密钥对          │
  │     (scalar, public_key)           │
  │                                    │
  │  2. ECDH 共享密钥 = server_pub * scalar
  │                                    │
  │  3. HMAC-SHA256(共享密钥, "Reality Souls") → 48字节请求
  │     - 前32字节: HMAC
  │     - 后16字节: short_id(8B) + random(8B)
  │                                    │
  │  4. 构建 TLS ClientHello (Chrome 指纹)
  │     - 伪造 Chrome 的 TLS 指纹
  │     - SNI 设为 destination (如 google.com)
  │     - key_share 包含 client_public
  │                                    │
  │───────────────────────────────────│
  │  5. 发送 ClientHello               │
  │───────────────────────────────────>│
  │                                    │
  │<───────────────────────────────────│
  │  6. 接收 ServerHello (解密后包含真实目标)│
  │                                    │
  │  7. 双向转发（relay）                │
```

### TLS ClientHello 构建（手动拼接字节）

```rust
// 手动构建 TLS 1.3 ClientHello，包含：
// - SNI 扩展 (server_name)
// - ALPN 扩展 (h2, http/1.1)
// - supported_versions 扩展 (TLS 1.3)
// - key_share 扩展 (X25519 public key)
// - psk_key_exchange_modes 扩展
```

### 关键方法

| 方法 | 作用 |
|------|------|
| `handle_vless()` | 主入口，解析 header，dispatch 到 TCP/UDP/XTLS |
| `handle_tcp()` | 标准 VLESS TCP relay |
| `handle_udp()` | UDP 包处理，解析 header，forward 到服务器 |
| `handle_reality_vision()` | X25519 密钥交换 + TLS ClientHello 构建 |
| `build_reality_client_hello()` | 手动拼接 TLS 1.3 ClientHello |
| `relay()` | tokio::io::copy 双向流复制 |
| `parse_target_address()` | 解析 ATYP 地址 |

---

## 关键调用链追溯

### TCP 连接入口

```
TcpListener.accept()
  → VlessServer::start() [spawns handle_vless]
    → VlessHandler::handle_vless()
        → 读取 VLESS_HEADER_MIN_SIZE (38字节)
        → 验证 version, UUID, command
        → match command:
            → Tcp  → handle_tcp() → relay()
            → Udp  → 返回错误（UDP走UDP端口）
            → XtlsVision → handle_reality_vision() → relay()
```

### UDP 连接入口

```
UdpSocket.recv_from()
  → VlessHandler::handle_udp() [loop]
    → 解析 VLESS UDP header (至少40字节)
    → 验证 v1, UUID, ver, cmd=0x02
    → 提取 port(4B), atyp, addr, iv(16B), payload
    → 构建服务器包并 send_to
    → recv_from 服务器响应
    → send_to 客户端
```

### Reality Vision 流程

```
VlessHandler::handle_reality_vision()
  1. 生成 X25519 临时密钥对 (curve25519_dalek)
  2. ECDH 计算共享密钥
  3. HMAC-SHA256("Reality Souls") 生成 48字节 request
  4. build_reality_client_hello()
      - add_sni_extension()
      - add_alpn_extension()
      - add_supported_versions_extension()
      - add_psk_modes_extension()
      - add_reality_key_share()
  5. 连接服务器，发送 ClientHello
  6. 接收 ServerHello
  7. relay() 双向转发
```

---

## 设计取舍说明

### 1. 为什么 VLESS UDP 命令走 TCP 端口会报错？

```rust
VlessCommand::Udp => {
    error!("VLESS UDP: UDP traffic should go through the UDP port, not TCP");
    Err(...)
}
```

**原因**：VLESS 协议设计上，UDP 和 TCP 是**分开的**。TCP 端口处理 TCP 流，UDP 端口处理独立的 UDP 包。客户端如果把 UDP 流量发到 TCP 端口，说明客户端配置错误。

### 2. 为什么 UDP header 里 port 是 4 字节？

标准做法是 2 字节，但 VLESS UDP header 里 port 占 4 字节（见 `buf[19..22]`）。这是协议规范，可能是为了对齐或为将来扩展留空间。

### 3. 为什么 Reality Vision 用 HMAC-SHA256？

```rust
hmac_sha256(&shared_secret, b"Reality Souls")
```

Reality 协议用 HMAC 而不是直接 hash，是为了：
- 确保只有拥有共享密钥的双方能生成有效的请求
- 防止中间人构造假请求
- "Reality Souls" 是协议的魔数（magic string）

### 4. 为什么不完整实现 Reality Vision 的目标地址解析？

```rust
// For now, just relay between client and server
// A full implementation would parse the server's response to get
// the real destination address from the server's ServerHello
self.relay(client, remote).await
```

**原因**：完整的 Reality Vision 需要解析服务器返回的加密 header，提取真实目标地址。这个实现做了简化——建立隧道后直接 relay。真实场景中服务器会在 ServerHello 里告诉客户端真实目标。

### 5. 为什么用 rand::random() 而不是更安全的 RNG？

```rust
let random_bytes: [u8; 8] = rand::random();
```

用的是 `rand::rngs::OsRng` 和 `rand::random()`，这是系统级别的安全 RNG。对于临时密钥和 IV 足够好。

### 6. 为什么 add_reality_key_share 是半实现的？

```rust
// Note: The actual Reality implementation may encode the request
// differently. This is a simplified implementation.
```

注释里明确说这是简化实现。Reality 协议的实际 chrome 编码可能更复杂。当前实现只是把 client_public 放进了 key_share 扩展。

### 7. UDP relay 为什么用两个独立 socket？

```rust
let server_socket = match UdpSocket::bind("0.0.0.0:0").await { ... };
// send_to 到服务器
// recv_from 从服务器
// send_to 回客户端
```

客户端 UDP socket 和服务器 UDP socket 是**分开的**。这是因为 UDP 是无连接的，每次 `send_to` 可以指定不同目标。

### 8. 为什么 relay() 用 tokio::io::split？

```rust
let (mut cr, mut cw) = tokio::io::split(client);
let (mut rr, mut rw) = tokio::io::split(remote);
tokio::try_join!(client_to_remote, remote_to_client)?;
```

用 `split()` 把读写半口分开，然后 `try_join!` 并行双向复制。这是 TCP 代理的标准做法，避免死锁。

---

## 大白话总结

> vless.rs 就是"加密快递公司"的**完整实现手册**。
>
> 它支持三种快递方式：
> 1. **普通加密包裹（TCP）**：你把东西交给快递公司，公司帮你寄，收件人不知道是你寄的
> 2. **明信片（UDP）**：不用建立连接，直接寄明信片，适合 DNS 查询等短消息
> 3. **伪装国际快递（Reality Vision）**：把你的包裹伪装成从 Google 寄出的退货包裹，快递公司看了完全正常，根本不知道你在翻墙
>
> Reality Vision 是这个文件最复杂的部分——它手动拼接了一个 TLS 1.3 ClientHello，用 X25519 做密钥交换，让流量看起来像在跟 Google 聊天。
>
> **没有 Reality**：审查者可以看到你连接了哪个代理服务器
> **有 Reality**：审查者只看到你在正常浏览 Google.com，完全无感知
