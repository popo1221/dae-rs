# 协议实现详情

## 协议支持总览

| 协议 | 实现状态 | 说明 |
|------|----------|------|
| VLESS + Reality Vision | ✅ 完整 | 最新协议支持 |
| VMess AEAD-2022 | ✅ 完整 | 标准实现 |
| Shadowsocks AEAD | ✅ 完整 | 流加密不支持 |
| Trojan | ✅ 完整 | TCP + UDP Associate |
| TUIC | ✅ 完整 | QUIC 传输 |
| Hysteria2 | ✅ 完整 | 激进拥塞控制 |
| Juicity | ✅ 完整 | QUIC 轻量代理 |
| NaiveProxy/AnyTLS | ✅ 完整 | 链式代理 |
| SOCKS5 | ✅ 完整 | RFC 1928 |
| SOCKS4/SOCKS4A | ✅ 完整 | 传统协议 |
| HTTP CONNECT | ✅ 完整 | 标准 HTTP 代理 |

## VLESS + Reality

**状态**: ✅ 完整实现

### 协议特性

- **无状态认证**: VLESS 使用 UUID 进行身份验证，无连接状态
- **Reality Vision**: 流量伪装目标站点，支持XTLS Vision flow
- **TLS 传输**: 支持标准 TLS 和 Reality 两种模式
- **IPv6 支持**: 完整支持 IPv6 地址

### 配置示例

```toml
[[nodes]]
name = "VLESS Reality"
type = "vless"
server = "example.com"
port = 443
uuid = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
tls = true
tls_server_name = "www.microsoft.com"  # 伪装的 SNI

# Reality 配置
[ nodes.reality ]
enabled = true
public_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
short_id = "xxxxxxxx"
```

### Reality Vision Flow

Reality 使用 Vision flow 实现流量伪装：

```
Client                          Server
  │                               │
  │──── TLS ClientHello ─────────▶│
  │    (REALITY dest: microsoft)  │
  │                               │
  │◀──── TLS ServerHello ─────────│
  │    (伪装目标站点的证书)        │
  │                               │
  │──── VLESS Request ───────────▶│
  │    (UUID + flow control)     │
  │                               │
  │◀──── Data (Vision flow) ──────│
  │                               │
```

## VMess AEAD-2022

**状态**: ✅ 完整实现

### 协议特性

- **AEAD 加密**: VMess AEAD-2022 标准，使用 AEADEncrypt/AEADDecrypt
- **无状态认证**: 基于 UUID 的用户 ID
- **动态端口**: 支持动态端口分配
- **时间同步**: 需要客户端/服务器时间同步 (±90秒)

### 安全参数

| 参数 | 值 |
|------|-----|
| 加密算法 | AES-128-GCM / ChaCha20-Poly1305 |
| 认证算法 | HMAC-SHA256 |
| 头部加密 | AES-128-CTR |
| 时间窗口 | 90 秒 |

### 配置示例

```toml
[[nodes]]
name = "VMess AEAD"
type = "vmess"
server = "example.com"
port = 10086
uuid = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
security = "auto"  # 自动选择加密方式
tls = false
```

## Shadowsocks AEAD

**状态**: ✅ 完整实现（流加密不支持）

### 支持的加密方式

| 加密方式 | 状态 | 说明 |
|----------|------|------|
| `chacha20-ietf-poly1305` | ✅ | 推荐 |
| `aes-256-gcm` | ✅ | 标准 |
| `aes-128-gcm` | ✅ | 标准 |
| `2022-blake3-aes-256-gcm` | ✅ | Shadowsocks 2022 |
| `2022-blake3-chacha20-poly1305` | ✅ | Shadowsocks 2022 |
| 流加密 (rc4-md5 等) | ❌ | 不支持 |

### 配置示例

```toml
[[nodes]]
name = "Shadowsocks AEAD"
type = "shadowsocks"
server = "example.com"
port = 8388
method = "chacha20-ietf-poly1305"
password = "your-password"
```

## Trojan

**状态**: ✅ 完整实现

### 协议特性

- **TLS 传输**: 必须使用 TLS
- **Trojan-GFW**: 原始 Trojan 协议
- **Trojan-Go**: 支持 WebSocket 等扩展
- **UDP Associate**: 支持 UDP 转发

### 配置示例

```toml
[[nodes]]
name = "Trojan"
type = "trojan"
server = "example.com"
port = 443
trojan_password = "your-password"
tls = true
tls_server_name = "example.com"
```

### UDP Associate 支持

Trojan 的 UDP Associate 通过以下方式实现：

```
Client                          Server
  │                               │
  │──── Connect (TCP) ───────────▶│
  │                               │
  │──── UDP Associate ───────────▶│
  │    (open udp port)            │
  │                               │
  │◀──── UDP Response ───────────│
  │                               │
```

## TUIC

**状态**: ✅ 完整实现

### 协议特性

- **QUIC 传输**: 基于 QUIC 协议，低延迟
- **拥塞控制**: CUBIC / BBR
- **多路复用**: 连接复用，减少握手开销
- **0-RTT**: 支持 0-RTT 连接建立

### 配置示例

```toml
[[nodes]]
name = "TUIC"
type = "tuic"
server = "example.com"
port = 443
uuid = "your-uuid"
password = "your-password"
```

### TUIC 认证流程

```
Client                          Server
  │                               │
  │──── QUIC Initial ────────────▶│
  │    (Crypto Frame)             │
  │                               │
  │──── Authentication ──────────▶│
  │    (UUID + Password)          │
  │                               │
  │◀──── Session Ticket ─────────│
  │                               │
  │──── Data Streams ────────────▶│
  │                               │
```

## Hysteria2

**状态**: ✅ 完整实现

### 协议特性

- **QUIC 传输**: 基于 QUIC
- **激进拥塞控制**: Brute / BBR
- **带宽认证**: 基于带宽的身份验证
- **高性能**: 高丢包率网络表现优秀

### 配置示例

```toml
[[nodes]]
name = "Hysteria2"
type = "hysteria2"
server = "example.com"
port = 443
password = "your-password"
up_mbps = 100  # 上传带宽 (Mbps)
down_mbps = 500  # 下载带宽 (Mbps)
```

### 拥塞控制算法

| 算法 | 适用场景 |
|------|----------|
| `brute` | 高带宽高延迟网络 |
| `bbr` | 中等带宽，丢包率<5% |
| `cubic` | 兼容模式 |

## Juicity

**状态**: ✅ 完整实现

### 协议特性

- **QUIC 传输**: 轻量级 QUIC 实现
- **简单认证**: UUID + Password
- **拥塞控制**: CUBIC
- **低开销**: 头部开销小

### 配置示例

```toml
[[nodes]]
name = "Juicity"
type = "juicity"
server = "example.com"
port = 443
uuid = "your-uuid"
password = "your-password"
```

## NaiveProxy / AnyTLS

**状态**: ✅ 完整实现

### 协议特性

- **链式代理**: 多级代理串联
- **AnyTLS**: 端到端 TLS 加密
- **Camo 伪装**: 伪装为 WebRTC/Camo
- **Phantun**: UDP 伪装为 TCP

### 配置示例

```toml
[[nodes]]
name = "NaiveProxy"
type = "naiveproxy"
server = "example.com"
port = 443
username = "user"
password = "password"
tls_server_name = "example.com"
```

### 代理链结构

```
Client → Proxy1 (Camo) → Proxy2 (TLS) → Proxy3 → Target
         ↑                                  ↑
      伪装为                           端到端
      WebRTC                           TLS
```

## SOCKS5

**状态**: ✅ 完整实现

### 支持的特性

| 特性 | 状态 |
|------|------|
| Connect | ✅ |
| Bind | ⚠️ 部分 |
| UDP Associate | ✅ |
| GSSAPI 认证 | ❌ |
| CHAP 认证 | ✅ |
| No Auth | ✅ |

### 配置示例

```toml
[proxy]
socks5_listen = "127.0.0.1:1080"
```

## HTTP Proxy

**状态**: ✅ 完整实现

### 支持的认证

- 无认证
- Basic Auth
- Digest Auth (部分)

### 配置示例

```toml
[proxy]
http_listen = "127.0.0.1:8080"
```

## 协议协商流程

### 协议自动检测

dae-rs 使用首字节检测自动识别协议类型：

```rust
match first_byte {
    0x05 => SOCKS5,
    0x04 => SOCKS4,
    0x47..=0x54 => HTTP (CONNECT method),
    b'v' => VMess (vmess:// URI),
    b'/' or b'{' => Configuration format,
    _ => Unknown,
}
```

### 握手时序

```
Client                     dae-rs                      Upstream
   │                          │                           │
   │── TCP Connect ─────────▶│                           │
   │                          │── TCP Connect ───────────▶│
   │                          │                           │
   │── Protocol Detection ───▶│                           │
   │    (首字节分析)           │                           │
   │                          │                           │
   │── Protocol Handshake ───▶│── Protocol Handshake ───▶│
   │                          │                           │
   │◀── Auth Response ────────│◀── Auth Response ─────────│
   │                          │                           │
   │── Data ─────────────────▶│── Data ─────────────────▶│
   │◀── Response ────────────│◀── Response ──────────────│
   │                          │                           │
```
