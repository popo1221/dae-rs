# 传输层详解

## 传输层总览

dae-rs 实现了模块化的传输层抽象，支持多种传输方式：

```
┌─────────────────────────────────────────────┐
│              传输层抽象 (Transport)           │
├─────────────────────────────────────────────┤
│  ┌─────────┐ ┌──────┐ ┌────────┐ ┌───────┐ │
│  │   TCP   │ │ TLS  │ │  WS    │ │ gRPC  │ │
│  └────┬────┘ └──┬───┘ └───┬────┘ └───┬───┘ │
│       │         │         │          │      │
│       └─────────┴────┬────┴──────────┘      │
│                      │                       │
│              ┌───────┴───────┐               │
│              │   Meek       │               │
│              │ (域前置/云函数)│               │
│              └───────────────┘               │
└─────────────────────────────────────────────┘
```

## Transport Trait

所有传输层实现都遵循统一的 `Transport` trait：

```rust
#[async_trait]
pub trait Transport: Send + Sync + Debug {
    fn name(&self) -> &'static str;
    async fn dial(&self, addr: &str) -> std::io::Result<TcpStream>;
    async fn listen(&self, addr: &str) -> std::io::Result<tokio::net::TcpListener>;
    fn supports_udp(&self) -> bool { false }
    async fn local_addr(&self) -> Option<SocketAddr> { None }
}
```

## TCP 传输

**状态**: ✅ 完整实现

### 特性

- 原始 TCP 连接
- 非阻塞 I/O (Tokio)
- 连接复用
- 保活探测

### 配置

```rust
pub struct TcpConfig {
    pub keepalive: Option<Duration>,
    pub nodelay: bool,
    pub read_buffer: usize,
    pub write_buffer: usize,
}
```

### 使用方式

```toml
# 在节点配置中指定传输
[[nodes]]
name = "TCP 直连"
type = "vless"
server = "example.com"
port = 443
uuid = "xxx"
transport = "tcp"
```

## TLS 传输

**状态**: ✅ 完整实现

### 特性

- 标准 TLS 1.2/1.3
- SNI 伪造
- 证书验证控制
- ALPN 协议协商
- **Reality**: TLS 伪装目标站点

### TLS 配置

```rust
pub struct TlsConfig {
    pub server_name: String,        // SNI
    pub alpn: Vec<String>,          // ALPN 协议列表
    pub insecure: bool,             // 跳过证书验证
    pub rustls_config: Arc<RustlsConfig>,
}
```

### Reality 配置

```rust
pub struct RealityConfig {
    pub public_key: [u8; 32],      // X25519 公钥
    pub short_id: [u8; 8],          // 短 ID
    pub destination: String,        // 伪装目标 (如 microsoft.com)
}
```

### 使用示例

```toml
[[nodes]]
name = "VLESS Reality"
type = "vless"
server = "example.com"
port = 443
uuid = "xxx"
tls = true
tls_server_name = "www.microsoft.com"  # 伪装 SNI

[ nodes.reality ]
enabled = true
public_key = "base64-encoded-public-key"
short_id = "01234567"
destination = "www.microsoft.com:443"
```

### Reality 握手流程

```
Client                                          Server
  │                                               │
  │──── TLS ClientHello ─────────────────────────▶│
  │     SNI = www.microsoft.com                    │
  │     ALPN = h2                                  │
  │     内含 REALITY 加密的 dest                   │
  │                                               │
  │◀─── TLS ServerHello ──────────────────────────│
  │     (返回伪装目标的证书链)                      │
  │                                               │
  │──── Application Data ─────────────────────────▶│
  │     (VLESS 协议数据，TLS 加密)                 │
  │                                               │
```

## WebSocket 传输

**状态**: ✅ 完整实现

### 特性

- HTTP/1.1 Upgrade 机制
- WebSocket 帧封装
- 路径/主机自定义
- 二进制/文本帧支持
- 继承 TLS (wss://)

### WebSocket 配置

```rust
pub struct WsConfig {
    pub path: String,               // /path
    pub host: String,               // Host header
    pub headers: HashMap<String, String>,
    pub max_read_buffer: usize,
    pub max_write_buffer: usize,
}
```

### 使用示例

```toml
[[nodes]]
name = "WebSocket"
type = "vless"
server = "example.com"
port = 443
uuid = "xxx"
transport = "websocket"
ws_path = "/vless-ws"
ws_host = "example.com"
tls = true
```

### WebSocket 帧结构

```
┌─────────────────────────────────────┐
│ 0x81 (FIN + Text)                   │
│ 0x.. (Length)                       │
│ 0x.. (Mask key, if client→server)   │
│ Payload Data                         │
└─────────────────────────────────────┘
```

## HTTP Upgrade 传输

**状态**: ✅ 完整实现

### 特性

- HTTP 1.1 Upgrade
- 自定义协议头
- 路径/主机配置
- TLS 支持 (https)

### 配置

```rust
pub struct HttpUpgradeConfig {
    pub path: String,
    pub host: String,
    pub headers: HashMap<String, String>,
}
```

### 使用示例

```toml
[[nodes]]
name = "HTTP Upgrade"
type = "vless"
server = "example.com"
port = 443
uuid = "xxx"
transport = "httpupgrade"
httpupgrade_path = "/upgrade"
httpupgrade_host = "example.com"
tls = true
```

## gRPC 传输

**状态**: ⚠️ 部分实现（仅流式传输）

### 特性

- HTTP/2 传输
- gRPC 帧封装
- **Streaming only**: 不支持 unary RPC
- 双向流支持

### 限制

- 不支持简单的请求-响应模式
- 需要服务端支持 gRPC 流

### 配置

```rust
pub struct GrpcConfig {
    pub service_name: String,       // gRPC 服务名
    pub multi_mode: bool,           // 多路复用模式
}
```

### 使用示例

```toml
[[nodes]]
name = "gRPC"
type = "vless"
server = "example.com"
port = 443
uuid = "xxx"
transport = "grpc"
grpc_service_name = "grpc"
grpc_multi_mode = true
tls = true
```

## Meek 传输

**状态**: ✅ 完整实现（所有 tactics）

### Meek 特性

Meek 是一种流量混淆技术，通过以下 tactics 实现：

| Tactic | 说明 | 状态 |
|--------|------|------|
| `域前置` | 使用 CDN 域名隐藏真实目标 | ✅ |
| `云函数` | 伪装为云函数请求 | ✅ |
| `指向器` | 通过 HTTP 指向器跳转 | ✅ |
| `Obfuscated` | 混淆模式 | ✅ |

### 域前置 (Fronting)

```toml
[[nodes]]
name = "Meek 域前置"
type = "vless"
server = "example.com"
port = 443
uuid = "xxx"
transport = "meek"
meek_tactic = "fronting"
fronting_host = "cdn.cloudfront.net"  # 前置域名
fronting_path = "/"                     # 请求路径
destination = "example.com:443"         # 真实目标
tls = true
```

### 云函数 (Azure/AWS)

```toml
[[nodes]]
name = "Meek 云函数"
type = "vless"
server = "azureedge.net"  # 云函数入口
port = 443
uuid = "xxx"
transport = "meek"
meek_tactic = "azure"
function_url = "https://xxx.azurewebsites.net/api/func"
```

### 指向器 (Amnezia)

```toml
[[nodes]]
name = "Meek 指向器"
type = "vless"
server = "redirector.com"
port = 443
uuid = "xxx"
transport = "meek"
meek_tactic = "redirect"
redirect_url = "https://target.example.com"
```

### Meek 数据流

```
Client                           CDN/Cloud                    Server
  │                                │                           │
  │── HTTPS GET / ────────────────▶│                           │
  │    Host: cdn.cloudfront.net    │                           │
  │    转发到 /?url=target.com     │                           │
  │                                │                           │
  │                                │── HTTPS GET / ───────────▶│
  │                                │    Host: target.com        │
  │                                │                           │
  │◀─── TLS Response ──────────────│◀─── TLS Response ─────────│
  │                                │                           │
```

## 传输层选择指南

| 场景 | 推荐传输 | 说明 |
|------|----------|------|
| 理想网络 | TCP | 最低延迟 |
| 审查严格 | Reality / Meek | 深度伪装 |
| 高审查+CDN | Meek 域前置 | CDN 掩护 |
| 云函数环境 | Meek Azure/AWS | 云函数入口 |
| WebSocket 友好 | WebSocket | HTTP 伪装 |
| gRPC 环境 | gRPC | HTTP/2 流 |

## 传输层配置优先级

```
节点配置 > 协议默认值 > 全局默认值
```

### 全局传输配置

```toml
[transport]
default = "tcp"
fallback = ["tls", "websocket"]

[transport.tls]
alpn = ["h2", "http/1.1"]
insecure = false

[transport.websocket]
path = "/proxy"
```

## 性能对比

| 传输方式 | 延迟 | 吞吐量 | 抗审查 |
|----------|------|--------|--------|
| TCP | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐ |
| TLS | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ |
| Reality | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| WebSocket | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| Meek | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

## 故障排查

### TLS 握手失败

```bash
# 检查时间同步
timedatectl status

# 检查证书
openssl s_client -connect example.com:443 -servername www.microsoft.com
```

### Reality 连接问题

```bash
# 验证公钥
./dae validate --config config.toml

# 检查 short_id
openssl rand -hex 8
```

### WebSocket 连接受限

```bash
# 检查代理允许的 WebSocket 路径
curl -v --http1.1 https://example.com/path
```
