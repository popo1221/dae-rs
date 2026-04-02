# 传输层 - 功能描述

## 概述
传输层抽象提供统一的接口支持多种传输协议：TCP、WebSocket、TLS、gRPC。

## Transport Trait
```rust
#[async_trait]
pub trait Transport: Send + Sync + Debug {
    fn name(&self) -> &'static str;
    async fn dial(&self, addr: &str) -> Result<TcpStream>;
    async fn listen(&self, addr: &str) -> Result<tokio::net::TcpListener>;
    fn supports_udp(&self) -> bool { false }
    async fn local_addr(&self) -> Option<SocketAddr> { None }
}
```

## 传输类型

### TCP Transport
基础 TCP 传输，无加密。
```rust
pub struct TcpTransport;
```

### TLS Transport
TLS 加密传输，支持 Reality。
```rust
pub struct TlsTransport {
    pub config: TlsConfig,
}
pub struct TlsConfig {
    pub server_name: String,
    pub alpn: Vec<String>,
    pub verify_certificate: bool,
    // ...
}
pub struct RealityConfig {
    pub enabled: bool,
    pub public_key: String,
    pub short_id: String,
}
```

### WebSocket Transport
WebSocket 传输，支持 HTTP/HTTPS。
```rust
pub struct WsTransport;
pub struct WsConfig {
    pub path: String,
    pub host: Option<String>,
}
pub struct WsStream {
    // WebSocket stream wrapper
}
```

### gRPC Transport
gRPC 传输 (占位)。
```rust
pub struct GrpcTransport;
pub struct GrpcConfig {
    pub service_name: String,
}
```

## 配置项

### TlsConfig
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `server_name` | String | - | SNI 主机名 |
| `alpn` | Vec<String> | ["h2", "http/1.1"] | ALPN 协议 |
| `verify_certificate` | bool | true | 验证证书 |
| `min_version` | String | "1.3" | 最低 TLS 版本 |
| `max_version` | String | "1.3" | 最高 TLS 版本 |

### WsConfig
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `path` | String | "/" | WebSocket 路径 |
| `host` | Option<String> | None | Host 头 |
| `origin` | Option<String> | None | Origin 头 |

### RealityConfig
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | false | 启用 Reality |
| `public_key` | String | - | X25519 公钥 |
| `short_id` | String | "" | Short ID |

## 接口设计

### 公开方法
- `fn TcpTransport::new() -> Self`: 创建 TCP transport
- `fn TcpTransport::dial(addr) -> TcpStream`: 拨号
- `fn TcpTransport::listen(addr) -> TcpListener`: 监听
- `fn TlsTransport::new(config) -> Self`: 创建 TLS transport
- `fn TlsTransport::with_reality(config, reality) -> Self`: 创建带 Reality 的 TLS
- `fn WsTransport::new(config) -> Self`: 创建 WebSocket transport
- `fn WsStream::new(stream) -> Self`: 从 TCP 创建 WebSocket 流

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `TlsError` | TLS 握手失败 | 重试或降级 |
| `HandshakeError` | WebSocket 握手失败 | 检查 URL |
| `ConnectionRefused` | 连接被拒绝 | 检查网络 |

## 安全性考虑

1. **TLS 1.3**: 优先使用 TLS 1.3，支持前向保密
2. **证书验证**: 默认验证服务器证书，防止中间人攻击
3. **Reality**: 使用 X25519 密钥交换，无证书暴露
4. **ALPN**: 支持 h2 用于 HTTP/2
