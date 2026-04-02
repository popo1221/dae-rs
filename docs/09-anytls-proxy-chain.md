# AnyTLS 和代理链 - 功能描述

## 概述
AnyTLS 是一个使用 TLS 作为传输层的代理协议，提供双向证书认证。dae-rs 实现了 AnyTLS 客户端，支持代理链多跳路由。

## AnyTLS 协议

### 协议特点
- 使用 TLS 1.3 作为传输
- 支持客户端证书认证
- 自定义协议头封装

### AnyTLS 握手流程
```
Client -> [ClientHello + AnyTLS Extension] -> Server
Client <- [ServerHello + Certificate] <- Server
Client -> [CertificateVerify + Finished] -> Server
Client <-> [Encrypted Data] <-> Server
```

## 代理链 (Proxy Chain)

### 代理链概念
代理链允许多个代理服务器串联，形成多跳路由：
```
Client -> Proxy1 -> Proxy2 -> Proxy3 -> Target
```

### dae-rs 支持的代理链
```
[SOCKS5/HTTP] -> [Trojan/VLESS/VMess/Shadowsocks] -> [TLS] -> [AnyTLS] -> Target
```

### 代理链配置
```toml
[[proxy_chain]]
type = "socks5"
addr = "127.0.0.1:1080"

[[proxy_chain]]
type = "trojan"
addr = "example.com:443"
password = "xxx"
```

## 配置项

### AnyTlsClientConfig
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `server_addr` | String | "127.0.0.1" | 服务器地址 |
| `server_port` | u16 | 443 | 服务器端口 |
| `client_cert` | String | - | 客户端证书 (PEM) |
| `client_key` | String | - | 客户端私钥 |
| `ca_cert` | Option<String> | None | CA 证书 |
| `tls_version` | String | "1.3" | TLS 版本 |

### AnyTlsServerConfig
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `listen_addr` | String | "0.0.0.0" | 监听地址 |
| `listen_port` | u16 | 443 | 监听端口 |
| `server_cert` | String | - | 服务器证书 |
| `server_key` | String | - | 服务器私钥 |
| `client_ca` | Option<String> | None | 客户端 CA |

## 接口设计

### 核心 trait/struct
- `struct AnyTlsClientConfig`: AnyTLS 客户端配置
- `struct AnyTlsServerConfig`: AnyTLS 服务端配置
- `struct AnyTlsHandler`: AnyTLS 处理器

### 公开方法
- `fn AnyTlsHandler::new(config)`: 创建 handler
- `fn AnyTlsHandler::connect() -> TcpStream`: 连接到服务器
- `fn AnyTlsHandler::handshake(stream)`: 执行握手

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `TlsError` | TLS 握手失败 | 重试或降级 |
| `AuthFailed` | 证书认证失败 | 检查证书配置 |

## 安全性考虑

1. **TLS 1.3**: 使用最新 TLS 版本，提供前向保密
2. **双向认证**: 支持客户端证书和服务端证书双向认证
3. **代理链加密**: 每跳使用 TLS 加密，防止中间人攻击
4. **证书固定**: 可配置 CA 证书固定，增强安全性
