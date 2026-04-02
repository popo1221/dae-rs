# Hysteria2 协议 - 功能描述

## 概述
Hysteria2 是一个基于 QUIC 的高性能代理协议，支持带宽感知拥塞控制和混淆。dae-rs 实现了 Hysteria2 协议支持。

## 流程图/数据流

### Hysteria2 协议架构
```
Client -> [QUIC Stream] -> [ClientHello + Auth] -> [UDP Relay] -> Target
```

### Hysteria2 帧类型
| Frame Type | 值 | 说明 |
|------------|---|------|
| ClientHello | 0x01 | 客户端问候 (含密码) |
| ServerHello | 0x02 | 服务端应答 |
| UdpPacket | 0x03 | UDP 数据包 |
| Heartbeat | 0x04 | 心跳 |
| Disconnect | 0x05 | 断开连接 |

### ClientHello 格式
```
[1 byte: FrameType=0x01][1 byte: Version=2][1 byte: PasswordLen][Password][LocalAddr?]
```

### 地址类型
| ATYP | 值 | 格式 |
|------|---|------|
| 0x01 | IPv4 | 4字节 IP + 2字节端口 |
| 0x02 | Domain | 1字节长度 + 域名 + 2字节端口 |
| 0x03 | IPv6 | 16字节 IP + 2字节端口 |

## 配置项

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `password` | String | - | 认证密码 |
| `server_name` | String | "" | TLS SNI |
| `obfuscate_password` | Option<String> | None | 混淆密码 (DPI 绕过) |
| `listen_addr` | SocketAddr | 127.0.0.1:8123 | 监听地址 |
| `bandwidth_limit` | u64 | 0 | 带宽限制 (0=无限制) |
| `idle_timeout` | Duration | 30s | 空闲超时 |
| `udp_enabled` | bool | true | 启用 UDP |

## 接口设计

### 核心 trait/struct
- `enum Hysteria2FrameType`: 帧类型枚举
- `enum Hysteria2Address`: 地址枚举
- `struct Hysteria2ClientHello`: 客户端问候
- `struct Hysteria2ServerHello`: 服务端应答
- `struct Hysteria2Config`: Hysteria2 配置
- `enum Hysteria2Error`: 错误类型

### 公开方法
- `fn Hysteria2Handler::new(config)`: 创建 handler
- `fn Hysteria2Handler::handle(stream)`: 处理连接
- `fn Hysteria2Server::new(config)`: 创建服务器
- `fn Hysteria2Server::serve()`: 启动服务
- `fn Hysteria2Address::parse(data)`: 解析地址
- `fn Hysteria2Address::encode()`: 编码地址

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `AuthFailed` | 密码不匹配 | 拒绝连接 |
| `Protocol` | 协议格式错误 | 关闭连接 |
| `Quic` | QUIC 错误 | 重试 |

## 安全性考虑

1. **密码认证**: 使用共享密码验证客户端
2. **混淆密码**: 额外的混淆层用于绕过 DPI
3. **QUIC 加密**: 使用 QUIC 内置加密
4. **带宽感知**: 带宽限制防止滥用
