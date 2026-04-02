# Shadowsocks AEAD 协议 - 功能描述

## 概述
Shadowsocks 是一个基于 SOCKS5 的代理协议，dae-rs 实现了 AEAD 加密方式 (chacha20-ietf-poly1305, aes-256-gcm, aes-128-gcm)，支持 OTA (One-Time Auth) 兼容模式。

## 流程图/数据流

### Shadowsocks AEAD 数据流
```
Client -> [Length Prefix (2B)][Nonce][Encrypted Header+Payload][Tag] -> Server -> Target
```

### AEAD Header 格式
```
[ATYP(1)][Target Addr][Port(2)] + [Payload]
```

### 地址类型
| ATYP | 类型 | 格式 |
|------|------|------|
| 0x01 | IPv4 | 4字节 IP + 2字节端口 |
| 0x02 | Domain | 1字节长度 + 域名 + 2字节端口 |
| 0x03 | IPv6 | 16字节 IP + 2字节端口 |

### 支持的加密方式
| 方式 | 密钥长度 | Nonce 长度 | 推荐 |
|------|----------|------------|------|
| chacha20-ietf-poly1305 | 32B | 12B | ✅ |
| aes-256-gcm | 32B | 12B | ✅ |
| aes-128-gcm | 16B | 12B | ✅ |

### 数据流步骤
1. 读取 1 字节 ATYP
2. 读取 2 字节长度前缀
3. 读取 AEAD 加密 payload
4. 解密并解析目标地址
5. 连接目标并 relay

## 配置项

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `addr` | String | "127.0.0.1" | 服务器地址 |
| `port` | u16 | 8388 | 服务器端口 |
| `method` | SsCipherType | Chacha20IetfPoly1305 | 加密方式 |
| `password` | String | - | 密码/密钥 |
| `ota` | bool | false | 启用 OTA |
| `tcp_timeout` | Duration | 60s | TCP 超时 |
| `udp_timeout` | Duration | 30s | UDP 超时 |

## 接口设计

### 核心 trait/struct
- `enum SsCipherType`: 加密类型 (Chacha20IetfPoly1305, Aes256Gcm, Aes128Gcm)
- `struct SsServerConfig`: 服务器配置
- `struct SsClientConfig`: 客户端配置
- `enum TargetAddress`: 目标地址 (Ip/Domain)

### 公开方法
- `fn ShadowsocksHandler::new(config)`: 创建 handler
- `fn ShadowsocksHandler::handle(stream)`: 处理 TCP 连接
- `fn ShadowsocksHandler::handle_udp(socket)`: 处理 UDP 会话
- `fn ShadowsocksServer::with_config(config)`: 创建服务器
- `fn ShadowsocksServer::start()`: 启动服务器
- `fn SsCipherType::from_str(s)`: 解析加密类型

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `InvalidData` | AEAD payload 解析失败 | 关闭连接 |
| `TimedOut` | 连接超时 | 重试 |
| `AuthFailed` | OTA 验证失败 | 拒绝连接 |

## 安全性考虑

1. **AEAD 加密**: 使用 ChaCha20-Poly1305 或 AES-GCM，提供认证加密
2. **OTA 兼容**: One-Time Auth 防止重放攻击
3. **插件支持**: 支持 simple-obfs 和 v2ray-plugin 混淆
4. **UDP 完整性**: UDP 包使用独立 nonce 防止重排序攻击
