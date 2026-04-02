# VMess 协议 - 功能描述

## 概述
VMess 是 V2Ray 开发的无状态 VPN 协议，支持 VMess-AEAD-2022。dae-rs 实现了 VMess 客户端，支持多种加密方式 (AES-128-CFB/GCM, ChaCha20-Poly1305)。

## 流程图/数据流

### VMess AEAD-2022 协议流程
```
Client -> [4字节长度][加密Header][payload] -> Remote -> Target
```

### VMess Header 格式
```
[4 bytes: 加密数据长度][加密Header][Target Address][Data]
```

### 加密方式
| 方式 | AEAD | 推荐 |
|------|------|------|
| aes-128-cfb | ❌ | ❌ (已废弃) |
| aes-128-gcm | ❌ | ❌ |
| chacha20-poly1305 | ❌ | ❌ |
| aes-128-gcm-aead | ✅ | ✅ |
| chacha20-poly1305-aead | ✅ | ✅ |

### 数据流
1. **Header 加密**: 使用 AES-128-GCM 或 ChaCha20-Poly1305 AEAD
2. **地址解析**: 解析 ATYP (0x01 IPv4, 0x02 Domain, 0x03 IPv6)
3. **连接 Relay**: 双向复制 client <-> remote

## 配置项

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `addr` | String | "127.0.0.1" | 服务器地址 |
| `port` | u16 | 10086 | 服务器端口 |
| `user_id` | String | - | 用户 ID (UUID) |
| `security` | VmessSecurity | Aes128GcmAead | 加密方式 |
| `enable_aead` | bool | true | 启用 AEAD-2022 |
| `tcp_timeout` | Duration | 60s | TCP 超时 |
| `udp_timeout` | Duration | 30s | UDP 超时 |

## 接口设计

### 核心 trait/struct
- `enum VmessSecurity`: 加密类型枚举
- `enum VmessAddressType`: 地址类型 (Ipv4/Domain/Ipv6)
- `enum VmessCommand`: 命令类型 (Tcp=0x01, Udp=0x02)
- `struct VmessServerConfig`: 服务端配置
- `struct VmessClientConfig`: 客户端配置
- `enum VmessTargetAddress`: 目标地址

### 公开方法
- `fn VmessHandler::new(config)`: 创建 VMess handler
- `fn VmessHandler::handle(stream)`: 处理 TCP 连接
- `fn VmessHandler::handle_udp(socket)`: 处理 UDP 会话
- `fn VmessServer::with_config(config)`: 创建服务器
- `fn VmessServer::start()`: 启动服务器
- `fn VmessSecurity::from_str(s)`: 从字符串解析加密类型
- `fn VmessTargetAddress::parse_from_bytes(payload)`: 解析目标地址

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `InvalidData` | Header 解析失败 | 关闭连接 |
| `TimedOut` | 连接超时 | 重试 |
| `ConnectionRefused` | 远程拒绝 | 检查网络 |

## 安全性考虑

1. **VMess-AEAD-2022**: 2022 年推出的 AEAD 加密方案，解决原版 VMess 头部可被主动探测的问题
2. **时间戳验证**: VMess 使用时间戳防止重放攻击
3. **Auth Key**: 基于 UUID 派生的认证密钥
4. **动态端口**: 支持动态端口分配增强安全性
5. **Mux多路复用**: 支持连接复用减少握手开销
