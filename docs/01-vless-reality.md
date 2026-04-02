# VLESS Protocol - 功能描述

## 概述
VLESS 协议是一个无状态的 VPN 协议，支持 TLS/XTLS 传输和 Reality 透明代理。dae-rs 实现了 VLESS client 和 server 两端，支持 Reality Vision (0x03 命令)。

## 流程图/数据流

### VLESS Client 流程
```
Client -> [VLESS Header: UUID+ADD+PORT+NET+TYPE+CMD] -> TLS/XTLS -> Remote Server -> Target
```

### VLESS Reality Vision 流程
```
1. Client: 生成 X25519 密钥对 (pubkey, privkey)
2. Client: 用 server pubkey 和 privkey 生成共享密钥 shared_secret
3. Client: HMAC-SHA256(request, "VLESS project") 生成 mask
4. Client: 构建 TLS ClientHello (SNI/ALPN/key_share)
5. Client: 发送 [3字节序列][加密请求][payload]
6. Server: 解密请求，解析 target address
7. Server: 连接 target 并 relay data
```

### 核心数据结构
- `VlessClientConfig`: 客户端配置 (listen_addr, server, timeout)
- `VlessServerConfig`: 服务端配置 (addr, port, uuid, tls, reality)
- `VlessRealityConfig`: Reality 配置 (public_key, short_id, spider_x)
- `VlessTargetAddress`: 目标地址解析 (IPv4/Domain/IPv6)

## 配置项

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `addr` | String | "127.0.0.1" | 服务器地址 |
| `port` | u16 | 443 | 服务器端口 |
| `uuid` | String | - | 用户 UUID (必需) |
| `tls.enabled` | bool | true | 启用 TLS |
| `tls.server_name` | Option<String> | None | SNI 主机名 |
| `tls.alpn` | Option<Vec<String>> | None | ALPN 协议列表 |
| `reality.enabled` | bool | false | 启用 Reality |
| `reality.public_key` | String | - | X25519 公钥 |
| `reality.short_id` | String | "" | Short ID (8字符) |
| `reality.spider_x` | String | "" | Spider 路径 |

## 接口设计

### 核心 trait/struct
- `struct VlessClientConfig`: VLESS 客户端配置
- `struct VlessServerConfig`: VLESS 服务端配置
- `struct VlessRealityConfig`: Reality 透明代理配置
- `struct VlessTargetAddress`: 目标地址枚举 (Ipv4/Domain/Ipv6)
- `trait VlessCommand`: 命令类型 (0x01 TCP, 0x02 UDP, 0x03 Vision)

### 公开方法
- `fn VlessHandler::new(config)`: 创建新的 VLESS handler
- `fn VlessHandler::handle(stream)`: 处理 VLESS 连接
- `fn VlessHandler::handle_udp(socket)`: 处理 UDP 连接
- `fn VlessServer::new(addr)`: 创建 VLESS 服务器
- `fn VlessServer::with_config(config)`: 使用自定义配置创建服务器
- `fn VlessServer::start()`: 启动服务器监听

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `InvalidHeader` | VLESS 头部格式错误 | 返回错误，关闭连接 |
| `AuthFailed` | UUID 验证失败 | 拒绝连接 |
| `Timeout` | 连接超时 | 重试或报错 |
| `InvalidRealityKey` | Reality 密钥无效 | 使用 fallback |

## 安全性考虑

1. **UUID 认证**: 每个用户使用唯一 UUID，防止未授权访问
2. **TLS 加密**: 默认启用 TLS 1.3，传输层加密
3. **Reality 混淆**: 使用 X25519 密钥交换，HMAC-SHA256 请求验证，躲避 DPI 检测
4. **Short ID**: 8字符短标识，支持多用户复用同一公钥
5. **Spider 路径**: 自定义 TLS 指纹生成路径，增强隐蔽性
