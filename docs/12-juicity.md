# Juicity 协议 - 功能描述

## 概述
Juicity 是一个基于 UDP 的高性能代理协议，设计用于低延迟和高吞吐量。dae-rs 实现了 Juicity 协议支持。

## 流程图/数据流

### Juicity 协议架构
```
Client -> [UDP Socket] -> [Magic=0xCAFE][Version][Token][Congestion] -> Server
Client <-> [Juicity Frames: Open/Send/Close/Ping/Pong] <-> Server
```

### Juicity 握手 (TCP)
```
1. Client -> [0xCAFE][1 byte version][32 bytes token][1 byte congestion] -> Server
2. Server -> [0xCAFE][Version][Success] -> Client
```

### Juicity 帧类型
| Command | 值 | 说明 |
|---------|---|------|
| Open | 0x00 | 打开连接 |
| Send | 0x01 | 发送数据 |
| Close | 0x02 | 关闭连接 |
| Ping | 0x03 | Ping (心跳) |
| Pong | 0x04 | Pong (心跳响应) |

### 拥塞控制算法
| 算法 | 值 | 说明 |
|------|---|------|
| BBR | 0x01 | BBR 拥塞控制 (推荐) |
| CUBIC | 0x02 | CUBIC 拥塞控制 |
| Reno | 0x03 | Reno 拥塞控制 |

## 配置项

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `token` | String | - | 认证 token |
| `server_name` | String | "" | TLS SNI |
| `server_addr` | String | "127.0.0.1" | 服务器地址 |
| `server_port` | u16 | 443 | 服务器端口 |
| `congestion_control` | CongestionControl | Bbr | 拥塞控制算法 |
| `timeout` | Duration | 30s | 超时时间 |

## 接口设计

### 核心 trait/struct
- `enum CongestionControl`: 拥塞控制枚举
- `struct JuicityConfig`: Juicity 配置
- `enum JuicityError`: 错误类型
- `struct JuicityFrame`: Juicity 帧
- `enum JuicityCommand`: 命令枚举
- `struct JuicityConnection`: 连接句柄
- `trait ProtocolHandler`: 协议处理器接口

### 公开方法
- `fn JuicityHandler::new(config)`: 创建 handler
- `fn JuicityHandler::handle_tcp(stream)`: 处理 TCP 连接
- `fn JuicityHandler::handle_udp(socket)`: 处理 UDP 会话
- `fn JuicityClient::new(config)`: 创建客户端
- `fn JuicityClient::connect(target) -> Result<JuicityConnection>`: 建立连接
- `fn JuicityConnection::send(data)`: 发送数据
- `fn JuicityConnection::recv(buf)`: 接收数据
- `fn JuicityConnection::close()`: 关闭连接
- `fn CongestionControl::from_str(s)`: 从字符串解析

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `InvalidHeader` | Magic number 不匹配 | 关闭连接 |
| `InvalidToken` | Token 验证失败 | 拒绝连接 |
| `ConnectionNotFound` | 连接不存在 | 创建新连接 |
| `Timeout` | 操作超时 | 重试 |
| `Protocol` | 协议错误 | 关闭连接 |

## 安全性考虑

1. **Token 认证**: 使用 32 字节 token 验证客户端
2. **Magic Number**: 0xCAFE 魔数用于快速协议识别
3. **BBR 拥塞控制**: BBR 算法在高丢包网络表现更好
4. **UDP 校验**: UDP 协议本身校验数据完整性
