# TUIC 协议 - 功能描述

## 概述
TUIC 是一个基于 QUIC 的高性能代理协议，设计用于低延迟和高吞吐量。dae-rs 实现了 TUIC 协议支持。

## 流程图/数据流

### TUIC 协议架构
```
Client -> [QUIC Connection] -> [AUTH] -> [CONNECT] -> [UDP/TCP Relay] -> Target
```

### TUIC 命令类型
| Command | 值 | 说明 |
|---------|---|------|
| AUTH | 0x01 | 认证命令 |
| CONNECT | 0x02 | TCP 连接命令 |
| DISCONNECT | 0x03 | 断开连接 |
| HEARTBEAT | 0x04 | 心跳 |
| UDP_PACKET | 0x05 | UDP 数据包 |

### TUIC 握手流程
```
1. Client -> [AUTH: version, uuid, token] -> Server
2. Server -> [AUTH Response: success/fail]
3. Client <-> Server: 发送 CONNECT/HEARTBEAT/UDP_PACKET
```

### 认证请求格式
```
[1 byte version][32 bytes uuid][32 bytes token]
```

## 配置项

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `token` | String | - | 认证 token |
| `uuid` | String | - | 用户 UUID |
| `server_name` | String | "tuic.cloud" | TLS SNI |
| `congestion_control` | String | "bbr" | 拥塞控制算法 |
| `max_idle_timeout` | u32 | 15 | 最大空闲超时 (秒) |
| `max_udp_packet_size` | u32 | 1400 | 最大 UDP 包大小 |
| `flow_control_window` | u32 | 8388608 | 流控窗口 |

## 接口设计

### 核心 trait/struct
- `enum TuicCommandType`: 命令类型枚举
- `struct TuicAuthRequest`: 认证请求
- `struct TuicConnectRequest`: 连接请求
- `struct TuicHeartbeatRequest`: 心跳请求
- `enum TuicCommand`: 命令联合体
- `struct TuicSession`: 会话状态
- `struct TuicConfig`: TUIC 配置
- `enum TuicError`: 错误类型

### 公开方法
- `fn TuicServer::new(config)`: 创建 TUIC 服务器
- `fn TuicServer::listen(addr)`: 启动监听
- `fn TuicClient::new(config, server_addr)`: 创建 TUIC 客户端
- `fn TuicClient::connect() -> Result<TuicClientSession>`: 建立连接
- `fn TuicClient::connect_target(session, host, port)`: 连接到目标
- `fn TuicHandler::handle_inbound(ctx)`: 处理入站连接
- `fn TuicHandler::handle_outbound(ctx)`: 处理出站连接

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `AuthFailed` | Token 或 UUID 不匹配 | 拒绝连接 |
| `InvalidProtocol` | 协议格式错误 | 关闭连接 |
| `Timeout` | 心跳超时 | 清理会话 |
| `NotConnected` | 未连接 | 先建立连接 |

## 安全性考虑

1. **Token 认证**: 使用 token 验证客户端身份
2. **UUID 标识**: 每个用户有唯一 UUID
3. **QUIC 加密**: QUIC 协议内置 TLS 1.3 加密
4. **心跳保活**: 心跳机制保持连接活跃
5. **BBR 拥塞控制**: 使用 BBR 算法优化高延迟网络性能
