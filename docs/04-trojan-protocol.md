# Trojan 协议 - 功能描述

## 概述
Trojan 是一个模拟 HTTPS 流量的代理协议，dae-rs 实现了 Trojan 客户端，支持 TLS 传输和 Trojan-Go WebSocket 扩展。

## 流程图/数据流

### Trojan 标准协议流程
```
Client -> [Trojan Header][TLS ClientHello] -> [HTTPS] -> Server -> Target
```

### Trojan Header 格式
```
[8字节: 连接 CRLF69xO][4字节: 目标长度][目标 (host:port)][CRLF][Payload]
```

### Trojan-Go WebSocket 流程
```
Client -> [WebSocket Handshake with Trojan token] -> [WS Frame] -> Server
```

### 数据流
1. 客户端发送 Trojan 握手头
2. 后续使用 TLS 传输真正的请求
3. 服务器解析目标地址
4. 建立到目标的连接并 relay

## 配置项

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `addr` | String | - | 服务器地址 |
| `port` | u16 | 443 | 服务器端口 |
| `password` | String | - | Trojan 密码 |
| `tls.enabled` | bool | true | 启用 TLS |
| `tls.version` | String | "1.3" | TLS 版本 |
| `tls.server_name` | Option<String> | None | SNI 主机名 |
| `ws.enabled` | bool | false | 启用 WebSocket |
| `ws.path` | String | "/" | WebSocket 路径 |
| `ws.host` | Option<String> | None | WebSocket Host 头 |

## 接口设计

### 核心 trait/struct
- `struct TrojanServerConfig`: 服务器配置
- `struct TrojanClientConfig`: 客户端配置
- `struct TrojanTlsConfig`: TLS 配置
- `enum TrojanCommand`: 命令类型
- `enum TrojanAddressType`: 地址类型

### 公开方法
- `fn TrojanHandler::new(config)`: 创建 handler
- `fn TrojanHandler::handle(stream)`: 处理连接
- `fn TrojanServer::with_config(config)`: 创建服务器
- `fn TrojanServer::with_backends(config, backends)`: 创建多后端服务器
- `fn TrojanGoWsHandler::new(config)`: 创建 WS handler
- `fn TrojanGoWsStream::new(stream)`: 创建 WS 流

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `AuthFailed` | 密码验证失败 | 关闭连接 |
| `InvalidHeader` | Trojan 头格式错误 | 关闭连接 |
| `TlsError` | TLS 握手失败 | 重试或 fallback |

## 安全性考虑

1. **TLS 伪装**: Trojan 流量与正常 HTTPS 无法区分
2. **密码认证**: 使用密码验证客户端身份
3. **WebSocket 混淆**: Trojan-Go 支持 WebSocket 进一步混淆
4. **SNI 伪造**: Reality 模式支持伪造 SNI 增强隐蔽性
