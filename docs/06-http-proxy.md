# HTTP CONNECT 代理 - 功能描述

## 概述
HTTP CONNECT 代理支持建立 HTTP 隧道穿透防火墙，常用于 HTTPS 流量的透明代理。dae-rs 实现了完整的 HTTP CONNECT 代理服务器，支持 Basic 认证。

## 流程图/数据流

### HTTP CONNECT 隧道流程
```
Client -> CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n
Server -> HTTP/1.1 200 Connection Established\r\n\r\n
Client <-> Server <-> Target (双向复制)
```

### 请求处理流程
1. 读取 HTTP 请求行
2. 解析 Host:Port
3. 检查 Proxy-Authorization 头 (如果启用认证)
4. 连接到目标地址
5. 返回 200 Connection Established
6. 双向 relay 数据

### 支持的 HTTP 方法
| 方法 | 说明 | 支持 |
|------|------|------|
| CONNECT | 建立隧道 | ✅ |
| GET | HTTP 请求 | ✅ (直接 relay) |
| POST | HTTP 请求 | ✅ (直接 relay) |
| HEAD | HTTP 请求 | ✅ (直接 relay) |
| PUT/DELETE/OPTIONS/PATCH | 其他方法 | ✅ (直接 relay) |

## 配置项

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `listen_addr` | SocketAddr | 127.0.0.1:8080 | 监听地址 |
| `auth` | Option<(String, String)> | None | Basic 认证凭据 |
| `tcp_timeout_secs` | u64 | 60 | TCP 超时 |
| `allow_all` | bool | true | 允许所有地址 |

## 接口设计

### 核心 trait/struct
- `struct BasicAuth`: Basic 认证凭据
  - `fn new(username, password)`: 创建凭据
  - `fn from_header(value)`: 从 Proxy-Authorization 头解析
  - `fn matches(username, password) -> bool`: 验证凭据
- `struct HttpConnectRequest`: CONNECT 请求
- `struct HttpProxyHandlerConfig`: Handler 配置
- `struct HttpProxyHandler`: HTTP 代理处理器

### 公开方法
- `fn HttpProxyHandler::new_no_auth()`: 创建无认证 handler
- `fn HttpProxyHandler::new_with_auth(username, password)`: 创建带认证 handler
- `fn HttpProxyHandler::handle(stream)`: 处理连接
- `fn HttpProxyServer::new(addr)`: 创建服务器
- `fn HttpProxyServer::with_handler(addr, handler)`: 使用自定义 handler 创建
- `fn BasicAuth::from_header(header)`: 解析认证头

## HTTP 响应码

| 状态码 | 含义 | 场景 |
|--------|------|------|
| 200 | Connection Established | 隧道建立成功 |
| 407 | Proxy Authentication Required | 需要认证 |
| 502 | Bad Gateway | 无法连接到目标 |

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `PermissionDenied` | 认证失败 | 返回 407 |
| `InvalidInput` | 无效 CONNECT 请求 | 返回 400 |
| `HostUnreachable` | DNS 解析失败 | 返回 502 |
| `TimedOut` | 连接超时 | 返回 504 |

## 安全性考虑

1. **Basic 认证**: 使用 base64 编码的用户名:密码 (可被轻易解码，仅适用 HTTPS)
2. **CONNECT 限制**: 可配置允许/禁止的域名
3. **日志泄露**: 需注意 HTTP 方法和 Host 头可能泄露访问目标
4. **端到端加密**: CONNECT 只建立隧道，TLS 端到端加密由应用层处理
