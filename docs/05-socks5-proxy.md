# SOCKS5 代理 - 功能描述

## 概述
SOCKS5 是 RFC 1928 定义的 SOCKS 协议，支持 TCP/UDP、IPv4/IPv6/Domain 地址、多种认证方式。dae-rs 实现了完整的 SOCKS5 服务器。

## 流程图/数据流

### SOCKS5 三阶段握手
```
Phase 1 (Greeting): Client -> [VER=0x05, NMETHODS, METHODS] -> Server -> [VER=0x05, METHOD]
Phase 2 (Auth):     Client -> [USERNAME_LEN, USERNAME, PASSWORD_LEN, PASSWORD] -> Server
Phase 3 (Request):  Client -> [VER=0x05, CMD, RSV=0x00, ATYP, DST.ADDR, DST.PORT]
                    Server -> [VER=0x05, REP, RSV=0x00, ATYP, BND.ADDR, BND.PORT]
```

### 支持的认证方式
| Method | 值 | 说明 |
|--------|---|------|
| NO_AUTH | 0x00 | 无需认证 |
| USERNAME_PASSWORD | 0x02 | 用户名/密码认证 (RFC 1929) |
| NO_ACCEPTABLE | 0xFF | 无可用认证方式 |

### 支持的命令
| CMD | 值 | 说明 |
|-----|---|------|
| CONNECT | 0x01 | 建立 TCP 连接 |
| BIND | 0x02 | 绑定端口 (少用) |
| UDP_ASSOCIATE | 0x03 | UDP 中继 |

### 地址类型
| ATYP | 值 | 格式 |
|------|---|------|
| IPv4 | 0x01 | 4字节 IP + 2字节端口 |
| Domain | 0x03 | 1字节长度 + 域名 + 2字节端口 |
| IPv6 | 0x04 | 16字节 IP + 2字节端口 |

## 配置项

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `listen_addr` | SocketAddr | 127.0.0.1:1080 | 监听地址 |
| `auth_handler` | Arc<dyn AuthHandler> | NoAuth | 认证处理器 |
| `tcp_timeout_secs` | u64 | 60 | TCP 超时 |

## 接口设计

### 核心 trait/struct
- `trait AuthHandler`: 认证处理器 trait
  - `fn requires_auth(&self) -> bool`
  - `fn validate_credentials(&self, username, password) -> bool`
- `struct NoAuthHandler`: 无认证处理器
- `struct UsernamePasswordHandler`: 用户名/密码认证
- `struct CombinedAuthHandler`: 组合认证处理器
- `enum Socks5Address`: 地址 (IPv4/IPv6/Domain)
- `enum Socks5Reply`: 回复码
- `enum Socks5Command`: 命令类型

### 公开方法
- `fn Socks5Handler::new_no_auth()`: 创建无认证 handler
- `fn Socks5Handler::new_with_auth(users)`: 创建带认证 handler
- `fn Socks5Handler::handle(stream)`: 处理连接
- `fn Socks5Server::new(addr)`: 创建服务器
- `fn Socks5Server::with_handler(addr, handler)`: 使用自定义 handler 创建
- `fn Socks5Address::parse_from(reader)`: 异步解析地址
- `fn Socks5Address::write_to(writer)`: 异步写入地址

## 错误处理

| Reply Code | 含义 | 场景 |
|------------|------|------|
| 0x00 | SUCCESS | 连接成功 |
| 0x01 | GENERAL_FAILURE | 一般失败 |
| 0x02 | CONNECTION_NOT_ALLOWED | 规则禁止 |
| 0x03 | NETWORK_UNREACHABLE | 网络不可达 |
| 0x04 | HOST_UNREACHABLE | 主机不可达 |
| 0x05 | CONNECTION_REFUSED | 连接被拒绝 |
| 0x06 | TTL_EXPIRED | TTL 超时 |
| 0x07 | COMMAND_NOT_SUPPORTED | 命令不支持 |
| 0x08 | ADDRESS_TYPE_NOT_SUPPORTED | 地址类型不支持 |

## 安全性考虑

1. **认证**: 支持用户名/密码认证保护代理访问
2. **DNS 解析**: 域名地址在服务器端解析，防止 DNS 泄露
3. **UDP Associate**: 支持 UDP 中继，需维护 TCP 保持连接
4. **权限控制**: 可通过 AuthHandler 实现细粒度权限控制
