# Proxy 核心 - 功能描述

## 概述
dae-proxy 是 dae-rs 的核心代理模块，协调 TCP/UDP 代理、eBPF Maps、连接池和各种协议处理器。

## 模块结构

### 核心组件
```
dae-proxy
├── protocol/          # 协议抽象层
│   ├── handler.rs     # ProtocolHandler trait
│   └── mod.rs        # ProtocolType 枚举
├── connection.rs     # 单个连接状态管理
├── connection_pool.rs # 连接池管理
├── ebpf_integration.rs # eBPF Maps 集成
├── proxy.rs         # 主 Proxy 协调器
├── protocol_dispatcher.rs # 协议检测分发
├── rules/           # 规则定义
├── tcp.rs           # TCP 代理
├── udp.rs           # UDP 代理
├── vless.rs         # VLESS 协议
├── vmess.rs         # VMess 协议
├── shadowsocks.rs   # Shadowsocks 协议
├── trojan_protocol/ # Trojan 协议
├── socks5.rs        # SOCKS5 协议
├── http_proxy.rs    # HTTP CONNECT 协议
├── dns/             # DNS 系统
├── nat/             # NAT 实现
├── tuic/            # TUIC 协议
├── hysteria2/       # Hysteria2 协议
├── juicity/         # Juicity 协议
├── anytls.rs        # AnyTLS
└── control.rs       # 控制接口
```

## 流程图/数据流

### Proxy 启动流程
```
Proxy::new(config)
    |
    +---> EbpfMaps::new()
    |         +---> SessionMapHandle
    |         +---> RoutingMapHandle
    |         +---> StatsMapHandle
    |
    +---> new_connection_pool()
    |
    +---> TcpProxy::new()
    |
    +---> UdpProxy::new()
    |
    +---> CombinedProxyServer::new()
    |
    +---> ShadowsocksServer::new() (if configured)
    |
    +---> VlessServer::new() (if configured)
    |
    +---> VmessServer::new() (if configured)
    |
    +---> TrojanServer::new() (if configured)
```

### Proxy 启动后的任务
```
Proxy::start()
    |
    +---> tcp_proxy.start()           # TCP 代理任务
    +---> udp_proxy.start()           # UDP 代理任务
    +---> connection_pool.cleanup()   # 连接池清理任务
    +---> combined_server.start()    # SOCKS5/HTTP 服务器
    +---> shadowsocks_server.start()  # Shadowsocks 服务器
    +---> vless_server.start()       # VLESS 服务器
    +---> vmess_server.start()        # VMess 服务器
    +---> trojan_server.start()       # Trojan 服务器
```

## 连接池 (Connection Pool)

### ConnectionKey 结构
```rust
pub struct ConnectionKey {
    pub src_ip: u32,      // 源 IP (网络字节序)
    pub dst_ip: u32,      // 目标 IP
    pub src_port: u16,   // 源端口
    pub dst_port: u16,   // 目标端口
    pub proto: u8,        // 协议 (6=TCP, 17=UDP)
}
```

### 连接池方法
```rust
impl ConnectionPool {
    fn get_or_create(&self, key: ConnectionKey) -> (SharedConnection, bool)
    fn remove(&self, key: &ConnectionKey) -> bool
    fn get(&self, key: &ConnectionKey) -> Option<SharedConnection>
    fn cleanup_expired(&self) -> usize
    fn update_state(&self, key: &ConnectionKey, state: ConnectionState)
    fn close_all(&self)
}
```

## 配置项

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `tcp.listen_addr` | SocketAddr | 127.0.0.1:1080 | TCP 监听 |
| `udp.listen_addr` | SocketAddr | 127.0.0.1:1080 | UDP 监听 |
| `pool.tcp_timeout` | Duration | 60s | TCP 超时 |
| `pool.udp_timeout` | Duration | 30s | UDP 超时 |
| `pool.tcp_keepalive` | Duration | 10s | TCP keepalive |
| `ebpf.enabled` | bool | true | 启用 eBPF |
| `ebpf.session_map_size` | u32 | 65536 | 会话 Map |
| `ebpf.routing_map_size` | u32 | 16384 | 路由 Map |

## 接口设计

### ProtocolHandler trait
```rust
#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    fn name(&self) -> &'static str;
    async fn handle_inbound(&self, ctx: &mut Context) -> Result<()>;
    async fn handle_outbound(&self, ctx: &mut Context) -> Result<()>;
}
```

### 公开方法
- `fn Proxy::new(config) -> Self`: 创建代理实例
- `fn Proxy::start() -> Result<()>`: 启动代理
- `fn Proxy::stop() -> Future`: 停止代理
- `fn Proxy::is_running() -> bool`: 检查运行状态
- `fn new_connection_pool() -> SharedConnectionPool`: 创建连接池

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `TcpError` | TCP 代理错误 | 记录日志，尝试恢复 |
| `UdpError` | UDP 代理错误 | 记录日志，尝试恢复 |
| `EbpfError` | eBPF 操作错误 | 使用纯用户态 fallback |
| `ConfigError` | 配置错误 | 启动失败 |
| `ShutdownError` | 关闭错误 | 强制关闭 |

## 安全性考虑

1. **连接池超时**: 自动过期长时间空闲的连接
2. **优雅关闭**: stop() 等待所有任务完成
3. **eBPF 沙箱**: eBPF 程序运行在受限内核环境
4. **错误隔离**: 各协议处理器独立，错误不扩散
