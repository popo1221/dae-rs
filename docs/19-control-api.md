# Control Socket API - 功能描述

## 概述
Control Socket 提供 Unix Domain Socket 方式的运行时管理接口，支持状态查询、配置热重载、节点测试等功能。

## Socket 路径
默认: `/var/run/dae/control.sock`

## 命令列表

### status
获取代理运行状态。
```
$ echo "status" | nc -U /var/run/dae/control.sock
{"running":true,"uptime_secs":3600,"tcp_connections":5,"udp_sessions":3,"rules_loaded":true,"rule_count":42,"nodes_configured":3}
```

### stats
获取流量统计。
```
$ echo "stats" | nc -U /var/run/dae/control.sock
{"total_connections":1234,"total_bytes_in":567890123,"total_bytes_out":987654321,...}
```

### reload
热重载配置文件。
```
$ echo "reload" | nc -U /var/run/dae/control.sock
Configuration reload initiated
```

### test
测试特定节点连通性。
```
$ echo "test:my-trojan-node" | nc -U /var/run/dae/control.sock
{"node_name":"my-trojan-node","success":true,"latency_ms":42,"error":null}
```

### shutdown
优雅关闭代理。
```
$ echo "shutdown" | nc -U /var/run/dae/control.sock
Shutdown initiated
```

### version
查看版本。
```
$ echo "version" | nc -U /var/run/dae/control.sock
dae-rs 0.1.0
```

### help
查看帮助。
```
$ echo "help" | nc -U /var/run/dae/control.sock
Available commands:
  status         Show proxy status
  stats          Show statistics
  reload         Hot reload configuration
  shutdown       Shutdown the proxy gracefully
  test <node>    Test connectivity to a node
  version        Show version information
  help           Show this help message
```

## 数据结构

### ProxyStatus
```rust
pub struct ProxyStatus {
    pub running: bool,
    pub uptime_secs: u64,
    pub tcp_connections: usize,
    pub udp_sessions: usize,
    pub rules_loaded: bool,
    pub rule_count: usize,
    pub nodes_configured: usize,
}
```

### ProxyStats
```rust
pub struct ProxyStats {
    pub total_connections: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub active_tcp_connections: usize,
    pub active_udp_sessions: usize,
    pub rules_hit: u64,
    pub nodes_tested: usize,
}
```

### NodeTestResult
```rust
pub struct NodeTestResult {
    pub node_name: String,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}
```

## 接口设计

### ControlServer
```rust
pub struct ControlServer {
    socket_path: String,
    state: Arc<ControlState>,
}

impl ControlServer {
    pub fn new(socket_path: &str) -> Self
    pub fn state(&self) -> Arc<ControlState>
    pub async fn start(&self) -> Result<()>
}
```

### ControlState
```rust
pub struct ControlState {
    pub running: Arc<RwLock<bool>>,
    pub start_time: SystemTime,
    pub stats: ProxyStats,
}

impl ControlState {
    pub fn new() -> Self
    pub async fn set_running(&self, running: bool)
    pub async fn is_running(&self) -> bool
    pub fn uptime_secs(&self) -> u64
    pub fn get_status(&self, ...) -> ProxyStatus
    pub fn get_stats(&self) -> ProxyStats
}
```

## 客户端工具

### connect_and_send
```rust
pub async fn connect_and_send(socket_path: &str, command: &str) -> Result<String>
```

### connect_and_get_status
```rust
pub async fn connect_and_get_status(socket_path: &str) -> Result<ControlResponse>
```

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `ConnectionRefused` | Socket 不存在 | 检查 dae 是否运行 |
| `SendError` | 发送失败 | 检查权限 |
| `RecvError` | 接收失败 | Socket 已关闭 |

## 安全性考虑

1. **Unix Socket 权限**: Socket 文件设置 0666 (所有者/组/其他可读写)
2. **本地访问**: 仅本地进程可访问，需 shell 权限
3. **JSON 响应**: 便于程序化解析
4. **热重载**: reload 命令不中断现有连接
