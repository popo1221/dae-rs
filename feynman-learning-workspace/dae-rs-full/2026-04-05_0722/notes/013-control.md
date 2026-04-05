# 013 - control.rs：Unix Domain Socket 控制接口

## 一句话总结（10岁版本）

> dae-rs 运行起来后，怎么告诉它"重启"、"看状态"或"关掉"？**control.rs** 就是那个遥控器 —— 它通过一个特殊的"电话"（Unix 插槽）来接收管理员的命令，而不需要直接连上 dae-rs 的内部。

---

## 简化法则自检（6项检查）

| # | 检查项 | 结论 |
|---|--------|------|
| 1 | **有没有正确的抽象层次？** | ✅ 暴露了 Command/Response 枚举，对外只有语义化接口 |
| 2 | **有没有不必要的复杂度？** | ✅ 命令解析直接字符串 split，不拐弯抹角 |
| 3 | **错误处理是否合理？** | ⚠️ placeholder 函数（rules_loaded/node_count）返回硬编码值，真实实现会从外部状态读取 |
| 4 | **是否遵循单一职责？** | ✅ ControlServer 管监听，handle_connection 管单次会话，process_command 管命令分发 |
| 5 | **并发安全吗？** | ✅ running 标志用 RwLock（读多写少），Arc 跨线程共享 |
| 6 | **可测试吗？** | ✅ 每个命令都有单元测试，parse_command 纯函数可同步测试 |

---

## 外婆能听懂的口语化讲解

想象一下你开了一家快递站（dae-rs），有很多工人（线程）在里面跑来跑去处理包裹（网络流量）。

**问题来了：**你怎么在不打扰工人的情况下，问他们"现在处理了多少件？"或者喊"全体注意，要换班了！"？

**外婆的解决方案：**

在快递站门口放一个意见箱（Unix 插槽 `/var/run/dae/control.sock`）。谁想下命令，往意见箱里扔纸条就行。工人有空了会去读纸条，然后按命令行事。

**支持的纸条命令：**

- `status` → "你们现在忙不忙？"
- `stats` → "给我看看今天收了多少件、发出去多少件"
- `reload` → "新规则本到了，大家换着用"
- `shutdown` → "收拾收拾，准备下班"
- `test <节点名>` → "老王那条线路还通吗？测一下"
- `version` → "你们这是什么版本啊？"

**为什么用 Unix 插槽而不是普通网络端口？**

因为插槽只给本机用，外部黑客想攻击也攻击不了（TCP/IP 端口可能被远程利用）。这是"门只给自己人开"的设计。

---

## 专业结构分析

### 核心类型一览

```
ControlCommand（命令枚举）
├── Status      → 查询运行状态
├── Reload      → 热重载配置
├── Stats       → 统计数据
├── Shutdown    → 优雅关闭
├── TestNode    → 节点连通性测试
├── Version     → 版本信息
└── Help        → 帮助

ControlResponse（响应枚举）
├── Ok(String)          → 成功信息
├── Error(String)       → 错误信息
├── Stats(ProxyStats)   → JSON 序列化的统计
├── Status(ProxyStatus) → JSON 序列化的状态
├── TestResult(NodeTestResult) → 节点测试结果
└── Version(String)     → 版本号

ProxyStatus（运行状态）
├── running: bool
├── uptime_secs: u64
├── tcp_connections: usize
├── udp_sessions: usize
├── rules_loaded: bool
├── rule_count: usize
└── nodes_configured: usize

ProxyStats（统计）
├── total_connections: u64
├── total_bytes_in/out: u64
├── active_tcp/udp: usize
├── rules_hit: u64
└── nodes_tested: usize
```

### 架构分层

```
┌─────────────────────────────────────────────┐
│           ControlServer                     │
│  ┌─────────────────────────────────────┐   │
│  │  start()                            │   │
│  │  - UnixListener.bind()              │   │
│  │  - 每连接 → handle_connection()     │   │
│  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
           │ Arc<ControlState>
           ▼
┌─────────────────────────────────────────────┐
│           ControlState                     │
│  - running: Arc<RwLock<bool>>              │
│  - start_time: SystemTime                  │
│  - stats: ProxyStats                        │
│  + get_status() / get_stats()              │
└─────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────┐
│       process_command()                     │
│  split_whitespace() → 命令分发               │
│  → ControlResponse                          │
└─────────────────────────────────────────────┘
```

---

## 关键调用链追溯

### 完整请求路径

```
外部进程（daectl）
    │
    │ connect_and_send(socket_path, "status\n")
    ▼
UnixStream::connect()  ←── 客户端连接
    │
    │  read_line() 读命令
    ▼
BufStream → process_command("status", &state)
    │
    ├── state.is_running().await       ← RwLock 读锁
    ├── state.get_status(...)         ← 构造 ProxyStatus
    └── ControlResponse::Status(...)
    │
    │  write_all(response_str.as_bytes())
    ▼
UnixStream → 响应 JSON 写回客户端
```

### 状态更新路径（shutdown 命令）

```
process_command("shutdown", &state)
    │
    └── state.set_running(false).await  ← RwLock 写锁
                                         → *running.write().await = false
```

### 关键并发设计

```rust
// 读多写少 → 用 RwLock 而非 Mutex
pub running: Arc<RwLock<bool>>

// 多个任务共享同一个 state → Arc
Arc<ControlState>
```

RwLock 在读多写少场景下性能优于 Mutex，因为多个读者可以同时持有锁。

---

## 设计取舍说明

### 1. Unix Domain Socket vs TCP 端口

| 选择 | 理由 |
|------|------|
| ✅ Unix Socket | 本机进程通信，更安全（无网络暴露）、更快（内核优化） |
| ❌ TCP 端口 | 不选，因为控制接口不需要远程访问 |

### 2. 纯文本命令 + JSON 响应

- 命令用简单字符串（"status"、"reload"），解析成本低
- 响应用 JSON 序列化，支持结构化数据
- **取舍**：牺牲了二进制的效率，换取人类可读性和调试便利

### 3. 状态占位设计

```rust
fn rules_loaded() -> bool { true }
fn rule_count() -> usize { 0 }
```

真实实现中，这些值应该从 dae-rs 主进程状态中读取。当前是占位符，暗示 control.rs 与主状态机之间的集成接口尚未完全实现。

### 4. tokio::io::copy 用于流转发（未来扩展）

`handle_connection` 目前的 relay 使用的是标准输入输出转发，而不是直接转发底层数据流。如果未来需要直接代理 TCP 流，需要修改这里的实现。

### 5. TCP 连接统计 vs 活跃连接统计

```rust
total_connections: u64    // 历史累计（只会增）
active_tcp_connections: usize  // 当前活跃（实时）
```

分离两个计数器，避免在每次状态查询时做减法运算。

---

## 关键代码片段

### 常量时间密码比对（防时序攻击）

```rust
// 密码比对用 ConstantTimeEq，防止时序攻击
pub fn matches(&self, username: &str, password: &str) -> bool {
    let user_match = self.username.as_bytes()
        .ct_eq(username.as_bytes()).unwrap_u8() == 1;
    let pass_match = self.password.as_bytes()
        .ct_eq(password.as_bytes()).unwrap_u8() == 1;
    user_match && pass_match
}
```

如果用普通 `==` 比较，攻击者通过测量响应时间差异（字符串前面匹配的长度），可以逐字节猜出密码。`ConstantTimeEq` 保证比较时间固定，不泄露信息。

### 插槽权限设置

```rust
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o666))?;
}
```

Unix 特有代码，让任何本地用户都能读写控制插槽，方便部署。

### 热重载的"未完成"设计

```rust
"reload" => {
    info!("Hot reload requested via control socket");
    // In real implementation, this would trigger config reload
    // For now, just acknowledge
    ControlResponse::Ok("Configuration reload initiated".to_string())
}
```

注释已经说明了当前只是确认收到命令，真实重载逻辑需要与 dae-rs 配置管理系统联动。
