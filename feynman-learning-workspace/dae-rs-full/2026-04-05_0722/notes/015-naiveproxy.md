# 015 - naiveproxy.rs：NaiveProxy 集成模块

## 一句话总结（10岁版本）

> NaiveProxy 就像一个**超级伪装者**——它用 Chrome 浏览器的网络协议栈来上网，让审查者以为你只是在正常浏览网页。**naiveproxy.rs** 就是 dae-rs 和这个伪装者之间的"中间人"：dae-rs 负责启动和管理 NaiveProxy 进程，NaiveProxy 负责实际把流量伪装成 Chrome 的样子发送出去。

---

## 简化法则自检（6项检查）

| # | 检查项 | 结论 |
|---|--------|------|
| 1 | **有没有正确的抽象层次？** | ✅ NaiveProxyManager 管进程生命周期，HttpConnectTunnel 管隧道建立，分工明确 |
| 2 | **有没有不必要的复杂度？** | ✅ 只实现管理接口，不重造 NaiveProxy 本身（它是个独立二进制） |
| 3 | **错误处理是否合理？** | ✅ start/stop/health_check 每步都有错误处理和状态检查 |
| 4 | **是否遵循单一职责？** | ✅ Manager = 进程管理，Tunnel = 隧道通信，不混在一起 |
| 5 | **并发安全吗？** | ✅ RwLock 保护 running 标志，Arc 跨线程共享配置 |
| 6 | **可测试吗？** | ⚠️ 多数测试是纯配置测试，实际进程启动需要真实 naiveproxy 二进制 |

---

## 外婆能听懂的口语化讲解

### 现实中的"借壳上市"

想象你要寄一封机密信件，但邮递员会检查所有信件内容。怎么办？

**聪明的方法：** 把信装进一个印着"XX公司官方文件"的信封里。邮递员一看是知名公司的信封，就直接放行了，根本不拆开看。

NaiveProxy 就是这个策略。它**借用 Chrome 浏览器的网络协议栈**来发送流量。审查系统看到的是 Chrome 在上网——TLS 握手、HTTP/2 请求、证书链——全部和真 Chrome 一模一样。审查系统根本分不清这是浏览器还是 NaiveProxy。

### naiveproxy.rs 在其中的角色

NaiveProxy 本身是一个**独立程序**（比如你下载的 `naiveproxy` 二进制文件）。dae-rs 不重新实现它的核心逻辑，而是：

1. **启动它**：帮它配置好监听地址（`--listen=http://127.0.0.1:1090`）
2. **告诉它**：上游代理服务器是谁（`--proxy=https://your-server.com`）
3. **使用它**：当 dae-rs 需要发送流量时，通过 HTTP CONNECT 隧道连接到 NaiveProxy
4. **管理它**：监控它是否还活着，必要时重启或关闭

naiveproxy.rs 就是这个"代管员"的代码实现。

### 启动 NaiveProxy 的命令行

```bash
naiveproxy \
  --listen=http://127.0.0.1:1090 \    # dae-rs 连接到这个本地地址
  --proxy=https://user:pass@server.com \  # 实际出口服务器
  --log-level=debug                    # 日志级别
```

---

## 专业结构分析

### 模块组成

```
naiveproxy.rs (约300行)
├── NaiveProxyConfig       → 配置结构体（Builder 模式）
├── NaiveProxyManager      → 进程生命周期管理
│   ├── start()            → 启动 naiveproxy 进程
│   ├── stop()             → kill 进程
│   ├── is_running()       → 查询状态
│   └── health_check()     → TCP 连通性探测
├── HttpConnectTunnel       → HTTP CONNECT 隧道客户端
│   └── connect(proxy_addr) → 建立到 naiveproxy 的 CONNECT 隧道
└── 辅助函数 / 测试
```

### 架构关系图

```
┌─────────────────────────────────────────────┐
│          dae-rs 进程                         │
│  ┌──────────────────────────────────────┐  │
│  │  NaiveProxyManager                    │  │
│  │  - 启动/停止 naiveproxy 子进程        │  │
│  │  - 监控健康状态                        │  │
│  └──────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
              │  spawn Child process
              ▼
┌─────────────────────────────────────────────┐
│       naiveproxy 子进程                       │
│  - 监听 http://127.0.0.1:1090               │
│  - 用 Chrome 网络栈连接 upstream proxy       │
└─────────────────────────────────────────────┘
              │
              │  HTTP CONNECT
              ▼
┌─────────────────────────────────────────────┐
│       HttpConnectTunnel                      │
│  - 发送 CONNECT host:port                   │
│  - 建立双向隧道                              │
└─────────────────────────────────────────────┘
```

### 配置的 Builder 模式

```rust
impl NaiveProxyConfig {
    pub fn new(listen_addr: &str, upstream_proxy: &str) -> Self { ... }
    pub fn with_binary_path(mut self, path: PathBuf) -> Self { self }
    pub fn with_extra_args(mut self, args: Vec<String>) -> Self { self }
    pub fn with_logging(mut self, level: &str) -> Self { self }
}
```

链式调用风格，灵活组合参数。例如：

```rust
NaiveProxyConfig::new("127.0.0.1:1090", "https://server.com")
    .with_binary_path(PathBuf::from("/usr/bin/naiveproxy"))
    .with_logging("debug")
    .with_extra_args(vec!["--ipv6".to_string()])
```

---

## 关键调用链追溯

### 启动流程（dae-rs 内部）

```
NaiveProxyManager::new(config)
    │
    └── manager.start().await
            │
            ├─ Command::new(binary_path)
            │     .args(["--listen=127.0.0.1:1090", "--proxy=https://..."])
            │     .stdout(Stdio::piped())
            │     .kill_on_drop(true)
            │     .spawn()
            │
            ├─ tokio::time::sleep(500ms)  // 等进程启动
            │
            ├─ child.try_wait()  → 检查进程是否立即退出
            │
            └─ *running.write().await = true
                self.process = Some(child)
```

### 健康检查流程

```
health_check()
    │
    ├─ running.read().await == false → return false
    │
    └─ TcpStream::connect(listen_addr)
            │
            ├─ Ok(_) → return true (进程在监听)
            └─ Err(_) → return false (连接失败)
```

注意：`health_check` 只是检查端口是否可连接，不验证 naiveproxy 是否真的能代理流量。轻量级检查，不做完整探测。

### 隧道建立流程

```
HttpConnectTunnel::new("google.com", 443)
    │
    └── tunnel.connect("127.0.0.1:1090")
            │
            ├─ TcpStream::connect(proxy_addr).await
            │
            ├─ write_all("CONNECT google.com:443 HTTP/1.1\r\nHost: google.com:443\r\n\r\n")
            │
            ├─ read(&mut response)  // 读 200 字节响应
            │
            └─ response.contains("200")
                    │
                    ├─ true  → return Ok(stream)  // 隧道建立成功
                    └─ false → return Error  // 代理拒绝
```

---

## 设计取舍说明

### 1. 进程管理 vs 库集成

| 选择 | 理由 |
|------|------|
| ✅ 启动子进程 | NaiveProxy 依赖 Chromium 网络栈，无法作为 Rust 库直接链接 |
| ✅ kill_on_drop | 进程随 manager 一起消亡时自动清理，防止僵尸进程 |
| ⚠️ try_wait 后立即检查 | 500ms 等待 + try_wait 只能检测"立即崩溃"，无法检测"几秒后崩溃" |

更可靠的做法是在后台定期 ping 健康检查端点，但当前实现是简化版本。

### 2. HTTP CONNECT 作为隧道协议

dae-rs → NaiveProxy 的通信用 **HTTP CONNECT** 而非 NaiveProxy 自有协议：

- NaiveProxy 对外暴露的就是一个**标准 HTTP 代理**
- dae-rs 不需要理解 NaiveProxy 内部协议
- 任何 HTTP CONNECT 客户端都能使用 NaiveProxy

这是**最小知识原则**：dae-rs 只需要把 NaiveProxy 当作一个普通 HTTP 代理使用，不绑定 NaiveProxy 特有行为。

### 3. 配置的纯数据性质

```rust
#[derive(Debug, Clone)]
pub struct NaiveProxyConfig {
    pub binary_path: PathBuf,
    pub listen_addr: String,
    pub upstream_proxy: String,
    pub extra_args: Vec<String>,
    pub enable_logging: bool,
    pub log_level: String,
}
```

`Config` 只存配置，不带可变状态，所以用 `#[derive(Clone)]`。真正的运行时状态（进程句柄、running 标志）存在 `NaiveProxyManager` 里。

### 4. Drop 实现中的 Best-Effort Kill

```rust
impl Drop for NaiveProxyManager {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.process {
            let _ = child.start_kill(); // ignore errors
        }
    }
}
```

在析构函数里 kill 进程是"尽力而为"——Rust 析构函数里panic 会导致程序中止，所以错误直接忽略。这是合理的最后防线，不依赖它做可靠清理。

### 5. 不支持 Windows

```rust
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o666))?;
}
```

NaiveProxy 本身是跨平台的，但当前 naiveproxy.rs 中没有 Windows 进程管理（`std::process::Command` 在 Windows 上也有 kill_on_drop）。这个取舍是因为 dae-rs 主要面向 Linux/macOS 等 Unix-like 系统。

### 6. 为什么用 TcpStream::connect 而非 HTTP 客户端

```rust
pub async fn health_check(&self) -> bool {
    match TcpStream::connect(addr).await {
        Ok(_) => true,
        Err(_) => false,
    }
}
```

只建立 TCP 连接，不发 HTTP 请求。因为 naiveproxy 监听的是原始 TCP 端口，任何连接到该端口的行为（即使不是有效 HTTP 请求）都会让 naiveproxy 保持连接。所以 TCP 连通性 = 健康状态，这是最轻量的检查方式。

---

## 关键代码片段

### 子进程启动与 500ms 等待

```rust
let mut child = Command::new(&self.config.binary_path)
    .args(&args)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true)
    .spawn()?;

tokio::time::sleep(std::time::Duration::from_millis(500)).await;

if let Some(status) = child.try_wait()
    .map_err(|e| std::io::Error::other(...))?
{
    if status.code().is_some() {
        return Err(...); // 进程立即退出 = 启动失败
    }
}
```

`try_wait()` 返回 `Option<ExitStatus>`：`None` = 进程还在跑，`Some(ExitStatus)` = 进程已结束。

### HTTP CONNECT 隧道请求格式

```rust
let request = format!(
    "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
    self.host, self.port, self.host, self.port
);
```

符合 RFC 7230 的 CONNECT 格式：`CONNECT target HTTP/1.1`，必须有 `Host:` 头。

### RwLock 保护进程状态

```rust
pub struct NaiveProxyManager {
    process: Option<Child>,
    running: Arc<RwLock<bool>>,
}
```

`process: Option<Child>` 必须是 `Manager` 的独占字段（一次只能有一个 start/stop 操作），而 `running` 需要跨线程共享所以用 `Arc<RwLock<bool>>`。这里用 RwLock 而非 Mutex 因为 `is_running()` 只读操作多于写入。
