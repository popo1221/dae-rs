# 014 - http_proxy.rs：HTTP CONNECT 代理处理器

## 一句话总结（10岁版本）

> 当你告诉浏览器"我要访问 https://google.com"，但浏览器不想自己直连，而是把请求"转交"给 dae-rs，让 dae-rs 帮忙去连，这时候 http_proxy.rs 就是那个**代购员**。它接过浏览器的请求，帮浏览器连接到 google.com，然后把双方的通信内容像快递一样原封不动地来回传递。

---

## 简化法则自检（6项检查）

| # | 检查项 | 结论 |
|---|--------|------|
| 1 | **有没有正确的抽象层次？** | ✅ HttpProxyHandler/HttpConnectRequest/HttpProxyServer 分层清晰 |
| 2 | **有没有不必要的复杂度？** | ✅ 自实现 base64 解码（不引入 base64 crate），但实际上 codec 够用 |
| 3 | **错误处理是否合理？** | ✅ 每一步都有对应的 HTTP 错误响应（502/407/400），不轻易 panic |
| 4 | **是否遵循单一职责？** | ✅ handler 管连接，relay 管转发，职责边界明确 |
| 5 | **并发安全吗？** | ✅ 每个连接独立 TcpStream，无共享可变状态 |
| 6 | **可测试吗？** | ✅ 全部 14 个单元测试，覆盖 parse/auth/encode 各路径 |

---

## 外婆能听懂的口语化讲解

### 场景还原：你在公司用代理上网

你（浏览器）想上 google.com，但公司规定：**所有网页请求必须先交给代理服务器**。

**流程是这样的：**

```
浏览器："我要 CONNECT google.com:443 HTTP/1.1"
代理（dae-rs）："行，等着，我帮你连上"
代理 → 连接 google.com:443
代理 → 告诉浏览器："200 OK，隧道建好了"
之后：浏览器和 google.com 之间的所有加密流量，都通过这个隧道原封不动地来回传
```

这就是 **HTTP CONNECT** 方法 —— 它不像普通 HTTP GET 那样代理自己处理请求，而是建立一个**隧道**，让双方直接对话，代理只当透明快递员。

### 为什么用 CONNECT 而不是普通代理？

- 普通 HTTP GET：代理能看见内容（不适合 https）
- CONNECT 隧道：代理只当搬运工，加密流量端到端，代理看不见内容

**这正是 dae-rs 需要的**——用户要安全上网，但 dae-rs 又要能转发流量，CONNECT 就是这个平衡点。

### 密码门卫：407 认证

如果代理设置了用户名密码：

```
浏览器："CONNECT google.com:443"
代理："等等，你谁啊？给我 407 Proxy-Authenticate"
浏览器："Proxy-Authorization: Basic YWRtaW46c2VjcmV0"
代理："嗯，验证通过，帮你连"
```

---

## 专业结构分析

### 模块组成

```
http_proxy.rs (约250行)
├── consts 模块           → HTTP 响应常量（200/502/407）
├── BasicAuth 结构体      → Base64解析 + 密码验证
├── base64_decode()      → 手写 base64 解码器
├── HttpProxyHandlerConfig → 配置（认证/超时/放行规则）
├── HttpConnectRequest    → CONNECT 请求解析
├── HttpProxyHandler      → 单连接处理器
└── HttpProxyServer       → TCP 监听服务器
```

### 数据流图

```
TCP Client (浏览器)
    │
    │ read_line() → 读取 "CONNECT host:port HTTP/1.1"
    ▼
parse HttpConnectRequest
    │
    ├── 检查 Proxy-Authorization (如果有)
    │       └── BasicAuth::from_header() → matches() [常量时间比对]
    │
    ├── DNS 解析或直接 SocketAddr
    │
    ├── TcpStream::connect(target)   → 连接目标服务器
    │
    ├── write_all(HTTP_OK)           → "200 Connection Established"
    │
    └── relay(client, remote)        → tokio::io::copy 双向转发
            │
            ├── client.read → remote.write
            └── remote.read → client.write
```

### relay() 的并发模型

```rust
async fn relay(&self, client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
    let (mut cr, mut cw) = tokio::io::split(client);  // 消费者端读写
    let (mut rr, mut rw) = tokio::io::split(remote);  // 远程端读写

    // 两个方向同时跑，谁先挂算谁的
    tokio::try_join!(
        tokio::io::copy(&mut cr, &mut rw),  // 客户端 → 远程
        tokio::io::copy(&mut rr, &mut cw),  // 远程 → 客户端
    )?;
    Ok(())
}
```

`try_join!` 确保两个方向同时进行，一个方向断了另一个也跟着停。

---

## 关键调用链追溯

### 完整 CONNECT 请求处理路径

```
TcpStream client (from browser)
    │
    ├─ read_line() → "CONNECT example.com:443 HTTP/1.1"
    │
    ├─ 循环 read_line() → 解析所有 Header
    │      "Proxy-Authorization: Basic xxx"
    │      "Host: example.com"
    │
    ├─ BasicAuth::from_header(value)
    │      └─ base64_decode("YWRtaW46c2VjcmV0") → "admin:secret"
    │
    ├─ HttpConnectRequest::parse("CONNECT example.com:443 HTTP/1.1")
    │      └─ parse_host_port("example.com:443")
    │              └─ (String, u16) = ("example.com", 443)
    │
    ├─ SocketAddr::from_str("example.com:443")
    │      └─ 失败 → tokio::net::lookup_host() DNS 查询
    │
    ├─ tokio::time::timeout(60s, TcpStream::connect(target))
    │
    ├─ client.write_all(HTTP_OK) → "HTTP/1.1 200 Connection Established\r\n\r\n"
    │
    └─ relay(client, remote)
            ├─ tokio::io::copy(cr, rw)  // client → remote
            └─ tokio::io::copy(rr, cw)  // remote → client
```

---

## 设计取舍说明

### 1. 手写 base64 解码 vs 依赖 crate

```rust
fn base64_decode(input: &str) -> Option<String> {
    // ... 手写实现 ...
}
```

选择手写而非引入 `base64` crate 的理由：
- **节省依赖**：dae-rs 追求最小依赖，手写解码只需 ~40 行
- **只读不解码**：只需要解码 Basic Auth，从来不编码，不需要完整 codec
- **权衡**：手写代码维护成本，但这个实现足够简单（核心逻辑约 30 行）

### 2. 常量时间密码比对 (Constant-Time Comparison)

```rust
pub fn matches(&self, username: &str, password: &str) -> bool {
    let user_match = self.username.as_bytes()
        .ct_eq(username.as_bytes()).unwrap_u8() == 1;
    ...
}
```

**攻击场景：**如果用普通 `==`，密码 "abc" 和 "abd" 的比对在第一个字符不匹配时就立即返回 FALSE。攻击者通过大量请求，测量响应时间差异，可以推断出正确的密码前缀。

**subtle 库的 `ConstantTimeEq`** 保证无论在哪个字节位置不匹配，比较时间完全相同，无法通过时序信息泄露密码。

### 3. BufStream vs 直接 read_line

```rust
let mut stream = BufStream::new(stream);
let mut line = String::new();
reader.read_line(&mut line).await?;
```

 BufReader 提供缓冲区，减少系统调用次数。HTTP 头部通常不大，但多条头部用 BufReader 更高效。

### 4. DNS 兜底解析

```rust
SocketAddr::from_str(&format!("{}:{}", request.host, request.port))
    .ok()
    .or_else(|| tokio::net::lookup_host(...).ok()) // DNS fallback
```

如果 `SocketAddr::from_str` 失败（host 不是 IP 格式），自动尝试 DNS 查询。这个 fallback 让 handler 更健壮，不需要调用方保证传入 IP 地址。

### 5. 关闭连接时的错误处理

```rust
Ok(0) => return Ok(()), // 连接关闭 → 优雅退出，不算错误
```

读到 0 字节 = 对端关闭连接。这是正常情况，不报警，不抛异常，安静地结束处理。

---

## 关键代码片段

### 手写 Base64 解码（RFC 4648）

```rust
fn base64_decode(input: &str) -> Option<String> {
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    // ... 4-byte block 解码逻辑 ...
}
```

支持标准 Base64 alphabet，处理 `=` padding，每 4 字符块 → 最多 3 字节输出。

### HTTP CONNECT 请求解析

```rust
impl HttpConnectRequest {
    pub fn parse(request_line: &str) -> Option<Self> {
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 { return None; }
        let host_port = parts[1];
        let (host, port) = Self::parse_host_port(host_port)?;
        Some(Self { host, port })
    }

    fn parse_host_port(s: &str) -> Option<(String, u16)> {
        if let Some(idx) = s.rfind(':') {  // 从右边找第一个冒号（处理 IPv6）
            let host = s[..idx].to_string();
            let port: u16 = s[idx + 1..].parse().ok()?;
            Some((host, port))
        } else {
            Some((s.to_string(), 443))  // 默认 443
        }
    }
}
```

用 `rfind` 而非 `find` 是为了兼容 IPv6 地址 `[::1]:8080`。

### tokio::io::split 实现双向转发

```rust
tokio::try_join!(
    tokio::io::copy(&mut cr, &mut rw),
    tokio::io::copy(&mut rr, &mut cw),
)?;
```

`tokio::io::split` 将 TcpStream 沿读写方向拆成两个独立 handle，可以并发执行 copy。`try_join!` 确保任一方向失败时另一个也被取消，避免半开连接。
