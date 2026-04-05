# 016 - protocol_dispatcher.rs | 协议分发器

## 一句话总结（10岁版本）

**像个智能快递分拣员**：一个包裹（TCP连接）进来，分拣员只瞄一眼封口（ peek 前 16 字节），就知道是 SOCKS5 的、HTTP 的，还是不认识（Unknown）的，然后把它们送到不同的流水线上去处理。

---

## 简化法则自检（6项）

- [x] **法则1**：只做协议检测，不做数据处理（peek 不消费数据）
- [x] **法则2**：超时 500ms 内必须做出判断，超时即拒绝
- [x] **法则3**：检测逻辑零依赖——只看字节模式，不查表不联网
- [x] **法则4**：检测结果四选一：Socks5 / HttpConnect / HttpOther / Unknown
- [x] **法则5**：Unknown 协议回 HTTP 501 响应，不挂起连接
- [x] **法则6**：Handler 未配置时优雅降级，不是 panic

---

## 外婆能听懂

想象你开了一个邮件分拣中心。包裹来了，你不需要拆开看里面是什么——只要看一下信封上的邮戳颜色：

- 红色邮戳（0x05）→ 送到 SOCKS5 专线
- 蓝色邮戳（字母开头 + "CONNECT"）→ 送到 HTTP 代理专线
- 绿色邮戳（其他字母开头，如 GET/POST）→ 也送 HTTP 代理，但标注"普通请求"
- 看不懂的 → 退回去，顺便告诉他"这包裹我们不收"

关键在于：**你只瞄一眼（peek），不拿走了看（read）**，这样包裹还在，能继续往下走。

---

## 专业结构分析

### 核心数据结构

```
DetectedProtocol (枚举，四选一)
├── Socks5      # 第一个字节 == 0x05
├── HttpConnect # 以 "CONNECT " 开头
├── HttpOther   # 以 "GET "/"POST "/"HEAD " 等开头
└── Unknown     # 以上都不是

ProtocolDispatcher
├── config: ProtocolDispatcherConfig
│   ├── socks5_addr: Option<SocketAddr>
│   └── http_addr: Option<SocketAddr>
├── socks5_handler: Option<Arc<Socks5Handler>>
└── http_handler: Option<Arc<HttpProxyHandler>>
```

### 检测算法

```rust
pub fn detect(first_bytes: &[u8]) -> DetectedProtocol {
    match first_bytes[0] {
        0x05 => Socks5,                    // 精确字节匹配
        b'A'..=b'Z' => {                   // ASCII 大写字母范围
            let s = String::from_utf8_lossy(first_bytes);
            if s.starts_with("CONNECT ") { HttpConnect }
            else if matches!(s, "GET /" | "POST /" | ...) { HttpOther }
            else { Unknown }
        }
        _ => Unknown
    }
}
```

### 关键设计决策

| 决策 | 选择 | 理由 |
|------|------|------|
| peek 长度 | 16 字节 | 覆盖所有协议头，安全边界 |
| 检测超时 | 500ms | 防止 slow-loris 攻击占用分拣员 |
| Unknown 响应 | HTTP 501 | 对客户端友好，告知原因 |
| handler 未配置 | 降级拒绝 | 而非 panic，保持服务可用 |

### 并发模型

- `ProtocolDispatcher` 本身是 `Sync + Send`（无锁状态）
- `handle_connection` 消费 `self: Arc<Self>` 保证独享
- Handler 使用 `Arc<Handler>` 允许多连接共享同一个 handler 实例

---

## 关键调用链追溯

### 连接入口

```
外部 TCP 连接 (TcpStream)
    │
    ▼
ProtocolDispatcher::handle_connection(self: Arc<Self>, client)
    │
    ├─→ client.peer_addr()          # 获取客户端地址
    │
    ├─→ client.peek(&mut buf[0..16]) # 偷看16字节，不消费
    │       │
    │       └─→ 超时 500ms → 返回 TimedOut 错误
    │
    ├─→ DetectedProtocol::detect(&buf[..n])  # 分类
    │       │
    │       └─→ DetectedProtocol::Socks5 | HttpConnect | HttpOther | Unknown
    │
    ▼
match protocol {
    Socks5      → socks5_handler.clone().handle(client).await
    HttpConnect → http_handler.clone().handle(client).await
    HttpOther   → http_handler.clone().handle(client).await  # 共用 handler
    Unknown     → reject_unknown(client, reason)           # 回 501
}
```

### 完整 Proxy Server 启动链

```
CombinedProxyServer::new(config)
    │
    ├─→ Socks5Server::new(socks5_addr) → Option<Arc<Socks5Server>>
    └─→ HttpProxyServer::new(http_addr)  → Option<Arc<HttpProxyServer>>

CombinedProxyServer::start(self: Arc<Self>)
    │
    ├─→ tokio::spawn(socks5_server.start())  # 后台运行
    └─→ tokio::spawn(http_server.start())    # 后台运行
```

---

## 设计取舍说明

### 1. 为什么用 peek 而不是 read？

**read 会消费数据**，如果协议检测失败，数据已经被拿走了，handler 就没法重新读取。peek 是 Linux/BSD 的 `MSG_PEEK` 标志，数据还在缓冲区里，检测完继续让 handler 读。

### 2. 为什么 HTTP CONNECT 和 HTTP Other 走同一个 handler？

两者都是 HTTP 协议，握手和处理流程完全一致。只是在日志里标注一下区别，实际处理路径相同。如果拆成两个 handler，会增加维护复杂度。

### 3. 500ms 超时是否太短？

对于一个 peek 操作来说，500ms 已经很充裕了。这个超时主要是防止恶意客户端发送极慢的 SNI 扩展或 TLS ClientHello，占用分拣员（acceptor 线程）。正常的 TCP 连接建立 < 50ms。

### 4. Unknown 为什么返回 HTTP 501 而不是直接关闭连接？

返回一个合法的 HTTP 响应，客户端能知道发生了什么。如果直接关掉，某些 HTTP 客户端会以为网络问题而重试，加重服务器负担。

---

## 补充：CombinedProxyServer 的角色

`CombinedProxyServer` 不是 protocol_dispatcher 的替代品，而是**上层容器**：

- 它同时管理一个 SOCKS5 Server 和一个 HTTP Server
- 两个 Server 监听**不同的端口**（默认 1080 和 8080）
- 每个 Server 内部用各自的 protocol dispatcher 做协议检测
- 也就是说，**分拣是每个 Server 内部的事**，CombinedProxyServer 只负责启动和生命周期管理

这与 dae-rs 整体架构的对应关系：
- CombinedProxyServer 对应 **dae-config** 里配置的多个 listen 节点
- 每个 listen 节点可以独立配置 SOCKS5 或 HTTP 端口
