# 017 - proxy_chain.rs | 代理链

## 一句话总结（10岁版本）

**像打电话转接**：你想打给朋友，但直接打电话被监控了。你先打给信任的同事A，A帮你转给同事B，B再帮你转给朋友C。整个通话过程中，只有A知道你的身份，B只知道A在打电话，C只知道有电话进来。

---

## 简化法则自检（6项）

- [x] **法则1**：链中每个节点顺序连接，上一个成功才连下一个
- [x] **法则2**：支持故障转移（failover）——当前节点失败自动试下一个
- [x] **法则3**：Direct 节点代表"直连"，跳出版主代理
- [x] **法则4**：SOCKS5/HTTP 有完整实现，其他协议（Trojan/VMess/VLESS）留空
- [x] **法则5**：链是可变的——通过 `next_node()` 在运行时切换当前位置
- [x] **法则6**：每个节点独立处理协议握手，不依赖上层协议理解

---

## 外婆能听懂

想象你要寄一封重要的信，但不想让邮递员知道是你寄的：

**方案A（直连）**：直接把信塞进邮筒 → 邮递员知道你家门牌号

**方案B（代理链）**：
1. 你把信给朋友甲（第一个代理节点）
2. 朋友甲把信重新包装，再给朋友乙（第二个代理节点）
3. 朋友乙最后把信送到目的地

这样目的地只知道"乙在寄信"，乙只知道"甲在寄信"，甲只知道"有人在寄信"——**你完全匿名**。

代码里的代理链就是这种思想：数据包在节点之间层层转发，每个节点只知道上下家，不知道原始发送者。

---

## 专业结构分析

### 核心数据结构

```
ProxyNode（一个节点）
├── node_type: ProxyNodeType   # 协议类型
├── addr: String               # IP 或域名
├── port: u16                 # 端口
├── username: Option<String>   # 认证（可选）
├── password: Option<String>   # 认证（可选）
└── tls: bool                  # 是否加密

ProxyChain（一条链 = 多个节点的有序列表）
├── nodes: Vec<ProxyNode>      # 节点列表
└── current_index: usize      # 当前尝试到第几个节点

ProxyNodeType（支持的协议）
├── Direct     # 直连（无代理）
├── Socks4     # SOCKS4/SOCKS4a
├── Socks5     # SOCKS5（完整实现）
├── Http       # HTTP CONNECT（完整实现）
├── Shadowsocks / Trojan / Vmess / Vless  # 预留，未实现
```

### SOCKS5 连接握手（详细）

```
客户端                        代理节点                       目标
  │                              │                           │
  ├──── TCP 连接建立 ──────────► │                           │
  │                              │                           │
  ├──── [0x05, 0x01, 0x00] ────► │  # SOCKS5 版本, 1种认证方法, 无认证
  │                              │                           │
  │ ◄─── [0x05, 0x00] ────────── │  # 版本确认, 认证成功 (0x00)
  │                              │                           │
  ├──── [0x05, 0x01, 0x00, ...] ► │  # CONNECT命令 + 目标地址
  │                              │                           │
  │                              ├──── TCP 连接建立 ────────► │
  │                              │                           │
  │ ◄─── [0x05, 0x00, ...] ──── │  # 连接成功
  │                              │                           │
  ├──── 应用数据 ──────────────► │ ──── 应用数据 ────────────► │
  │◄─── 响应数据 ──────────────── │ ◄─── 响应数据 ────────────│
```

### HTTP CONNECT 隧道（详细）

```
客户端              HTTP代理                目标
  │                    │                    │
  ├─ TCP 连接建立 ────► │                    │
  │                    │                    │
  ├─ "CONNECT target:port HTTP/1.1\r\n" ──►│
  │                    │                    │
  │                    ├─ TCP 连接建立 ────►│
  │                    │                    │
  │ ◄─ "200 Connection Established" ◄───  │
  │                    │                    │
  ├─ 应用数据 ────────► │ ──── 应用数据 ────►│
  │◄─ 响应数据 ◄─────── │ ◄─── 响应数据 ◄───│
```

### 故障转移（Failover）逻辑

```rust
async fn connect(&mut self, target: &str, port: u16) -> Result<TcpStream> {
    while self.current_index < self.nodes.len() {
        let node = &self.nodes[self.current_index];
        match self.connect_through_node(node, target, port).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                // 连接失败，尝试下一个节点
                if self.next_node() { continue; }
                break;
            }
        }
    }
    Err(all_nodes_failed)
}
```

---

## 关键调用链追溯

### 代理链连接流程

```
外部调用: proxy_chain.connect("example.com", 443)
    │
    ▼
ProxyChain::connect()
    │
    ├─→ [loop] current_index < nodes.len()
    │       │
    │       ├─→ ProxyChain::connect_through_node(node, target, port)
    │       │       │
    │       │       ├─→ Direct     → TcpStream::connect() 直接连接
    │       │       ├─→ Socks5     → ProxyChain::socks5_connect()
    │       │       ├─→ Http       → ProxyChain::http_connect()
    │       │       └─→ 其他       → Err(Unsupported)
    │       │
    │       ├─→ 成功 → 返回 stream
    │       │
    │       └─→ 失败
    │           ├─→ next_node() = true  → 继续循环
    │           └─→ next_node() = false → 退出循环
    │
    ▼
返回 Result<TcpStream, Error>
```

### SOCKS5 内部握手

```
socks5_connect(node, target, target_port)
    │
    ├─→ TcpStream::connect(proxy_addr)     # 连接代理服务器
    │
    ├─→ write_all([0x05, 0x01, 0x00])      # 发送认证协商
    │
    ├─→ read_exact([0, 0])                  # 读取响应
    │       └─→ resp[1] != 0x00 → 认证失败
    │
    ├─→ 构建 CONNECT 请求:
    │       [0x05, 0x01, 0x00]              # VER, CMD=connect, RSV
    │       + [0x01, ...ipv4...]           # IPv4 地址类型
    │       或 [0x03, len, ...domain...]   # 域名类型
    │       + [port: u16]                  # 端口
    │
    ├─→ write_all(request)
    │
    ├─→ read_exact([0..10])                 # 读取回复
    │       └─→ reply[1] != 0x00 → 连接被拒绝
    │
    ▼
返回已建立的 TcpStream（通往目标的连接）
```

---

## 设计取舍说明

### 1. 为什么 current_index 是可变状态？

代理链的当前节点位置是**运行时可变**的，因为 failover 需要记录"上次试到哪个了"。这意味着 `ProxyChain` 实例不能跨连接共享（否则并发连接会互相覆盖位置）。这是合理的——每个连接有自己独立的链状态。

```rust
// 注意：connect 需要 &mut self
pub async fn connect(&mut self, target: &str, port: u16)
// 如果链是 Clone 的，每个克隆有独立的 current_index
```

### 2. 为什么只实现 SOCKS5 和 HTTP，不实现其他协议？

SOCKS5 和 HTTP CONNECT 是**标准化且广泛支持**的代理协议，所有代理软件都认识它们。其他协议（Trojan/VMess/VLESS/ShadowSocks）需要各自的协议栈实现，会大幅增加代码量。当前设计预留了扩展接口，但没有实现。

### 3. 为什么 SOCKS5 连接目标时用域名而非 IP？

SOCKS5 支持 `ATYP=0x03`（域名），这样代理服务器会替我们做 DNS 解析。好处：
- 本地不需要泄露 DNS 查询
- 目标地址在代理链中是加密传输的（如果链路上有 TLS）

### 4. Direct 节点的意义

Direct 不是"没有节点"，而是一个**显式的直连决策**。在代理链中，有时候某些目标需要绕过所有代理直接连接（比如内网地址），Direct 节点就是这种场景的语法支持。

### 5. 未实现的协议如何处理？

当遇到未实现的协议时，直接返回 `ErrorKind::Unsupported`，并携带清晰的错误信息指明是哪种协议。这比 panic 或默默跳过要好，方便后续扩展实现时排查问题。
