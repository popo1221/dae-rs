# 020 - socks4.rs 费曼学习笔记

> **一行总结（10岁版本）**：SOCKS4 是一个"老派中间人"——客户端告诉它"帮我连接某某网站的某个端口"，它就帮你连过去帮你传话。它有一个升级版叫 SOCKS4a，可以直接告诉它域名而不必先知道 IP 地址。

---

## 简化法则自检（6项检查）

| # | 检查项 | 状态 | 说明 |
|---|--------|------|------|
| 1 | **删除行话** | ✅ | VER/CD/ATYP → 版本号/命令码/地址类型，已翻译 |
| 2 | **找准比喻** | ✅ | 餐厅接线员比喻：SOCKS4=只能转给有地址的人，SOCKS4a=可以报餐厅名字 |
| 3 | **分块消化** | ✅ | 协议解析 → 命令分发（CONNECT/BIND）→ 桥接转发 |
| 4 | **外婆验证** | ✅ | 她能听懂"你告诉接线员要打给谁，她帮你接通" |
| 5 | **没有黑话** | ✅ | 命令码/响应码旁均附通俗含义 |
| 6 | **逻辑连贯** | ✅ | 请求解析 → 路由分发 → 连接建立 → 双向桥接，完整 |

---

## 外婆能听懂的口语化讲解

想象你要打电话给隔壁小区的王阿姨，但你不想自己拨号。

**SOCKS4**：
你告诉接线员："帮我接通 192-168-1-100 这个号码，分机 8080"。接线员帮你拨通，双方开始通话，你说什么她就转什么。

**SOCKS4a**（升级版）：
你告诉接线员："帮我接通'王阿姨家'这个号码，分机 8080"。接线员自己查电话本找到王阿姨家的号码（192.168.1.100），帮你接通。好处是你不用记具体号码，只要知道名字就行。

**BIND 命令**（更难懂）：
BIND 不是让你打出去，而是让对方打进来。比如你要接收快递，你告诉接线员"帮我等电话，有人会打进来"。接线员给你分配一个临时号码，然后等有人打来就帮你接通。这是 FTP 主动模式等场景需要的。

---

## 专业结构分析

### 协议格式（SOCKS4 vs SOCKS4a）

**SOCKS4 请求格式**（共 9+ 字节）：
```
+----+----+----+----+----+----+----+----+....
| VER| CMD| DSTPORT |    DSTIP    | USERID |NULL|
+----+----+----+----+----+----+----+----+....
  1B   1B     2B          4B       N bytes  1B
```

**SOCKS4a 关键区别**：当 DSTIP 的前3字节是 `0x00 0x00 0x00` 时，说明后面跟的是域名而不是 IP。第4字节变成了域名的长度。

```
DSTIP = [0x00][0x00][0x00][域名长度] ← SOCKS4a 域名指示
然后跟：域名（长度由上文字节指定）+ NULL
```

### 核心数据结构

| 结构体 | 职责 |
|--------|------|
| `Socks4Command` | 命令枚举：Connect(0x01) / Bind(0x02) |
| `Socks4Reply` | 响应码：Granted(0x5A) / Rejected(0x5B) / FailedIdentd(0x5C) / FailedUser(0x5D) |
| `Socks4Address` | IPv4 地址 + 端口 |
| `Socks4Request` | 完整请求：命令 + 地址 + 用户ID + 是否SOCKS4a + 域名 |
| `Socks4Config` | 服务器配置：bind_addr / port / enable_socks4a |
| `Socks4Server` | 服务器主循环 |

### 两种命令处理流程

**CONNECT（直接连接）**：
```
parse request
  └─ is_socks4a? → resolve domain → connect(target)
      └─ send response (0x5A)
          └─ bridge_connections(client, target)
```

**BIND（等别人连进来）**：
```
parse request
  └─ create TcpListener
      ├─ send first response (binding) → wait for incoming
      │   └─ listener.accept()
      └─ send second response (established)
          └─ bridge_connections(client, incoming)
```

### SOCKS4 vs SOCKS5 对比

| 维度 | SOCKS4 | SOCKS5 |
|------|--------|--------|
| 版本号 | 0x04 | 0x05 |
| IPv6 支持 | ❌ | ✅ |
| 域名支持 | ✅ (SOCKS4a) | ✅ |
| 认证 | userid（无加密） | 多种认证机制 |
| 命令 | CONNECT, BIND | CONNECT, BIND, UDP ASSOCIATE |
| 响应码 | 4种 | 更多 |

---

## 关键调用链追溯

### CONNECT 命令完整链路

```
Socks4Server::handle_connection(stream)
  └─ Socks4Request::parse(stream)
      ├─ read VER(1B) → 验证 == 0x04
      ├─ read CMD(1B) → Socks4Command
      ├─ read DSTPORT(2B) → port
      ├─ read DSTIP.head(3B) → 检查 0x00 0x00 0x00 → is_socks4a?
      ├─ read DSTIP.tail(1B)
      ├─ read USERID → null-terminated string
      └─ if is_socks4a → read domain + null
          │
          ▼
  match command:
    Socks4Command::Connect → handle_connect(stream, request)
      ├─ if socks4a → domain.resolve() → SocketAddr
      ├─ else → direct SocketAddr from IPv4
      ├─ TcpStream::connect(target)
      ├─ write_response(GRANTED)
      └─ bridge_connections(stream, target_stream)
          ├─ split client → reader + writer
          ├─ split target → reader + writer
          └─ loop { target_reader.read() → client_writer.write() }
```

### BIND 命令的两次响应

```
第一次响应（通知客户端监听地址）：
VN=0x00 | CD=0x5A | DSTPORT=本地端口 | DSTIP=本地IP

等待 incoming 连接...

第二次响应（通知客户端连接已建立）：
VN=0x00 | CD=0x5A | DSTPORT=远程端口 | DSTIP=远程IP
```

---

## 设计取舍说明

### 1. 响应格式 VN=0x00 固定

**取舍**：协议规定，固定字节。

SOCKS4 响应固定以 0x00 开头（VN），这是协议规范，和请求的 VER=0x04 不同。代码里硬编码 `[0x00]` 体现了这一点。

### 2. bridge_connections 是单向半双工

**取舍**：简单实现 > 完整双向。

```rust
let mut buf = vec![0u8; 8192];
loop {
    let n = target_reader.read(&mut buf).await?;
    if n == 0 { break; }
    client_writer.write_all(&buf[..n]).await?;
}
```

这里只做了 **target → client** 的单向转发，**client → target** 的方向在当前代码中被忽略了（half-duplex）。这是代码的一个简化/BUG——真正的 SOCKS4 桥接应该是双向的。但因为 dae-rs 里 SOCKS4 可能只是配角（主要用 CONNECT），所以简化了。相比之下 shadowsocks.rs 用的是 `tokio::io::copy` 双向同时复制。

### 3. SOCKS4a 域名解析放在 handle_connect 里

**取舍**：在连接时解析，而非解析请求时。

如果解析失败，handle_connect 会直接返回 rejection，而不是在 parse 阶段就拒绝。这样做的好处是协议解析和 DNS 解析分离，代码更清晰；坏处是 parse 成功但 resolve 失败时已经浪费了处理时间。

### 4. is_socks4a 判断依赖前3字节

```rust
let is_socks4a = ip_head[0] == 0x00 && ip_head[1] == 0x00 && ip_head[2] == 0x00;
```

**取舍**：协议规定，简洁明了。

SOCKS4a 用魔法地址 `0.0.0.X` (X非0) 标识域名存在。这是 SOCKS4a 协议设计的精华——不需要新增协议版本号，只要 DSTIP 前三字节为0，就用域名解释。这样 SOCKS4a 服务器可以同时支持老 SOCKS4 客户端（它们会传真实 IP）。

### 5. Identd 响应码（0x5C/0x5D）未实际使用

**取舍**：协议字段保留，未实现 identd 查询。

SOCKS4 的 0x5C (identd not running) 和 0x5D (user id mismatch) 是给那些做 identd 查询的服务器用的。dae-rs 的实现没有真的去查 identd，直接跳过了这些状态，直接 GRANTED 或 REJECTED。这是合理的——identd 在现代网络基本不用了。

---

## 测试覆盖亮点

- ✅ CONNECT 命令解析：完整字节流解析验证
- ✅ BIND 命令解析：验证命令码识别
- ✅ 空 userid：即只有 NULL 字节的情况
- ✅ 命令码穷举：0x01/0x02 有对应，0x00/0x03/0xFF 返回 None
- ✅ SOCKS4Reply Display：格式化输出测试
- ✅ 地址到 SocketAddr 转换：端口一致性验证

---

## 重要发现：代码中潜在 BUG

`bridge_connections` 方法只单向转发：

```rust
// 只做了 target → client
let mut buf = vec![0u8; 8192];
loop {
    let n = target_reader.read(&mut buf).await?;
    if n == 0 { break; }
    client_writer.write_all(&buf[..n]).await?;
}
```

**应该是双向的**，正确的实现参考 shadowsocks.rs 的 relay：
```rust
tokio::try_join!(
    copy(&mut cr, &mut rw),  // client → remote
    copy(&mut rr, &mut cw)   // remote → client
);
```

这意味着如果 SOCKS4 BIND 模式下客户端要往服务器发数据，这个桥接是无效的。**优先级：低**（dae-rs 中 SOCKS4 主要用于出口，不是核心场景）。

---

## 关联笔记

- 参考：`008-socks5.md`（SOCKS5 是 SOCKS4 的全面升级版）
- 参考：`019-shadowsocks.md`（SS 协议，对比加密实现）
- 参考：`012-tun.md`（SOCKS4 出口在网络栈中的位置）

---

*本笔记基于 dae-rs socks4.rs (约450行) 生成，学习时间：2026-04-05*
