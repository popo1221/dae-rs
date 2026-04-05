# 019 - Shadowsocks.rs 费曼学习笔记

> **一行总结（10岁版本）**：Shadowsocks 是一个加密的"邮件转发员"——它把你的网络请求装进一个加密信封里，寄到远方的服务器，服务器拆开信封帮你送信去目的地，这样别人就不知道你在访问什么了。

---

## 简化法则自检（6项检查）

| # | 检查项 | 状态 | 说明 |
|---|--------|------|------|
| 1 | **删除行话** | ✅ | 已将 ATYP/SsCipherType 等术语还原为"地址类型/加密方式" |
| 2 | **找准比喻** | ✅ | 加密信封比喻：SS 客户端=寄信人，SS 服务器=远方邮局 |
| 3 | **分块消化** | ✅ | 协议解析→连接建立→数据转发三大块 |
| 4 | **外婆验证** | ✅ | 她能听懂"信封里的信纸写着你真正想去哪" |
| 5 | **没有黑话** | ✅ | 术语旁均附通俗解释 |
| 6 | **逻辑连贯** | ✅ | 从收到请求→解密→连接目标→回信，完整链路无跳跃 |

---

## 外婆能听懂的口语化讲解

想象你要寄一封情书给隔壁班的小明，但你不信任邮递员，怕他偷看。

**普通上网**：你直接写上小明的班级姓名，让邮递员送过去。邮递员（就是墙）一看："哦你要找小明"，直接把信没收了。

**Shadowsocks 上网**：你把情书塞进一个上锁的铁盒子里，锁的密码只有你和远方一个可信的朋友知道。你让邮递员把铁盒子寄到那个朋友那里。邮递员拿到盒子，看不到里面写的啥，只能寄过去。朋友收到后，用密码打开盒子，看到里面写着"帮我把这封信送给小明"，朋友就帮你送过去了。小明回信也是原路返回，朋友再把回信锁进盒子寄给你。

**daes-rs 里的 Shadowsocks** 就是实现这个"远方朋友"角色的代码。它只支持三种锁（chacha20-poly1305、aes-256-gcm、aes-128-gcm），而且**不支持**老式的那种弱锁（比如 rc4-md5），因为弱锁真的很不安全。

---

## 专业结构分析

### 核心数据流

```
Client → [AEAD Header + Length Prefix] → SS Handler
                                              ↓
                                    TargetAddress::parse_from_aead
                                              ↓
                                    解析目标地址（IPv4/Domain/IPv6）
                                              ↓
                                    连接 SS 服务器
                                              ↓
                                    tokio::io::copy 双向转发
```

### 核心数据结构

| 结构体 | 职责 | 关键字段 |
|--------|------|----------|
| `SsCipherType` | 枚举加密方式 | chacha20-ietf-poly1305 / aes-256-gcm / aes-128-gcm |
| `SsServerConfig` | SS 服务器配置 | addr, port, method, password, ota |
| `SsClientConfig` | SS 客户端配置 | listen_addr, server, tcp_timeout, udp_timeout |
| `TargetAddress` | 目标地址联合体 | IPv4(0x01) / Domain(0x03) / IPv6(0x04) |
| `ShadowsocksHandler` | SS 连接处理器 | handle() 主入口，relay() 双向转发 |
| `ShadowsocksServer` | SS 服务器监听器 | start() 循环 accept |

### AEAD 协议格式

```
AEAD TCP 首包格式：
[1B type=0x01][2B length][加密payload]

AEAD UDP 格式：
[ATYP][地址][端口][加密payload]
```

### TargetAddress 解析

地址类型 byte (`atyp`) 决定后续格式：
- `0x01` → IPv4：1字节类型 + 4字节IP + 2字节端口 = 7字节
- `0x03` → Domain：1字节类型 + 1字节长度 + N字节域名 + 2字节端口 = 4+N 字节
- `0x04` → IPv6：1字节类型 + 16字节IP + 2字节端口 = 19字节

### 协议限制

⚠️ **重要**：当前实现**未完整实现 AEAD 解密**，handle() 里 `TargetAddress::parse_from_aead` 直接解析的是明文 payload（注释写了"for testing/non-encrypted mode"）。完整实现需要在 parse 之前调用 AEAD 解密（HMAC-SHA256 → AES-256-GCM / ChaCha20-Poly1305 解密）。

---

## 关键调用链追溯

### TCP 处理链路

```
ShadowsocksServer::start()
  └─ listener.accept()
      └─ handler.handle(client_stream)
          ├─ read_exact(1B) → header_type
          ├─ read_exact(2B) → payload_len (BE u16)
          ├─ read_exact(payload_len) → encrypted_payload
          ├─ TargetAddress::parse_from_aead(&encrypted_payload)
          │   ├─ atyp == 0x01 → IPv4 解析
          │   ├─ atyp == 0x03 → Domain 解析
          │   └─ atyp == 0x04 → IPv6 解析
          ├─ TcpStream::connect(remote_server)
          └─ relay(client, remote)
              └─ tokio::try_join!(
                    copy(&mut cr, &mut rw),  // client → remote
                    copy(&mut rr, &mut cw)    // remote → client
                  )
```

### UDP 处理链路

```
ShadowsocksHandler::handle_udp(client_socket)
  └─ loop { recv_from(buf) }
      ├─ atyp 解析（IPv4/Domain/IPv6）
      ├─ payload_offset 计算
      └─ send_to(server) + recv_from(server) → send_to(client)
```

### 插件支持（未来扩展）

```
plugin/
ssr/  ← ShadowsocksR（另一个衍生协议）
```

---

## 设计取舍说明

### 1. 只支持 AEAD，不支持 Stream Cipher

**取舍**：安全性优先。

流密码（如 rc4-md5、aes-ctr）有已知的**字节流向攻击**弱点。AEAD（Authenticated Encryption with Associated Data）同时提供加密和完整性验证，更安全。代价是 CPU 开销稍高，但现代 CPU 有硬件加速，影响可忽略。

### 2. TargetAddress 用枚举而非 struct 继承

**取舍**：Rust 风格简单枚举 > 继承。

```rust
enum TargetAddress {
    Ip(IpAddr),           // IPv4 或 IPv6
    Domain(String, u16),  // 域名 + 端口
}
```

匹配模式清晰，parse/serialize 各路径独立，无虚函数开销。

### 3. relay() 使用 `tokio::io::copy` 双向复制

**取舍**：简洁正确 > 极致性能。

```rust
tokio::try_join!(client_to_remote, remote_to_client)?;
```

用 `try_join!` 保证双向同时进行。如果自己做 buffer 管理、边缘情况处理，容易出 bug。tokio 的 copy 在这里足够用。

### 4. UDP 使用简单 loop 而非连接池

**取舍**：实现简单 > 复杂优化。

每次收到 UDP 包都新建 server socket 再销毁。理论上连接池更好，但 SS 的 UDP 场景（DNS、游戏包）session 短，连接池收益不大，徒增复杂度。

### 5. handle() 里 AEAD 解密未实现

**取舍**：框架先行，密码学实现留待专家。

代码注释明确写了"For a full implementation, decryption would happen here"。地址解析已经做好，解密部分需要正确的 AEAD decryption context（nonce + key + tag），这涉及复杂的密码学实现，容易出错，适合后续专项完成。

---

## 测试覆盖亮点

- ✅ 加密方式三剑客：chacha20/aes-256/aes-128 解析测试
- ✅ IPv4 解析：`192.168.1.1:8080` → 确认 port 正确
- ✅ Domain 解析：`example.com:80` → 确认长度字段处理
- ✅ IPv6 解析：完整的 16 字节段解析
- ✅ 截断检测：payload 太短时返回 None
- ✅ 域名长度不匹配：长度字段说11但实际只有3字节 → None

---

## 关联笔记

- 参考：`008-socks5.md`（SOCKS5 协议，更复杂但更完整）
- 参考：`012-tun.md`（TUN 模块，SS 所在的网络层级）
- 参考：`011-vmess.md`（AEAD 加密模式类似，可对比学习）

---

*本笔记基于 dae-rs shadowsocks.rs (约500行) 生成，学习时间：2026-04-05*
