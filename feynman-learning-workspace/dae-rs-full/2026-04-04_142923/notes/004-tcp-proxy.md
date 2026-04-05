# 💻 费曼代码笔记：tcp.rs — TCP 透明代理核心

> 📅 学习日期：2026-04-04
> 📂 来源：packages/dae-proxy/src/tcp.rs
> 🏷️ 代码语言：Rust
> ⭐ Value_Score：8/10

## 一句话总结（10岁版本）

> 这个文件是"电话接线员"——把客户端打进来的电话（TCP连接），转接（relay）到目标服务器，同时把服务器的回话原封不动传回来。

---

## 简化法则自检

- [ ] 口语化讲解区全篇没有专业术语吗？
- [ ] 每个概念都有生活类比吗？
- [ ] 外婆能听懂吗？
- [ ] 数据流每个环节都能说清吗？
- [ ] 设计取舍（为什么这样做）讲清楚了吗？
- [ ] 副作用都列清楚了吗？

---

## 口语化讲解区（外婆版）

**TCP 中继（relay）是怎么工作的？**

想象一个翻译员：
- 客户端说中文（A），翻译员听完后用中文打电话给英文服务器（B）
- 服务器说英文（B），翻译员听完用英文打电话给客户端（A）

这个"翻译员"就是 `relay_connection` 的核心：两个方向的 `tokio::spawn` 任务同时跑，一个负责 A→B，一个负责 B→A。

**为什么用 `join_all` 或 `select!` 而不是顺序处理？**

因为 TCP 是全双工的——电话里两个人可以同时说话。如果一个人说完才轮到另一个人，就会卡死（head-of-line blocking）。所以两个方向要同时跑，不能串行。

**双工拆分流（`tokio::io::split`）是什么？**

把一条电话线拆成两条独立的线：一条只能听（read），一条只能说（write）。这样两个人可以同时说，不冲突。

**超时是怎么工作的？**

每次 read/write 都包在 `tokio_timeout(timeout_dur, ...)` 里——如果对方在规定时间内没说话（没发数据），就超时断开，防止连接永远挂着。

---

## 专业结构区（同行版）

### 宏观执行流程

**启动（`start()`）**：
1. 创建 TCP listener 在 `config.listen_addr` 监听
2. `loop` + `accept()` 等待客户端连接
3. 每收到一个客户端：`spawn` 一个 `handle_client` 任务

**处理（`handle_client()`）**：
1. 从连接池获取或新建连接（复用）
2. 更新 session 状态（New → Active）
3. 连接远程服务器
4. `relay_connection()` 做双向数据转发
5. 完成后清理（从池移除，状态改为 Closed）

**中继（`relay_connection()`）**：
1. `split` 拆成双向流
2. spawn 两个任务：client→remote 和 remote→client
3. `rx1.recv()` 等待任一方向出错
4. 第一个出错后 `abort()` 掉另一个任务，关闭连接

---

### 关键逻辑块

- **`tokio::io::split`**：把 `TcpStream` 拆成 `(AsyncRead, AsyncWrite)`，支持双向并发读写
- **`mpsc::channel` 单信道**：`tx1.send(Ok(()))` — 任意方向出错都往同一个 channel 发信号，两个任务共享 sender
- **`rx1.recv().await` 只等第一个**：`recv()` 等第一个消息，一旦收到就停止——只要有一方断开了，另一方也没必要继续
- **`Arc<Connection>` 双任务共享**：两个 relay 任务克隆同一个 `Arc`，各自拿 `Arc.write()` 拿锁更新 `touch()`（最后访问时间）

---

### 设计意图

- **为什么 relay 用两个独立 spawn 而不是 `tokio::io::copy`？** — `copy` 是半双工的，这里需要全双工（同时双向）；而且 relay 需要追踪 session 状态（更新 touch），`copy` 做不到
- **为什么用 `abort()` 而不是优雅等待？** — relay 场景下，一旦一方断开了，另一方的数据已经没有意义了，直接拔掉电源（abort）更快
- **为什么 client 和 remote 都用 64KB buffer？** — 平衡内存和性能，大多数网络 MTU 是 1500 bytes，64KB 是合理的吞度量

---

## 关键应用场景

**系统中做什么**：处理所有入口 TCP 流量——监听本地端口，接收用户连接，连接到目标服务器，双向转发数据，更新 eBPF session 状态。

**没了会怎样**：代理完全丧失 TCP 转发能力，UDP 代理可能仍工作但整体功能严重降级。

---

## 大白话总结（外婆版）

> tcp.rs 就是电话接线员——把客户打进来的电话（A → 接线员 → B），和服务器回的电话（B → 接线员 → A），同时接起来。
>
> 两个人可以同时说话（全双工），所以接线员有两条耳朵（client_read + remote_read）和两条嘴（client_write + remote_write）。一条耳朵听到对方说话，就往另一条嘴里传。
>
> 如果任何一方超时没说话，接线员就挂断两边电话（abort）。
