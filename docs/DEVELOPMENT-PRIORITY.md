# dae-rs 开发优先级列表

> 创建日期: 2026-04-02
> 基于: dae-rs vs Go dae 详细对比

---

## 一、高优先级（核心协议支持）

### 1. SOCKS4/4a 支持
**优先级**: P0
**原因**: Go dae 基础协议，dae-rs 缺失
**工作内容**:
- 实现 SOCKS4 协议 handler
- 实现 SOCKS4a 协议 handler（支持域名解析）
- 添加 `socks4://` 和 `socks4a://` URI 支持
- 配置解析支持
- 单元测试

**文件预估**:
- `packages/dae-proxy/src/socks4.rs` (~400行)
- `packages/dae-proxy/src/protocol/socks4/` (~200行)

---

### 2. ShadowsocksR (SSR)
**优先级**: P1
**原因**: 国内常用协议，Go dae 有完整实现
**工作内容**:
- 完善 `ssr.rs` 现有代码
- 实现协议混淆（obfs）支持
- 实现 STCP 和 SSTP 协议
- SSR URI 解析支持
- 完善单元测试

**文件**: `packages/dae-proxy/src/shadowsocks/ssr.rs`

---

## 二、中优先级（扩展传输）

### 3. VLESS gRPC 传输支持
**优先级**: P2
**原因**: VLESS 配套传输方式
**工作内容**:
- 实现 gRPC transport
- 实现 HTTP/2 支持
- 添加 `grpc://` 和 `h2://` URI 支持
- TLS 配置完善

**文件预估**:
- `packages/dae-proxy/src/transport/grpc.rs` (~300行)
- `packages/dae-proxy/src/vless.rs` 修改

---

### 4. Meek 传输支持
**优先级**: P2
**原因**: 抗封锁传输方式
**工作内容**:
- 实现 HTTP/2 meek tactics
- 实现云端欺骗请求
- 实现连接池管理

---

### 5. HTTPUpgrade 传输
**优先级**: P2
**原因**: VLESS 配套传输方式
**工作内容**:
- 实现 HTTP Upgrade 协议
- WebSocket 握手优化
- 头部伪装完善

---

## 三、低优先级（增强功能）

### 6. NaiveProxy 集成
**优先级**: P3
**原因**: Go dae 通过外部程序支持，dae-rs 可作为增强功能
**工作内容**:
- 外部程序管理接口
- HTTP/2 优化
- 混淆增强

---

### 7. SIP008 订阅规范
**优先级**: P3
**原因**: Shadowsocks 订阅更新增强
**工作内容**:
- SIP008 URI 解析
- 订阅更新逻辑
- 节点过滤规则

---

## 四、已完成功能（里程碑）

| 功能 | 状态 | PR/Commit |
|------|------|-----------|
| NodeCapabilities | ✅ 完成 | PR #49 |
| 用户空间日志 | ✅ 完成 | PR #48 |
| MACv2 提取 | ✅ 完成 | PR #48 |
| Full-Cone NAT | ✅ 完成 | PR #46 |
| DNS 循环检测 | ✅ 完成 | PR #46 |
| AnyTLS | ✅ 完成 | master |
| Proxy Chain | ✅ 完成 | master |
| VLESS Reality | ✅ 完成 | master |

---

## 开发顺序建议

1. **SOCKS4/4a** → 最基础协议，用户需求高
2. **ShadowsocksR** → 国内用户常用
3. **gRPC** → VLESS 配套
4. **Meek** → 抗封锁
5. **HTTPUpgrade** → VLESS 配套
6. **NaiveProxy** → 增强功能
7. **SIP008** → 订阅增强

---

## 资源估算

| 功能 | 预估工时 | 预估代码行数 |
|------|----------|--------------|
| SOCKS4/4a | 1-2天 | ~600行 |
| ShadowsocksR | 2-3天 | ~800行 |
| gRPC | 1-2天 | ~400行 |
| Meek | 2-3天 | ~600行 |
| HTTPUpgrade | 1天 | ~300行 |
| NaiveProxy | 2天 | ~400行 |
| SIP008 | 1天 | ~200行 |

**总计**: ~10-14 天开发时间，~3100 行代码
