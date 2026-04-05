# CHANGELOG - eBPF Refactoring

> 📅 Date: 2026-04-05
> 📂 Module: dae-proxy / eBPF Integration
> 🎯 Status: Phase 1 Complete

---

## v0.2.0 | 2026-04-05 - eBPF Integration Refactor

### ✨ 新增

#### Kernel Version Detection
- **`KernelVersion`** 结构体：自动检测内核版本
  - 支持解析 `/proc/version` 或 `libc::uname`
  - **`capability()`** 方法返回 `KernelCapability` 枚举
  - 支持检测: None, BasicMaps, XdpOnly, FullTc, RingBuf, Full

- **`KernelCapability`** 枚举：内核 eBPF 能力分级
  - `None (0)`: 无 eBPF 支持
  - `BasicMaps (1)`: 基础 Maps (kernel 4.14+)
  - `XdpOnly (2)`: XDP 支持 (kernel 5.8+)
  - `FullTc (3)`: TC clsact + LpmTrie (kernel 5.10+)
  - `RingBuf (4)`: ringbuf + 稳定 LpmTrie (kernel 5.13+)
  - `Full (5)`: 完整功能 (kernel 5.17+)

- **`EbpfRuntime`** 枚举：eBPF 运行时状态
  - `Active`: 真实 eBPF 运行中
  - `Fallback`: 使用内存回退
  - `Uninitialized`: 未初始化

- **`EbpfContext`** 结构体：eBPF 上下文管理器
  - `new(interface, ebpf_obj_path)` 异步初始化
  - 自动检测内核能力并选择最佳运行模式
  - 支持 TC clsact 和 XDP 两种程序类型
  - 自动降级到内存回退（当 eBPF 不可用时）

#### eBPF Program Types
- **`EbpfProgramType`** 枚举：支持 TC 和 XDP 两种程序类型
  - `Tc`: TC clsact qdisc（推荐用于透明代理）
  - `Xdp`: XDP express path（高性能但路由受限）
  - `MapsOnly`: 仅 Maps，无程序

#### Cargo.toml 依赖
```toml
aya = { version = "0.13", features = ["async"] }
aya-log = "0.13"
```

### 🔧 修改

#### `EbpfMaps` 结构体
- 新增 `is_real_ebpf` 字段标识是否使用真实 eBPF
- 新增 `set_real_ebpf()` 方法（内部使用）
- 保持向后兼容：`new()`, `new_in_memory()`, `default()` 均正常工作

#### `SessionMapHandle`, `RoutingMapHandle`, `StatsMapHandle`
- 保持原有 HashMap 实现作为 fallback
- 保留完整的 insert/lookup/remove/get/increment 等方法
- 所有现有测试保持通过

#### 错误类型扩展
- `EbpfError` 新增变体：
  - `EbpfNotAvailable(String)`: eBPF 不可用
  - `KernelNotSupported(String)`: 内核版本不支持
- 实现 `From<aya::BpfError>`, `From<aya::maps::MapError>`, `From<aya::program::ProgramError>`

### 🐛 修复

- 修复 `RoutingMapHandle::remove()` 方法添加了 `#[allow(dead_code)]` 属性
- 修复 `EbpfContext::try_init_ebpf()` 在 eBPF 对象文件不存在时正确返回 fallback
- 修复 `EbpfRuntime` 的 `is_active()` 和 `program_type()` 方法正确返回状态

### 📝 文档

- 更新模块文档说明架构变更
- 新增 eBPF Map 类型对比表
- 新增内核版本能力分级说明
- 添加 Mermaid 架构图引用

### 🔬 测试

- 新增 `KernelVersion` 相关测试：
  - `test_kernel_version_parse`: 版本字符串解析
  - `test_kernel_version_parse_edge_cases`: 边界情况
  - `test_kernel_capability_ordering`: 能力级别排序
  - `test_kernel_capability_display`: Display trait
  - `test_kernel_version_capability_detection`: 内核版本→能力检测

- 新增 `EbpfRuntime` 相关测试：
  - `test_ebpf_runtime_is_active`: 运行时状态检测

- 保持所有原有测试通过

---

## Architecture Changes

### Before (HashMap Stub)
```
┌─────────────────────────────────────────────────────────────┐
│                    ebpf_integration.rs                       │
│  SessionMapHandle → Arc<StdRwLock<HashMap>>                 │
│  RoutingMapHandle → Arc<StdRwLock<HashMap>> (exact match)   │
│  StatsMapHandle   → Arc<StdRwLock<HashMap>>                 │
└─────────────────────────────────────────────────────────────┘
```

### After (aya eBPF + Fallback)
```
┌─────────────────────────────────────────────────────────────┐
│                      EbpfContext                            │
│  ├─ kernel_version: KernelVersion (自动检测)                │
│  ├─ runtime: EbpfRuntime (Active/Fallback/Uninitialized)   │
│  ├─ ebpf_maps: Option<aya::Ebpf> (真实 eBPF)               │
│  └─ fallback_maps: EbpfMaps (内存回退)                     │
│                                                              │
│  EbpfContext::new()                                          │
│    ├─ 检测内核版本                                           │
│    ├─ 尝试加载 eBPF 程序 (TC 或 XDP)                        │
│    └─ 失败时自动降级到 fallback                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Migration Path

### Phase 1 (Current) ✅
- [x] 内核版本检测
- [x] KernelCapability 分级
- [x] EbpfRuntime 状态机
- [x] EbpfContext 管理器
- [x] 内存回退保持兼容
- [x] TC clsact 挂载逻辑
- [x] XDP 挂载逻辑

### Phase 2 (Next)
- [ ] 实现 `AyaSessionMapHandle` (真实 aya HashMap)
- [ ] 实现 `AyaRoutingMapHandle` (真实 aya LpmTrie)
- [ ] 实现 `AyaStatsMapHandle` (真实 aya PerCpuArray)

### Phase 3 (Future)
- [ ] ringbuf 事件通道集成
- [ ] 内核↔用户空间事件通知
- [ ] DNS Map 支持

---

## Breaking Changes

**无破坏性变更** - 所有现有 API 保持兼容：
- `EbpfMaps::new()` - 返回未初始化的 maps
- `EbpfMaps::new_in_memory()` - 返回内存回退 maps（默认）
- `SessionMapHandle::new()` - 返回内存 HashMap
- `RoutingMapHandle::new()` - 返回内存 HashMap
- `StatsMapHandle::new()` - 返回内存 HashMap

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| aya | 0.13 | User-space eBPF API |
| aya-log | 0.13 | eBPF 日志支持 |

---

## Related Issues

- GitHub Issue #73: Real eBPF Implementation
- Related: EBPF_REFACTOR_ARCH.md
