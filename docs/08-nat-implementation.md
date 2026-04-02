# Full-Cone NAT 实现 - 功能描述

## 概述
Full-Cone NAT (NAT1) 是一种 NAT 映射类型，任何外部主机都可以向映射后的外部地址发送数据包，只要内部主机曾经向该外部主机发送过数据包。

## NAT 类型对比

| NAT 类型 | 内部->外部 | 外部->内部 | 安全性 | P2P 友好度 |
|----------|------------|------------|--------|------------|
| Full-Cone | ✅ | 任何主机 | 低 | 非常高 |
| Address-Restricted | ✅ | 仅目标 IP | 中 | 高 |
| Port-Restricted | ✅ | 仅目标 IP:Port | 高 | 中 |
| Symmetric | ✅ | 仅该连接 | 最高 | 低 |

## 流程图/数据流

### Full-Cone NAT 映射流程
```
内部请求: 192.168.1.100:12345 -> 8.8.8.8:53
     |
     v
分配外部端口: 203.0.113.50:54321
     |
     v
创建映射: (192.168.1.100:12345) <-> (203.0.113.50:54321)
     |
     v
转发请求到 8.8.8.8:53
```

### 外部响应流程
```
8.8.8.8:53 -> 203.0.113.50:54321
     |
     v
查找映射: 203.0.113.50:54321 -> 192.168.1.100:12345
     |
     v
转发到内部主机 (任何外部主机都可以！)
```

## 配置项

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `external_ip` | IpAddr | 0.0.0.0 | 外部 IP 地址 |
| `port_range_start` | u16 | 10000 | 端口范围起始 |
| `port_range_end` | u16 | 65535 | 端口范围结束 |
| `mapping_ttl` | Duration | 300s | 映射 TTL |
| `max_mappings` | usize | 65535 | 最大映射数 |

## 接口设计

### 核心 trait/struct
- `struct NatMapping`: NAT 映射条目
  - `internal: SocketAddr`: 内部地址
  - `external: SocketAddr`: 外部地址
  - `created_at: Instant`: 创建时间
  - `expires_at: Instant`: 过期时间
  - `allowed_remotes: Vec<SocketAddr>`: 允许的远程地址 (Full-Cone 为空)
  - `is_active: bool`: 是否活跃
- `struct NatStats`: NAT 统计
  - `mappings_created`: 总创建映射数
  - `packets_forwarded`: 转发数据包数
  - `packets_dropped`: 丢弃数据包数
  - `active_mappings`: 当前活跃映射数
- `struct FullConeNat`: Full-Cone NAT 实现
- `struct FullConeNatUdpHandler`: UDP handler

### 公开方法
- `fn FullConeNat::new(config)`: 创建 NAT 实例
- `fn FullConeNat::create_mapping(internal) -> Result<external>`: 创建映射
- `fn FullConeNat::find_internal(external) -> Option<internal>`: 查找内部地址
- `fn FullConeNat::remove_mapping(internal)`: 移除映射
- `fn FullConeNat::cleanup_expired() -> usize`: 清理过期映射
- `fn FullConeNat::get_stats() -> NatStats`: 获取统计
- `fn FullConeNat::get_active_mappings() -> Vec<NatMapping>`: 获取活跃映射
- `fn FullConeNatUdpHandler::handle_outgoing(internal, target) -> external`: 处理外出 UDP
- `fn FullConeNatUdpHandler::handle_incoming(external, from) -> Option<internal>`: 处理进入 UDP

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `AddrInUse` | 端口耗尽 | 等待清理或扩大端口范围 |
| `MaxMappingsReached` | 超过最大映射数 | 等待过期清理 |

## 安全性考虑

1. **端口预分配**: 端口分配时检查是否已使用，避免冲突
2. **TTL 管理**: 映射自动过期，防止资源泄漏
3. **Full-Cone 限制**: 映射仅对发起过连接的外部 IP 有效
4. **P2P 应用**: Full-Cone NAT 最适合 P2P 应用如 VoIP、游戏
