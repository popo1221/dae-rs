# DNS 系统 - 功能描述

## 概述
dae-rs 提供基于 MAC 地址的 DNS 解析和循环检测功能，可以根据设备 MAC 地址选择不同的上游 DNS 服务器，并自动检测 DNS 循环。

## 模块结构

### 1. mac_dns - MAC 地址DNS解析
基于源 MAC 地址选择 DNS 服务器，实现不同设备使用不同 DNS 上游。

### 2. loop_detection - DNS 循环检测
自动检测上游 DNS 服务器是否是 dae-rs 客户端，防止 DNS 查询无限循环。

## 流程图/数据流

### DNS 循环检测流程
```
DNS Query -> Check Upstream Loop -> Check Source Loop -> Forward/Block
     |
     v
Upstream IP in Client Range? -> YES -> 添加 SIP 规则建议
Source IP in Client Range? -> YES -> 添加 SIP 规则建议
```

### MAC DNS 解析流程
```
Client MAC -> 查找 MAC-DNS Rule -> 选择对应 DNS Server -> 发起 DNS 查询
```

## 配置项

### LoopDetectionConfig
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `check_upstream` | bool | true | 检测上游循环 |
| `check_source` | bool | true | 检测源循环 |
| `known_client_ranges` | Vec<String> | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 | 已知客户端网段 |
| `notification_url` | Option<String> | None | 通知回调 URL |

### MacDnsConfig
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `mac_rules` | Vec<MacDnsRule> | [] | MAC 地址规则列表 |
| `default_dns` | Vec<IpAddr> | 8.8.8.8, 1.1.1.1 | 默认 DNS 服务器 |

## 接口设计

### 核心 trait/struct
- `enum LoopDetectionResult`: 循环检测结果
  - `NoLoop`: 无循环
  - `UpstreamIsClient { upstream, suggestion }`: 上游是客户端
  - `SourceIsReachable { source, suggestion }`: 源可到达
- `struct DnsCacheEntry`: DNS 缓存条目
- `struct DnsResolution`: DNS 解析结果
- `struct MacDnsRule`: MAC DNS 规则
- `struct MacDnsResolver`: MAC DNS 解析器

### 公开方法
- `fn DnsLoopDetector::new(config)`: 创建检测器
- `fn DnsLoopDetector::check_upstream_loop(ip)`: 检测上游循环
- `fn DnsLoopDetector::check_source_loop(ip)`: 检测源循环
- `fn DnsLoopDetector::check(upstream, source)`: 同时检测
- `fn DnsLoopDetector::clear_detected_loops()`: 清除已检测循环
- `fn DnsLoopDetector::get_detected_loops()`: 获取已检测循环列表
- `fn MacDnsResolver::resolve(mac, domain)`: 基于 MAC 解析域名

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `LoopDetected` | 检测到循环 | 记录警告，添加 SIP 规则建议 |
| `DnsError` | DNS 解析失败 | 使用备用 DNS |
| `MacNotFound` | MAC 地址不在规则中 | 使用默认 DNS |

## 安全性考虑

1. **循环预防**: 自动检测并警告 DNS 循环，避免路由黑洞
2. **SIP 规则建议**: 当检测到循环时，提供 SIP 规则建议修复
3. **私有地址保护**: 已知客户端网段用于识别内网设备
4. **通知机制**: 支持 HTTP 回调通知管理员
