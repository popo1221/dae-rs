//! dae-tc eBPF Maps 模块
//!
//! 定义 dae-tc 程序使用的所有 eBPF Map，包括连接跟踪、路由规则、DNS 映射和统计计数。
//!
//! # Map 类型一览
//!
//! | Map 名称      | 类型          | Key 类型              | Value 类型         | 用途                   |
//! |--------------|---------------|----------------------|--------------------|------------------------|
//! | SESSIONS     | HashMap       | SessionKey (5元组)    | SessionEntry       | TCP/UDP 连接跟踪        |
//! | ROUTING      | LpmTrie       | u32 (IP 前缀)        | RoutingEntry       | CIDR 路由规则           |
//! | DNS_MAP      | HashMap       | u64 (域名 DJB2 哈希) | DnsMapEntry        | 域名→IP 映射            |
//! | IP_DOMAIN_MAP| HashMap       | u32 (IP)             | u64 (域名哈希)      | IP→域名反向查询          |
//! | CONFIG       | Array         | u32 (索引)           | ConfigEntry        | 全局配置（启用/禁用）    |
//! | STATS        | PerCpuArray   | u32 (协议索引)        | StatsEntry         | 流量统计                 |
//!
//! # LpmTrie（最长前缀匹配 Trie）
//!
//! ROUTING Map 使用 LpmTrie 而非普通 HashMap，以支持 CIDR notation：
//! - 键为 `(prefix_length, IP)` 元组
//! - 查询时内核自动返回最长匹配前缀的规则
//! - 例如：查询 `10.1.2.3` 时，规则 `10.0.0.0/8` 和 `10.1.0.0/16` 均匹配，
//!   但 `10.1.0.0/16` 更精确（16 > 8），返回该规则
//!
//! # HashMap vs PerCpuArray
//!
//! - **HashMap**（SESSIONS、ROUTING、DNS_MAP）：支持任意数量条目，查询 O(1)
//! - **PerCpuArray**（STATS）：固定容量，每个 CPU 核心独立计数，更新无锁
//!
//! # 与 dae-xdp 的区别
//!
//! dae-tc 比 dae-xdp 多了两个 Map：
//! - `DNS_MAP`：域名到 IP 的映射（dae-xdp 不做 DNS 相关处理）
//! - `IP_DOMAIN_MAP`：IP 到域名的反向映射（用于按 IP 查域名）

/// Re-export statistics indices from dae-ebpf-common
pub use dae_ebpf_common::stats::idx;

/// 默认路由条目键（catch-all，前缀长度为 0）
///
/// 在 ROUTING LpmTrie 中，`/0` 前缀匹配任何 IP 地址。
/// 用于实现"未匹配任何规则时"的默认动作（通常是 PASS）。
///
/// # 用法
///
/// ```ignore
/// let key = Key::new(0, DEFAULT_ROUTE_KEY);  // 前缀=0，IP=0
/// let default_route = ROUTING.get(&key);
/// ```
pub const DEFAULT_ROUTE_KEY: u32 = 0;

/// 从域名生成 DNS Map 键
///
/// 使用 DJB2 哈希算法将域名转换为 64 位哈希键，
/// 用于 DNS_MAP HashMap 的键。
///
/// # 参数
///
/// * `domain` - 域名字节数组（例如 `b"example.com"`）
///
/// # 返回值
///
/// 64 位无符号整数哈希键
///
/// # 算法
///
/// DJB2 算法：
/// ```
/// hash = 5381
/// for each byte b in domain:
///     hash = hash * 33 + b
/// ```
/// 初始值 5381 和乘数 33 是 Daniel J. Bernstein 提出的经典参数，
/// 对 DNS 域名模式有良好的哈希分布。
///
/// # 注意事项
///
/// - DJB2 不是加密哈希，可能存在碰撞，但对 DNS 查图场景可接受
/// - 域名应使用小写形式，哈希对大小写敏感
/// - 建议域名最长不超过 253 字节（DNS 标准限制）
pub fn dns_key(domain: &[u8]) -> u64 {
    let mut key: u64 = 5381;
    for &b in domain {
        // DJB2 hash algorithm
        key = key.wrapping_mul(33).wrapping_add(b as u64);
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_key() {
        let key1 = dns_key(b"example.com");
        let key2 = dns_key(b"example.com");
        assert_eq!(key1, key2);

        let key3 = dns_key(b"google.com");
        assert_ne!(key1, key3);
    }
}
