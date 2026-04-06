//! TUN 代理路由类型

/// 数据包路由结果
///
/// 表示数据包路由决策的结果。
#[derive(Debug, Clone)]
pub enum RouteResult {
    /// 数据包被丢弃
    Dropped,
    /// 数据包被转发（直连或代理）
    Forwarded,
    /// 数据包需要响应（例如 DNS 响应）
    Response(Vec<u8>),
}
