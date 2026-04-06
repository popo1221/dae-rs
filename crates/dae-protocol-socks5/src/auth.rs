//! SOCKS5 认证机制模块（RFC 1928, RFC 1929）
//!
//! 支持 NO_AUTH（无需认证）和 USERNAME/PASSWORD（用户名/密码认证）。

/// 用户名/密码凭证
///
/// 用于 SOCKS5 用户名/密码认证。
#[derive(Debug, Clone)]
pub struct UserCredentials {
    /// 用户名
    pub username: String,
    /// 密码
    pub password: String,
}

/// SOCKS5 认证处理器特征
///
/// 定义 SOCKS5 认证处理器必须实现的行为。
///
/// # 设计原则
///
/// - `Send + Sync`: 实现必须是线程安全的
/// - 无状态: 处理器不保存连接状态
pub trait AuthHandler: Send + Sync {
    /// 检查是否需要认证
    ///
    /// # 返回值
    /// - `true`: 需要认证（需要客户端提供凭证）
    /// - `false`: 无需认证（接受所有连接）
    fn requires_auth(&self) -> bool;

    /// 验证凭证
    ///
    /// # 参数
    /// - `username`: 用户名
    /// - `password`: 密码
    ///
    /// # 返回值
    /// - `true`: 凭证有效
    /// - `false`: 凭证无效
    fn validate_credentials(&self, username: &str, password: &str) -> bool;
}

/// 无需认证处理器
///
/// 接受所有连接，不进行任何认证检查。
#[derive(Debug, Clone, Default)]
pub struct NoAuthHandler;

impl AuthHandler for NoAuthHandler {
    /// NO_AUTH 不需要认证
    fn requires_auth(&self) -> bool {
        false
    }

    /// 接受所有凭证（虽然不会调用）
    fn validate_credentials(&self, _username: &str, _password: &str) -> bool {
        true
    }
}

/// 用户名/密码认证处理器
///
/// 基于 RFC 1929 的用户名/密码认证。
#[derive(Debug, Clone)]
pub struct UsernamePasswordHandler {
    /// 凭证存储（用户名 -> 密码）
    credentials: std::collections::HashMap<String, String>,
}

impl UsernamePasswordHandler {
    /// 创建新的用户名/密码处理器
    pub fn new() -> Self {
        Self {
            credentials: std::collections::HashMap::new(),
        }
    }

    /// 添加用户
    ///
    /// # 参数
    /// - `username`: 用户名
    /// - `password`: 密码
    pub fn add_user(&mut self, username: &str, password: &str) {
        self.credentials
            .insert(username.to_string(), password.to_string());
    }
}

impl Default for UsernamePasswordHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthHandler for UsernamePasswordHandler {
    /// 用户名/密码认证需要认证
    fn requires_auth(&self) -> bool {
        true
    }

    /// 验证用户名和密码
    ///
    /// # 参数
    /// - `username`: 用户名
    /// - `password`: 密码
    ///
    /// # 返回值
    /// - `true`: 用户存在且密码匹配
    /// - `false`: 用户不存在或密码不匹配
    fn validate_credentials(&self, username: &str, password: &str) -> bool {
        self.credentials
            .get(username)
            .map(|p| p == password)
            .unwrap_or(false)
    }
}

/// 组合认证处理器
///
/// 支持同时启用 NO_AUTH 和用户名/密码认证。
///
/// # 使用场景
///
/// 允许部分用户使用用户名/密码认证，同时允许其他用户免认证访问。
#[derive(Clone)]
pub struct CombinedAuthHandler {
    /// 是否允许无认证访问
    no_auth_allowed: bool,
    /// 用户名/密码处理器（可选）
    username_password: Option<UsernamePasswordHandler>,
}

impl std::fmt::Debug for CombinedAuthHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CombinedAuthHandler")
            .field("no_auth_allowed", &self.no_auth_allowed)
            .field(
                "username_password",
                &self.username_password.as_ref().map(|_| "***"),
            )
            .finish()
    }
}

impl CombinedAuthHandler {
    /// 创建新的组合认证处理器
    ///
    /// 允许无认证访问，不启用用户名/密码认证。
    pub fn new() -> Self {
        Self {
            no_auth_allowed: true,
            username_password: None,
        }
    }

    /// 创建带有用户名/密码认证的处理器
    ///
    /// # 参数
    /// - `users`: 用户名和密码对列表
    ///
    /// # 示例
    ///
    /// ```ignore
    /// let handler = CombinedAuthHandler::with_username_password(vec![
    ///     ("user1".to_string(), "pass1".to_string()),
    ///     ("user2".to_string(), "pass2".to_string()),
    /// ]);
    /// ```
    pub fn with_username_password(users: Vec<(String, String)>) -> Self {
        let mut handler = UsernamePasswordHandler::new();
        for (username, password) in users {
            handler.add_user(&username, &password);
        }
        Self {
            no_auth_allowed: true,
            username_password: Some(handler),
        }
    }

    /// 设置是否允许无认证访问
    ///
    /// # 参数
    /// - `allowed`: true 表示允许无认证访问
    pub fn no_auth_allowed(mut self, allowed: bool) -> Self {
        self.no_auth_allowed = allowed;
        self
    }
}

impl Default for CombinedAuthHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthHandler for CombinedAuthHandler {
    /// 检查是否需要认证
    ///
    /// 当 no_auth_allowed 为 false 且没有用户名/密码配置时才需要认证。
    fn requires_auth(&self) -> bool {
        !self.no_auth_allowed || self.username_password.is_some()
    }

    /// 验证凭证
    ///
    /// 委托给内部的用户名/密码处理器。
    fn validate_credentials(&self, username: &str, password: &str) -> bool {
        if let Some(ref handler) = self.username_password {
            return handler.validate_credentials(username, password);
        }
        false
    }
}
