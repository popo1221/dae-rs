//! SOCKS5 authentication mechanisms (RFC 1928, RFC 1929)
//!
//! Supports NO_AUTH (0x00) and USERNAME/PASSWORD (0x02) authentication.

/// SOCKS5 username/password credentials
#[derive(Debug, Clone)]
pub struct UserCredentials {
    pub username: String,
    pub password: String,
}

/// SOCKS5 authentication handler trait
pub trait AuthHandler: Send + Sync {
    /// Check if authentication is required
    fn requires_auth(&self) -> bool;

    /// Validate credentials, returns true if valid
    fn validate_credentials(&self, username: &str, password: &str) -> bool;
}

/// No authentication handler - allows all connections
#[derive(Debug, Clone, Default)]
pub struct NoAuthHandler;

impl AuthHandler for NoAuthHandler {
    fn requires_auth(&self) -> bool {
        false
    }

    fn validate_credentials(&self, _username: &str, _password: &str) -> bool {
        true
    }
}

/// Username/password authentication handler
#[derive(Debug, Clone)]
pub struct UsernamePasswordHandler {
    credentials: std::collections::HashMap<String, String>,
}

impl UsernamePasswordHandler {
    pub fn new() -> Self {
        Self {
            credentials: std::collections::HashMap::new(),
        }
    }

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
    fn requires_auth(&self) -> bool {
        true
    }

    fn validate_credentials(&self, username: &str, password: &str) -> bool {
        self.credentials
            .get(username)
            .map(|p| p == password)
            .unwrap_or(false)
    }
}

/// Combined auth handler that supports both NO_AUTH and username/password
#[derive(Clone)]
pub struct CombinedAuthHandler {
    no_auth_allowed: bool,
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
    pub fn new() -> Self {
        Self {
            no_auth_allowed: true,
            username_password: None,
        }
    }

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
    fn requires_auth(&self) -> bool {
        !self.no_auth_allowed || self.username_password.is_some()
    }

    fn validate_credentials(&self, username: &str, password: &str) -> bool {
        if let Some(ref handler) = self.username_password {
            return handler.validate_credentials(username, password);
        }
        false
    }
}
