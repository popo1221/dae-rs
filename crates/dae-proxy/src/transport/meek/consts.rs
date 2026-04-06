//! Meek constants and types

/// Meek obfuscation tactic
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MeekTactic {
    /// HTTP proxy through front domain
    Http,
    /// HTTPS proxy through front domain
    Https,
    /// Length-encoded requests with padding (default)
    #[default]
    Bytepolding,
    /// Session ticket ID obfuscation (Azure)
    Snia,
    /// Pattern-based obfuscation
    Patterns,
    /// Simple tunnel with greeting
    Gimmie,
    /// Server-side redirect following
    Redirect,
}

impl std::fmt::Display for MeekTactic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeekTactic::Http => write!(f, "http"),
            MeekTactic::Https => write!(f, "https"),
            MeekTactic::Bytepolding => write!(f, "bytepolding"),
            MeekTactic::Snia => write!(f, "snia"),
            MeekTactic::Patterns => write!(f, "patterns"),
            MeekTactic::Gimmie => write!(f, "gimmie"),
            MeekTactic::Redirect => write!(f, "redirect"),
        }
    }
}
