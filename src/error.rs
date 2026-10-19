use std::borrow::Cow;
use thiserror::Error;

use crate::exit;

/// Typed error so the CLI can map command failures to the right exit code and
/// machine-readable error code without inspecting message strings.
#[derive(Debug, Error)]
pub enum AkmError {
    /// User-supplied input is invalid (bad value, malformed name). Exit 3.
    #[error("{0}")]
    BadInput(String),

    /// A parse error; `suggestion` lists what the failing command accepts.
    /// Neither field ever contains the offending argv token. Exit 3.
    #[error("{message}")]
    Usage { message: String, suggestion: String },

    /// `guard scan` found candidate secrets; `details.hits` names them. Exit 3.
    #[error("possible secrets staged for commit")]
    SecretsStaged(serde_json::Value),

    /// Key not found in the Keychain. Exit 6.
    #[error("{0}")]
    NotFound(String),

    /// A requested key is missing; `details.candidates` names similar stored
    /// keys (names only) so the caller can retry without listing. Exit 6.
    #[error("{message}")]
    MissingKey {
        message: String,
        suggestion: String,
        details: serde_json::Value,
    },

    /// Keychain missing, locked, or refusing access without UI. Exit 2.
    #[error("{0}")]
    KeychainUnavailable(String),

    /// `doctor` found failing checks; the full report is in `details`. Exit 2.
    #[error("doctor found failing checks")]
    Diagnostics(serde_json::Value),

    /// Only reachable through the hidden `contract` hook. Exit 4.
    #[error("{0}")]
    RateLimited(String),

    /// Anything else: IO, FFI, upstream process. Exit 1.
    #[error("{0}")]
    Internal(#[from] anyhow::Error),
}

impl AkmError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::BadInput(_) | Self::Usage { .. } | Self::SecretsStaged(_) => exit::BAD_INPUT,
            Self::NotFound(_) | Self::MissingKey { .. } => exit::NOT_FOUND,
            Self::KeychainUnavailable(_) | Self::Diagnostics(_) => exit::SETUP,
            Self::RateLimited(_) => exit::RATE_LIMITED,
            Self::Internal(_) => exit::TRANSIENT,
        }
    }

    pub fn suggestion(&self) -> Cow<'static, str> {
        match self {
            Self::BadInput(_) => "Check accepted arguments with `akm <command> --help` or `akm agent-info --command <command>`.".into(),
            Self::Usage { suggestion, .. } | Self::MissingKey { suggestion, .. } => {
                suggestion.clone().into()
            }
            Self::SecretsStaged(_) => "Remove the values listed in error.details.hits from the staged files and store them with `akm add NAME`; bypass with `git commit --no-verify` only for intentional examples.".into(),
            Self::NotFound(_) => "Use `akm list` to find the stored name, or supply the value to `akm add NAME` through stdin.".into(),
            Self::KeychainUnavailable(_) => "Run `akm doctor`. Unlock your existing login Keychain and keep HOME set to your macOS account home; do not reset the Keychain. After upgrading from an unsigned AKM, use `akm migrate --from /path/to/old/akm`.".into(),
            Self::Diagnostics(_) => "Fix the failed checks listed in error.details, then run `akm doctor` again.".into(),
            Self::RateLimited(_) => "Wait, then retry only if the operation is safe to repeat.".into(),
            Self::Internal(_) => "Check the named resource, executable, or macOS Keychain access. Check the operation outcome before retrying a write.".into(),
        }
    }

    /// Whether repeating the same request unchanged can succeed; `None` when
    /// that depends on an outcome AKM cannot know.
    pub fn retryable(&self) -> Option<bool> {
        match self {
            Self::BadInput(_)
            | Self::Usage { .. }
            | Self::SecretsStaged(_)
            | Self::NotFound(_)
            | Self::MissingKey { .. }
            | Self::Diagnostics(_) => Some(false),
            Self::RateLimited(_) => Some(true),
            Self::KeychainUnavailable(_) | Self::Internal(_) => None,
        }
    }

    pub fn details(&self) -> Option<&serde_json::Value> {
        match self {
            Self::SecretsStaged(details)
            | Self::Diagnostics(details)
            | Self::MissingKey { details, .. } => Some(details),
            _ => None,
        }
    }

    pub fn code_str(&self) -> &'static str {
        match self {
            Self::BadInput(_) | Self::Usage { .. } => "bad_input",
            Self::SecretsStaged(_) => "secrets_staged",
            Self::NotFound(_) | Self::MissingKey { .. } => "not_found",
            Self::KeychainUnavailable(_) => "keychain_unavailable",
            Self::Diagnostics(_) => "setup_error",
            Self::RateLimited(_) => "rate_limited",
            Self::Internal(_) => "internal_error",
        }
    }
}

pub type Result<T> = std::result::Result<T, AkmError>;

impl From<std::io::Error> for AkmError {
    fn from(e: std::io::Error) -> Self {
        AkmError::Internal(anyhow::Error::from(e))
    }
}
