use thiserror::Error;

use crate::exit;

/// Typed error so the CLI can map command failures to the right exit code and
/// machine-readable error code without inspecting message strings.
#[derive(Debug, Error)]
pub enum AkmError {
    /// User-supplied input is invalid (missing flag, bad value, malformed
    /// name). Maps to exit 3 / `bad_input`.
    #[error("{0}")]
    BadInput(String),

    /// Key not found in the keychain. Maps to exit 6 / `not_found`.
    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    KeychainUnavailable(String),

    /// Anything else — IO, FFI, upstream process. Maps to exit 1 / `transient`
    /// since these are typically retriable or environment-dependent.
    #[error("{0}")]
    Internal(#[from] anyhow::Error),
}

impl AkmError {
    pub fn exit_code(&self) -> u8 {
        match self {
            AkmError::BadInput(_) => exit::BAD_INPUT,
            AkmError::NotFound(_) => exit::NOT_FOUND,
            AkmError::Internal(_) | AkmError::KeychainUnavailable(_) => exit::TRANSIENT,
        }
    }

    pub fn suggestion(&self) -> &'static str {
        match self {
            Self::BadInput(_) => "Use `akm <command> --help` or `akm agent-info --command <command>` for accepted arguments.",
            Self::NotFound(_) => "Use `akm list` to find the stored name, or supply the value to `akm add NAME` through stdin.",
            Self::KeychainUnavailable(_) => "Open Keychain Access and check that your existing login Keychain is available and unlocked. Keep HOME set to your macOS account home; do not reset the Keychain. After upgrading from an unsigned AKM, use `akm migrate --from /path/to/old/akm`.",
            Self::Internal(_) => "Check the named resource, executable, or macOS Keychain access. Check the operation outcome before retrying a write.",
        }
    }

    pub fn code_str(&self) -> &'static str {
        match self {
            AkmError::BadInput(_) => "bad_input",
            AkmError::NotFound(_) => "not_found",
            AkmError::KeychainUnavailable(_) => "keychain_unavailable",
            AkmError::Internal(_) => "internal_error",
        }
    }
}

pub type Result<T> = std::result::Result<T, AkmError>;

impl From<std::io::Error> for AkmError {
    fn from(e: std::io::Error) -> Self {
        AkmError::Internal(anyhow::Error::from(e))
    }
}
