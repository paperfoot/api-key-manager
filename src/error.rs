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
            AkmError::Internal(_) => exit::TRANSIENT,
        }
    }

    pub fn code_str(&self) -> &'static str {
        match self {
            AkmError::BadInput(_) => "bad_input",
            AkmError::NotFound(_) => "not_found",
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
