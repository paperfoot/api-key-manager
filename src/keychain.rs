use anyhow::{anyhow, Context, Result};
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

use crate::error::AkmError;

/// Service prefix used for every keychain entry written by akm.
pub const SERVICE: &str = "com.paperfoot.akm";

/// macOS Security framework status code for "item not found".
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

pub fn set(name: &str, value: &str) -> Result<()> {
    validate_name(name)?;
    set_generic_password(SERVICE, name, value.as_bytes())
        .with_context(|| format!("failed to set keychain entry '{}'", name))
}

/// Fetch a keychain value, distinguishing "not found" from real keychain /
/// UTF-8 failures so the CLI can map them to the right exit code.
pub fn get_with_status(name: &str) -> std::result::Result<String, AkmError> {
    validate_name(name).map_err(|e| AkmError::BadInput(e.to_string()))?;
    let bytes = match get_generic_password(SERVICE, name) {
        Ok(b) => b,
        Err(e) => {
            if e.code() == ERR_SEC_ITEM_NOT_FOUND {
                return Err(AkmError::NotFound(format!("key '{}' not found", name)));
            }
            return Err(AkmError::Internal(anyhow!(
                "keychain read failed for '{}': {}",
                name,
                e
            )));
        }
    };
    String::from_utf8(bytes)
        .map_err(|_| AkmError::Internal(anyhow!("keychain entry '{}' is not valid UTF-8", name)))
}

/// Check whether a key exists, distinguishing "not found" (Ok(false)) from a
/// real read failure (Err).
pub fn exists(name: &str) -> std::result::Result<bool, AkmError> {
    validate_name(name).map_err(|e| AkmError::BadInput(e.to_string()))?;
    match get_generic_password(SERVICE, name) {
        Ok(_) => Ok(true),
        Err(e) => {
            if e.code() == ERR_SEC_ITEM_NOT_FOUND {
                Ok(false)
            } else {
                Err(AkmError::Internal(anyhow!(
                    "keychain read failed for '{}': {}",
                    name,
                    e
                )))
            }
        }
    }
}

pub fn remove(name: &str) -> Result<()> {
    validate_name(name)?;
    delete_generic_password(SERVICE, name)
        .with_context(|| format!("failed to delete keychain entry '{}'", name))
}

/// Enumerate all akm-owned keychain entries via SecItemCopyMatching, NOT by
/// parsing `security dump-keychain` text. Uses security-framework's
/// ItemSearchOptions which talks to the Security API directly. Result is
/// reflected immediately under concurrent writes, so integration tests no
/// longer need single-threaded execution.
pub fn list_names() -> Result<Vec<String>> {
    let mut opts = ItemSearchOptions::new();
    opts.class(ItemClass::generic_password())
        .service(SERVICE)
        .load_attributes(true)
        .limit(Limit::All);

    let results = match opts.search() {
        Ok(r) => r,
        Err(e) => {
            if e.code() == ERR_SEC_ITEM_NOT_FOUND {
                return Ok(Vec::new());
            }
            return Err(anyhow!("keychain enumeration failed: {}", e));
        }
    };

    let mut names = Vec::with_capacity(results.len());
    for r in results {
        if let SearchResult::Dict(_) = &r {
            if let Some(attrs) = r.simplify_dict() {
                if let Some(acct) = attrs.get("acct") {
                    names.push(acct.clone());
                }
            }
        }
    }

    names.sort();
    names.dedup();
    Ok(names)
}

/// Validate a key name.
///
/// Names must match `[A-Z_][A-Z0-9_]*` (POSIX-compatible env-var name shape).
/// Rules out `FOO=BAR`-style names, lowercase, leading digits, empty, NUL.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("key name cannot be empty"));
    }
    if name.len() > 255 {
        return Err(anyhow!("key name too long (max 255 bytes)"));
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_uppercase() || first == '_') {
        return Err(anyhow!(
            "invalid key name '{}': must match [A-Z_][A-Z0-9_]* (env-var shape)",
            name
        ));
    }
    for c in chars {
        if !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
            return Err(anyhow!(
                "invalid key name '{}': must match [A-Z_][A-Z0-9_]* (env-var shape)",
                name
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_env_var_names() {
        assert!(validate_name("OPENAI_API_KEY").is_ok());
        assert!(validate_name("_PRIVATE").is_ok());
        assert!(validate_name("A").is_ok());
        assert!(validate_name("ABC123_XYZ").is_ok());
    }

    #[test]
    fn rejects_equals_in_name() {
        assert!(validate_name("FOO=BAR").is_err());
    }

    #[test]
    fn rejects_lowercase() {
        assert!(validate_name("foo").is_err());
        assert!(validate_name("MixedCase").is_err());
    }

    #[test]
    fn rejects_empty_and_nul() {
        assert!(validate_name("").is_err());
        assert!(validate_name("FOO\0BAR").is_err());
    }

    #[test]
    fn rejects_leading_digit() {
        assert!(validate_name("1FOO").is_err());
    }
}
