use anyhow::{anyhow, Context, Result};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

/// Service prefix used for every keychain entry written by akm.
pub const SERVICE: &str = "com.paperfoot.akm";

pub fn set(name: &str, value: &str) -> Result<()> {
    validate_name(name)?;
    set_generic_password(SERVICE, name, value.as_bytes())
        .with_context(|| format!("failed to set keychain entry '{}'", name))
}

pub fn get(name: &str) -> Result<String> {
    validate_name(name)?;
    let bytes = get_generic_password(SERVICE, name)
        .with_context(|| format!("keychain entry '{}' not found", name))?;
    String::from_utf8(bytes).map_err(|_| anyhow!("keychain entry '{}' is not valid UTF-8", name))
}

pub fn remove(name: &str) -> Result<()> {
    validate_name(name)?;
    delete_generic_password(SERVICE, name)
        .with_context(|| format!("failed to delete keychain entry '{}'", name))
}

/// List all akm keys by parsing `security dump-keychain`.
///
/// Each keychain entry in the dump-keychain output starts with a `keychain:`
/// line. Inside we collect the `"acct"<blob>=` (the key name) and the service
/// (either `"svce"<blob>=` or the legacy `0x00000007 <blob>=`). We emit the
/// name when the entry's service matches `SERVICE`.
pub fn list_names() -> Result<Vec<String>> {
    use std::process::Command;

    let output = Command::new("/usr/bin/security")
        .args(["dump-keychain"])
        .output()
        .context("failed to run `security dump-keychain`")?;

    if !output.status.success() {
        return Err(anyhow!(
            "`security dump-keychain` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut names = Vec::new();
    let mut current_svc: Option<String> = None;
    let mut current_acct: Option<String> = None;

    let flush = |names: &mut Vec<String>, svc: &mut Option<String>, acct: &mut Option<String>| {
        if let (Some(s), Some(a)) = (svc.as_ref(), acct.as_ref()) {
            if s == SERVICE {
                names.push(a.clone());
            }
        }
        *svc = None;
        *acct = None;
    };

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("keychain:") {
            flush(&mut names, &mut current_svc, &mut current_acct);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("\"svce\"<blob>=") {
            current_svc = unquote_security_field(rest);
        } else if let Some(rest) = trimmed.strip_prefix("0x00000007 <blob>=") {
            if current_svc.is_none() {
                current_svc = unquote_security_field(rest);
            }
        } else if let Some(rest) = trimmed.strip_prefix("\"acct\"<blob>=") {
            current_acct = unquote_security_field(rest);
        }
    }
    flush(&mut names, &mut current_svc, &mut current_acct);

    names.sort();
    names.dedup();
    Ok(names)
}

fn unquote_security_field(s: &str) -> Option<String> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('"') {
        if let Some(end) = rest.rfind('"') {
            return Some(rest[..end].to_string());
        }
    }
    if s == "<NULL>" || s.is_empty() {
        return None;
    }
    Some(s.to_string())
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("key name cannot be empty"));
    }
    if name.contains('\0') {
        return Err(anyhow!("key name cannot contain NUL bytes"));
    }
    if name.len() > 255 {
        return Err(anyhow!("key name too long (max 255 bytes)"));
    }
    Ok(())
}
