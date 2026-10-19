//! Read-only setup diagnostics. Never prompts, never reads secret values, and
//! reports counts rather than key names. No failed checks: success on stdout,
//! exit 0. Any failed check: error with the full report in `details`, exit 2.
use serde::Serialize;
use serde_json::json;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;

use crate::cli::{Global, VERSION};
use crate::envelope;
use crate::error::{AkmError, Result};
use crate::exit;
use crate::keychain;

const TEAM_ID: &str = "S25N6MXJCF";
const IDENTIFIER: &str = "com.paperfoot.akm";
const AUDIT_WARN_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Serialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Status {
    Pass,
    Warn,
    Fail,
}

#[derive(Serialize)]
struct Check {
    name: &'static str,
    status: Status,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    suggestion: Option<String>,
}

fn check(name: &'static str, status: Status, message: impl Into<String>) -> Check {
    Check {
        name,
        status,
        message: message.into(),
        suggestion: None,
    }
}

impl Check {
    fn fix(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }
}

fn keychain_checks() -> Vec<Check> {
    let unlock = "Unlock the login Keychain in Keychain Access and keep HOME set to your macOS account home; do not reset the Keychain";
    match keychain::default_unlocked() {
        Err(status) => {
            return vec![check(
                "keychain",
                Status::Fail,
                format!("no default Keychain opens without UI (macOS status {status})"),
            )
            .fix(unlock)]
        }
        Ok(false) => {
            return vec![
                check("keychain", Status::Fail, "the default Keychain is locked").fix(unlock),
            ]
        }
        Ok(true) => {}
    }
    let (primary, legacy) = match (keychain::primary_names(), keychain::legacy_names()) {
        (Ok(primary), Ok(legacy)) => (primary, legacy),
        (Err(error), _) | (_, Err(error)) => {
            return vec![check("keychain", Status::Fail, error.to_string()).fix(unlock)]
        }
    };
    let legacy_only = legacy.iter().filter(|name| !primary.contains(name)).count();
    let keys = format!(
        "{} keys in {}; {legacy_only} only in legacy {}",
        primary.len(),
        keychain::SERVICE,
        keychain::LEGACY_SERVICE
    );
    let keys = if legacy_only == 0 {
        check("keys", Status::Pass, keys)
    } else {
        check("keys", Status::Warn, keys).fix(
            "Copy them with `akm migrate --from /path/to/older/akm --dry-run`, then without --dry-run",
        )
    };
    vec![
        check(
            "keychain",
            Status::Pass,
            "default Keychain is unlocked and searchable without UI",
        ),
        keys,
    ]
}

fn signature_check() -> Check {
    let exe = match std::env::current_exe().and_then(|exe| exe.canonicalize()) {
        Ok(exe) => exe,
        Err(error) => {
            return check(
                "signature",
                Status::Warn,
                format!("cannot locate this executable: {error}"),
            )
        }
    };
    let output = match Command::new("/usr/bin/codesign")
        .arg("-dv")
        .arg(&exe)
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            return check(
                "signature",
                Status::Warn,
                format!("cannot run codesign: {error}"),
            )
        }
    };
    // codesign -d writes its report to stderr.
    let report = String::from_utf8_lossy(&output.stderr);
    let field = |key: &str| {
        report
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .map(str::to_string)
    };
    let identifier = field("Identifier").unwrap_or_default();
    let team = field("TeamIdentifier").unwrap_or_default();
    let reinstall = "Keychain access follows the code signature: authorize a rebuilt binary in Keychain Access, and keep the previous binary until the new one reads a key";
    if !output.status.success() {
        check("signature", Status::Warn, "executable is not signed").fix(reinstall)
    } else if report.contains("Signature=adhoc") {
        check(
            "signature",
            Status::Warn,
            "ad-hoc signed source build; each rebuild can need Keychain Access authorization",
        )
        .fix(reinstall)
    } else if team == TEAM_ID && identifier == IDENTIFIER {
        check(
            "signature",
            Status::Pass,
            format!("Developer ID {TEAM_ID}, {IDENTIFIER}"),
        )
    } else {
        check(
            "signature",
            Status::Warn,
            format!(
                "signed as {identifier} by team {team}; releases use {IDENTIFIER} by {TEAM_ID}"
            ),
        )
        .fix(reinstall)
    }
}

fn skill_check() -> Check {
    let states = super::skill_install::states();
    let installed = states.iter().filter(|(_, installed, _)| *installed).count();
    let stale = states
        .iter()
        .filter(|(_, installed, current)| *installed && !current)
        .count();
    if installed == 0 {
        check("skill", Status::Warn, "not installed (optional)").fix("Run `akm skill install`")
    } else if stale > 0 {
        check(
            "skill",
            Status::Warn,
            format!("{stale} of {installed} installed copies differ from this version"),
        )
        .fix("Run `akm skill install`")
    } else {
        check(
            "skill",
            Status::Pass,
            format!("current in {installed} locations"),
        )
    }
}

fn writable(path: &Path) -> bool {
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `path` is a valid NUL-terminated string.
    unsafe { libc::access(path.as_ptr(), libc::W_OK) == 0 }
}

fn audit_check() -> Check {
    let path = crate::audit::log_path();
    let shown = path.display().to_string();
    match std::fs::metadata(&path) {
        Ok(metadata) => {
            let size = metadata.len();
            if !writable(&path) {
                check(
                    "audit_log",
                    Status::Warn,
                    format!("{shown} is not writable"),
                )
                .fix(format!("Make {shown} writable by your user"))
            } else if size > AUDIT_WARN_BYTES {
                check(
                    "audit_log",
                    Status::Warn,
                    format!("{shown} is {} MB", size / (1024 * 1024)),
                )
                .fix(format!("Archive or truncate {shown} after reviewing it"))
            } else {
                check(
                    "audit_log",
                    Status::Pass,
                    format!("{shown} is writable ({size} bytes)"),
                )
            }
        }
        Err(_) => {
            // Created on first use: the nearest existing ancestor must accept it.
            let ancestor = path.ancestors().skip(1).find(|dir| dir.exists());
            if ancestor.is_some_and(writable) {
                check(
                    "audit_log",
                    Status::Pass,
                    format!("{shown} will be created on first use"),
                )
            } else {
                check("audit_log", Status::Warn, format!("cannot create {shown}"))
                    .fix("Keep HOME set to a writable macOS account home")
            }
        }
    }
}

fn guard_check() -> Check {
    match super::guard::hook_path() {
        Err(_) => check(
            "guard",
            Status::Pass,
            "not in a git repository; guard not checked",
        ),
        Ok(path) => match super::guard::hook_is_akm(&path) {
            Ok(true) => check(
                "guard",
                Status::Pass,
                "pre-commit hook installed in this repository",
            ),
            _ => check(
                "guard",
                Status::Pass,
                "pre-commit hook not installed (optional)",
            ),
        },
    }
}

pub fn run(global: &Global) -> Result<u8> {
    let mut checks = keychain_checks();
    checks.extend([
        signature_check(),
        skill_check(),
        audit_check(),
        guard_check(),
    ]);
    let count = |status| checks.iter().filter(|c| c.status == status).count();
    let summary = json!({"pass": count(Status::Pass), "warn": count(Status::Warn), "fail": count(Status::Fail)});
    let failed = count(Status::Fail) > 0;
    let report = json!({"version": VERSION, "checks": checks, "summary": summary});
    if failed {
        return Err(AkmError::Diagnostics(report));
    }
    if global.json_mode() {
        println!("{}", envelope::ok(report));
    } else if !global.quiet {
        for c in &checks {
            let icon = match c.status {
                Status::Pass => "ok  ",
                Status::Warn => "warn",
                Status::Fail => "FAIL",
            };
            println!("{icon} {}: {}", c.name, c.message);
            if let Some(suggestion) = &c.suggestion {
                println!("     {suggestion}");
            }
        }
    }
    Ok(exit::SUCCESS)
}
