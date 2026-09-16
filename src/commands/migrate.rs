//! Explicit, resumable migration from a locally trusted older executable.
//! Values travel only through an anonymous pipe and memory, never argv/files.
use clap::Args as ClapArgs;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{IsTerminal, Read};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

use crate::audit;
use crate::cli::Global;
use crate::envelope;
use crate::error::{AkmError, Result};
use crate::keychain;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Trusted older AKM binary that can still read the original items.
    #[arg(long, value_name = "PATH")]
    pub from: PathBuf,
    /// Comma-separated names; defaults to all names in the source.
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,
    /// Preview names without reading or writing secret values.
    #[arg(long)]
    pub dry_run: bool,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    let source = args.from.canonicalize()?;
    if source == std::env::current_exe()?.canonicalize()? {
        return Err(AkmError::BadInput(
            "--from must name a different, trusted older AKM binary".into(),
        ));
    }
    // Validate all requested names before invoking the source or writing items.
    for name in &args.only {
        keychain::validate_name(name).map_err(|e| AkmError::BadInput(e.to_string()))?;
    }
    let names: BTreeSet<String> = if args.only.is_empty() {
        let result = source_json(&source, &["list", "--json"])?;
        let values = result["data"]["keys"]
            .as_array()
            .ok_or_else(|| source_error("list response has no key names"))?;
        values
            .iter()
            .map(|name| {
                let name = name
                    .as_str()
                    .ok_or_else(|| source_error("invalid key name response"))?;
                keychain::validate_name(name)
                    .map_err(|_| source_error("invalid key name response"))?;
                Ok(name.to_owned())
            })
            .collect::<Result<_>>()?
    } else {
        args.only.into_iter().collect()
    };
    let existing: BTreeSet<_> = keychain::primary_names()?.into_iter().collect();
    let mut migrated = Vec::new();
    let mut skipped = Vec::new();
    for name in names {
        if existing.contains(&name) {
            // Refuse to call an unreadable destination a successful migration.
            if !args.dry_run {
                keychain::get_with_status(&name)?;
            }
            skipped.push(name);
            continue;
        }
        if !args.dry_run {
            let response = source_json(&source, &["get", &name, "--raw", "--json"])?;
            let value = source_value(&response, &name)?;
            if !keychain::create_if_absent(&name, value)? {
                keychain::get_with_status(&name)?;
                skipped.push(name);
                continue;
            }
            if keychain::get_with_status(&name)? != value {
                return Err(source_error(
                    "destination verification failed; originals are preserved",
                ));
            }
            let mut entry = audit::entry_base("migrate", "ok");
            entry.keys = vec![name.clone()];
            entry.input_mode = Some("pipe");
            if let Err(error) = audit::append(&entry) {
                if !global.quiet {
                    eprintln!("akm: warning: audit log write failed: {error}");
                }
            }
        }
        migrated.push(name);
    }
    if global.json || !std::io::stdout().is_terminal() {
        println!(
            "{}",
            envelope::ok(json!({"dry_run":args.dry_run,
            "migrated":migrated,"skipped":skipped,"originals_preserved":true}))
        );
    } else if !global.quiet {
        eprintln!(
            "akm: {} {} keys; {} already present; originals preserved",
            if args.dry_run {
                "would migrate"
            } else {
                "migrated"
            },
            migrated.len(),
            skipped.len()
        );
    }
    Ok(0)
}

fn source_error(message: &str) -> AkmError {
    AkmError::KeychainUnavailable(format!("migration: {message}"))
}

fn source_value<'a>(response: &'a Value, name: &str) -> Result<&'a str> {
    let data = &response["data"];
    if data["name"] != name || data["masked"] != false {
        return Err(source_error(
            "source did not return the requested unmasked item",
        ));
    }
    data["value"]
        .as_str()
        .filter(|v| !v.is_empty() && !v.contains('\0'))
        .ok_or_else(|| source_error("source returned an invalid value"))
}

fn source_json(path: &Path, args: &[&str]) -> Result<Value> {
    // Older releases can show Keychain UI. Stop on the first failure/timeout,
    // and never echo their stdout or stderr (either can contain a value).
    const MAX_RESPONSE: u64 = 16 * 1024 * 1024;
    let mut child = Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_RESPONSE + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let waited = child.wait_timeout(Duration::from_secs(5));
    // Also close pipes held by descendants of an unexpected wrapper executable.
    // The group was created specifically for this source invocation.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    if !matches!(waited, Ok(Some(_))) {
        let _ = child.wait();
    }
    let bytes = reader
        .join()
        .map_err(|_| source_error("source reader failed"))??;
    let status = waited?.ok_or_else(|| {
        source_error("source timed out after 5 seconds; rerun with a trusted, working older binary")
    })?;
    if !status.success() || bytes.len() as u64 > MAX_RESPONSE {
        return Err(source_error(
            "source failed; no values were printed and original items are unchanged",
        ));
    }
    let result: Value =
        serde_json::from_slice(&bytes).map_err(|_| source_error("invalid source response"))?;
    if result["status"] != "ok" {
        return Err(source_error("source returned an error"));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_source_identity_and_exact_value() {
        let good = json!({"data":{"name":"EXAMPLE","masked":false,"value":"space\n'quote'\n"}});
        assert_eq!(source_value(&good, "EXAMPLE").unwrap(), "space\n'quote'\n");
        assert!(source_value(&good, "DIFFERENT").is_err());
        assert!(source_value(
            &json!({"data":{"name":"EXAMPLE","masked":true,"value":"masked"}}),
            "EXAMPLE"
        )
        .is_err());
        assert!(source_value(
            &json!({"data":{"name":"EXAMPLE","masked":false,"value":"\0"}}),
            "EXAMPLE"
        )
        .is_err());
    }
}
