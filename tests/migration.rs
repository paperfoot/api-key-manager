//! End-to-end regressions for migration from a trusted older AKM executable.
//!
//! Fixtures use uniquely named synthetic Keychain items and preserve the real
//! HOME so macOS never selects a different Login Keychain.

#![cfg(target_os = "macos")]

use serde_json::Value;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use wait_timeout::ChildExt;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(12);
static KEYCHAIN_TEST_LOCK: Mutex<()> = Mutex::new(());
static UNIQUE: AtomicU64 = AtomicU64::new(0);

const SOURCE: &str = r#"#!/usr/bin/python3
import json
import os
import sys
import time

name = os.environ["AKM_IT_SOURCE_NAME"]
value = os.environ.get("AKM_IT_SOURCE_VALUE", "")
mode = os.environ.get("AKM_IT_SOURCE_MODE", "normal")
marker = os.environ.get("AKM_IT_GET_MARKER")
command = sys.argv[1] if len(sys.argv) > 1 else ""

if mode == "hang":
    time.sleep(20)

if command == "list":
    print(json.dumps({"version": "1", "status": "ok", "data": {"keys": [name]}}))
elif command == "get":
    if marker:
        with open(marker, "a", encoding="utf-8") as handle:
            handle.write("get\n")
    if mode == "invalid":
        sys.stdout.write(value)
    elif mode == "nonzero":
        sys.stdout.write(value)
        sys.stderr.write(value)
        raise SystemExit(23)
    else:
        print(json.dumps({"version": "1", "status": "ok", "data": {
            "name": name, "value": value, "masked": False
        }}))
else:
    raise SystemExit(24)
"#;

struct Harness {
    _keychain_serial: MutexGuard<'static, ()>,
    scratch: TempDir,
    source: PathBuf,
    keys: Vec<String>,
}

impl Harness {
    fn new() -> Self {
        let scratch = tempfile::tempdir().expect("create migration scratch directory");
        let source = scratch.path().join("fake-old-akm");
        fs::write(&source, SOURCE).expect("write fake source executable");
        let mut permissions = fs::metadata(&source).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&source, permissions).expect("make fake source executable");
        Self {
            _keychain_serial: KEYCHAIN_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            scratch,
            source,
            keys: Vec::new(),
        }
    }

    fn track_key(&mut self, tag: &str) -> String {
        let name = unique_key(tag);
        // Register before any command so panic cleanup covers partial writes.
        self.keys.push(name.clone());
        name
    }

    fn command(&self) -> Command {
        Command::new(env!("CARGO_BIN_EXE_akm"))
    }

    fn migrate_command(
        &self,
        name: &str,
        value: Option<&str>,
        mode: &str,
        marker: Option<&Path>,
    ) -> Command {
        let mut command = self.command();
        command
            .env("AKM_IT_SOURCE_NAME", name)
            .env("AKM_IT_SOURCE_MODE", mode);
        if let Some(value) = value {
            command.env("AKM_IT_SOURCE_VALUE", value);
        }
        if let Some(marker) = marker {
            command.env("AKM_IT_GET_MARKER", marker);
        }
        command
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        for name in self.keys.iter().rev() {
            let mut child = match self
                .command()
                .args(["rm", name])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(child) => child,
                Err(_) => continue,
            };
            if !matches!(child.wait_timeout(Duration::from_secs(3)), Ok(Some(_))) {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

fn unique_key(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let serial = UNIQUE.fetch_add(1, Ordering::Relaxed);
    format!("AKM_IT_{tag}_{}_{serial}_{nanos}", std::process::id())
}

fn capture(mut command: Command, timeout: Duration) -> Output {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn AKM migration command");
    let mut stdout = child.stdout.take().expect("capture stdout");
    let mut stderr = child.stderr.take().expect("capture stderr");
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).expect("read stdout");
        bytes
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).expect("read stderr");
        bytes
    });
    let status = match child.wait_timeout(timeout).expect("wait for AKM") {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let status = child.wait().expect("reap timed-out AKM");
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            panic!(
                "AKM migration command exceeded the test's {:?} bound (exit {:?})",
                timeout,
                status.code()
            );
        }
    };
    Output {
        status,
        stdout: stdout_reader.join().expect("join stdout reader"),
        stderr: stderr_reader.join().expect("join stderr reader"),
    }
}

fn output_json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("AKM output is one JSON envelope")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|part| part == needle)
}

#[test]
fn dry_run_lists_names_without_fetching_or_creating_values() {
    let mut harness = Harness::new();
    let name = harness.track_key("MIGRATE_DRY_RUN");
    let marker = harness.scratch.path().join("get-called");
    let source = harness.source.to_str().unwrap().to_owned();
    let mut command = harness.migrate_command(&name, None, "normal", Some(&marker));
    command.args(["--json", "migrate", "--from", &source, "--dry-run"]);

    let migrated = capture(command, COMMAND_TIMEOUT);
    assert!(migrated.status.success());
    let response = output_json(&migrated.stdout);
    assert_eq!(response["data"]["dry_run"], true);
    assert_eq!(response["data"]["migrated"], serde_json::json!([name]));
    assert!(!marker.exists(), "dry-run invoked source get");

    let mut get = harness.command();
    get.args(["--json", "get", &name, "--raw"]);
    let missing = capture(get, COMMAND_TIMEOUT);
    assert_eq!(missing.status.code(), Some(6));
}

#[test]
fn migration_preserves_exact_multiline_quoted_value_and_trailing_newline() {
    let mut harness = Harness::new();
    let name = harness.track_key("MIGRATE_EXACT");
    let value = format!("synthetic {name}\n\"double\" and 'single'\ntrailing newline\n");
    let source = harness.source.to_str().unwrap().to_owned();
    let mut command = harness.migrate_command(&name, Some(&value), "normal", None);
    command.args(["--json", "migrate", "--from", &source, "--only", &name]);
    let migrated = capture(command, COMMAND_TIMEOUT);
    assert!(migrated.status.success());

    let mut get = harness.command();
    get.args(["--json", "get", &name, "--raw"]);
    let fetched = capture(get, COMMAND_TIMEOUT);
    assert!(fetched.status.success());
    let captured_get_json = output_json(&fetched.stdout);
    assert_eq!(captured_get_json["data"]["value"], value);
    assert_eq!(captured_get_json["data"]["masked"], false);
}

#[test]
fn rerun_skips_existing_item_without_fetching_or_overwriting() {
    let mut harness = Harness::new();
    let name = harness.track_key("MIGRATE_RERUN");
    let original = format!("synthetic original for {name}\n");
    let replacement = format!("synthetic replacement for {name}\n");
    let source = harness.source.to_str().unwrap().to_owned();
    let marker = harness.scratch.path().join("rerun-get-called");

    let mut first = harness.migrate_command(&name, Some(&original), "normal", None);
    first.args(["--json", "migrate", "--from", &source, "--only", &name]);
    assert!(capture(first, COMMAND_TIMEOUT).status.success());

    let mut second = harness.migrate_command(&name, Some(&replacement), "normal", Some(&marker));
    second.args(["--json", "migrate", "--from", &source, "--only", &name]);
    let rerun = capture(second, COMMAND_TIMEOUT);
    assert!(rerun.status.success());
    let response = output_json(&rerun.stdout);
    assert_eq!(response["data"]["migrated"], serde_json::json!([]));
    assert_eq!(response["data"]["skipped"], serde_json::json!([name]));
    assert!(!marker.exists(), "rerun fetched a replacement source value");

    let mut get = harness.command();
    get.args(["--json", "get", &name, "--raw"]);
    let fetched = capture(get, COMMAND_TIMEOUT);
    assert!(fetched.status.success());
    assert_eq!(output_json(&fetched.stdout)["data"]["value"], original);
}

#[test]
fn invalid_and_nonzero_sources_never_echo_source_value() {
    let mut harness = Harness::new();
    for mode in ["invalid", "nonzero"] {
        let name = harness.track_key(if mode == "invalid" {
            "MIGRATE_INVALID"
        } else {
            "MIGRATE_NONZERO"
        });
        let value = format!("synthetic-source-value-{name}");
        let source = harness.source.to_str().unwrap().to_owned();
        let mut command = harness.migrate_command(&name, Some(&value), mode, None);
        command.args(["--json", "migrate", "--from", &source, "--only", &name]);
        let failed = capture(command, COMMAND_TIMEOUT);
        assert!(!failed.status.success());
        assert!(!contains(&failed.stdout, value.as_bytes()));
        assert!(!contains(&failed.stderr, value.as_bytes()));
        assert_eq!(output_json(&failed.stderr)["status"], "error");
    }
}

#[test]
fn hanging_source_is_stopped_by_bounded_timeout() {
    let mut harness = Harness::new();
    let name = harness.track_key("MIGRATE_TIMEOUT");
    let source = harness.source.to_str().unwrap().to_owned();
    let mut command = harness.migrate_command(&name, None, "hang", None);
    command.args(["--json", "migrate", "--from", &source, "--only", &name]);

    let started = Instant::now();
    let failed = capture(command, COMMAND_TIMEOUT);
    let elapsed = started.elapsed();
    assert!(!failed.status.success());
    assert!(
        elapsed < Duration::from_secs(10),
        "source timeout was not bounded"
    );
    let response = output_json(&failed.stderr);
    assert!(response["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .contains("timed out after 5 seconds"));
}
