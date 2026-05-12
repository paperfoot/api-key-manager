//! End-to-end integration tests.
//!
//! Most tests use a unique random prefix for key names so concurrent runs don't
//! step on each other. Tests that touch the keychain are gated by a feature
//! flag because CI may run on Linux where the macOS keychain doesn't exist.

#![cfg(target_os = "macos")]

use assert_cmd::Command;
use std::process::Command as StdCommand;

fn akm() -> Command {
    Command::cargo_bin("akm").expect("akm binary built")
}

fn unique_key(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("AKM_IT_{}_{}", prefix, nanos)
}

fn cleanup(name: &str) {
    let _ = StdCommand::new(env!("CARGO_BIN_EXE_akm"))
        .args(["rm", name])
        .output();
}

#[test]
fn version_and_help() {
    akm().arg("--version").assert().success();
    akm().arg("--help").assert().success();
}

#[test]
fn agent_info_json() {
    let out = akm().args(["agent-info", "--json"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("\"name\":\"akm\""));
    assert!(s.contains("\"commands\""));
}

#[test]
fn add_get_rm_roundtrip() {
    let name = unique_key("ROUNDTRIP");
    let value = "sk-test-roundtrip-value-1234567890";

    akm()
        .args(["add", &name])
        .write_stdin(value)
        .assert()
        .success();

    let out = akm().args(["get", &name, "--raw"]).output().unwrap();
    assert!(out.status.success());
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(body.contains(value), "raw get should return value, got: {}", body);

    let out = akm().args(["get", &name]).output().unwrap();
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(!body.contains(value), "masked get must not contain raw value");

    akm().args(["rm", &name]).assert().success();

    let out = akm().args(["get", &name]).output().unwrap();
    assert!(!out.status.success(), "get after rm should fail");

    cleanup(&name);
}

#[test]
fn get_missing_returns_not_found() {
    let name = unique_key("MISSING");
    let out = akm().args(["get", &name]).output().unwrap();
    let code = out.status.code().unwrap();
    assert_eq!(code, 6, "missing key should exit 6 (not_found)");
}

#[test]
fn run_requires_only_or_all() {
    let out = akm().args(["run", "--", "true"]).output().unwrap();
    assert!(!out.status.success(), "run without --only/--all should fail");
}

#[test]
fn run_injects_only_named_keys() {
    let name = unique_key("RUN");
    let value = "value-for-run-injection-test-abc123";

    akm()
        .args(["add", &name])
        .write_stdin(value)
        .assert()
        .success();

    let out = akm()
        .args([
            "run",
            "--only",
            &name,
            "--no-redact",
            "--",
            "/bin/sh",
            "-c",
            &format!("echo ${}", name),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.contains(value),
        "child should see the injected value, got: {}",
        body
    );

    cleanup(&name);
}

#[test]
fn run_redaction_replaces_value() {
    let name = unique_key("REDACT");
    let value = "secret-to-redact-not-in-output-xyz789";

    akm()
        .args(["add", &name])
        .write_stdin(value)
        .assert()
        .success();

    let out = akm()
        .args([
            "run",
            "--only",
            &name,
            "--",
            "/bin/sh",
            "-c",
            &format!("echo ${}", name),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        !body.contains(value),
        "raw secret must not appear in redacted stdout, got: {}",
        body
    );
    assert!(
        body.contains("[REDACTED:"),
        "redaction token should appear, got: {}",
        body
    );

    cleanup(&name);
}

#[test]
fn list_includes_added_key() {
    let name = unique_key("LIST");
    akm()
        .args(["add", &name])
        .write_stdin("list-test-value-1234567890")
        .assert()
        .success();

    let out = akm().args(["list", "--json"]).output().unwrap();
    assert!(out.status.success());
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.contains(&name),
        "list output should contain key name, got: {}",
        body
    );

    cleanup(&name);
}

#[test]
fn add_via_argv_works() {
    let name = unique_key("ARGV");
    let value = "argv-test-value-1234567890";
    akm().args(["add", &name, value]).assert().success();
    let out = akm().args(["get", &name, "--raw"]).output().unwrap();
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(body.contains(value));
    cleanup(&name);
}
