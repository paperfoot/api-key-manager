//! End-to-end integration tests.
//!
//! Tests use unique random prefixes so reruns don't step on each other. Run
//! single-threaded (`-- --test-threads=1`) because the macOS Keychain itself
//! has eventual-consistency edge cases when many writers churn concurrently —
//! even with v0.1.3's `ItemSearchOptions`-based enumeration (which is far
//! more robust than the v0.1.2 `security dump-keychain` text parser, but not
//! perfectly atomic under cargo's default thread fan-out).

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

// ----- baseline tests -----

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
    assert!(s.contains("\"threat_model\""));
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
    assert!(body.contains(value));

    let out = akm().args(["get", &name]).output().unwrap();
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(!body.contains(value), "masked get must not contain raw value");

    akm().args(["rm", &name]).assert().success();

    let out = akm().args(["get", &name]).output().unwrap();
    assert!(!out.status.success());

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
    assert!(body.contains(&name));

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

#[test]
fn run_requires_only_or_all() {
    let out = akm().args(["run", "--", "true"]).output().unwrap();
    let code = out.status.code().unwrap();
    assert_eq!(code, 3, "missing --only/--all should exit 3 (bad_input)");
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
    assert!(body.contains(value));

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
    assert!(!body.contains(value));
    assert!(body.contains("[REDACTED:"));

    cleanup(&name);
}

// ----- new tests for Codex 0.1.1 fixes -----

/// Fix #9: `akm run --json` must NOT pollute child stdout with the akm
/// envelope. Envelope goes to stderr.
#[test]
fn run_json_envelope_does_not_pollute_child_stdout() {
    let name = unique_key("RUN_JSON");
    let value = "run-json-stdout-test-value-abc1234567890";

    akm()
        .args(["add", &name])
        .write_stdin(value)
        .assert()
        .success();

    let out = akm()
        .args([
            "run",
            "--json",
            "--only",
            &name,
            "--no-redact",
            "--",
            "/bin/sh",
            "-c",
            "echo CHILD_OUTPUT_LINE",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.trim() == "CHILD_OUTPUT_LINE",
        "child stdout should be exactly CHILD_OUTPUT_LINE, got: {:?}",
        stdout
    );
    assert!(
        stderr.contains("\"command\":\"run\""),
        "envelope should be on stderr in --json mode, got: {:?}",
        stderr
    );
    cleanup(&name);
}

/// v0.1.3: `akm stdin NAME -- <cmd>` writes the value to the child's stdin.
#[test]
fn stdin_writes_value_to_child_stdin() {
    let name = unique_key("STDIN_PIPE");
    let value = "stdin-pipe-test-value-abc1234567890";
    akm()
        .args(["add", &name])
        .write_stdin(value)
        .assert()
        .success();

    // /bin/cat echoes stdin to stdout. With --no-redact we get the raw value;
    // assert we see exactly what we put in.
    let out = akm()
        .args(["stdin", &name, "--no-redact", "--", "/bin/cat"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.contains(value),
        "child should receive the value on stdin, got: {:?}",
        body
    );
    cleanup(&name);
}

/// v0.1.3: stdin command redacts the value from child stdout by default.
#[test]
fn stdin_redacts_value_in_child_output() {
    let name = unique_key("STDIN_REDACT");
    let value = "stdin-redact-test-value-xyz9876543210";
    akm()
        .args(["add", &name])
        .write_stdin(value)
        .assert()
        .success();

    // Child reads value from stdin, then prints it back. Default mode should
    // replace the value with [REDACTED:NAME].
    let out = akm()
        .args(["stdin", &name, "--", "/bin/cat"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        !body.contains(value),
        "raw value must not appear in redacted stdout, got: {:?}",
        body
    );
    assert!(
        body.contains(&format!("[REDACTED:{}]", name)),
        "redaction token should appear, got: {:?}",
        body
    );
    cleanup(&name);
}

/// Fix #12: key names must match env-var pattern.
#[test]
fn add_rejects_invalid_name() {
    let out = akm()
        .args(["add", "FOO=BAR"])
        .write_stdin("any-value-12345678")
        .output()
        .unwrap();
    assert_eq!(out.status.code().unwrap(), 3, "FOO=BAR should be bad_input (3)");
}

#[test]
fn add_rejects_lowercase_name() {
    let out = akm()
        .args(["add", "lowercase"])
        .write_stdin("any-value-12345678")
        .output()
        .unwrap();
    assert_eq!(out.status.code().unwrap(), 3);
}

/// Fix #7: audit log file is created with mode 0600 (not group/other readable).
#[test]
fn audit_log_perms_are_0600() {
    use std::os::unix::fs::PermissionsExt;
    let name = unique_key("PERM");
    akm()
        .args(["add", &name])
        .write_stdin("perm-test-value-1234567890")
        .assert()
        .success();
    let home = std::env::var("HOME").unwrap();
    let path = format!("{}/.akm/audit.log", home);
    let meta = std::fs::metadata(&path).expect("audit log exists");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "expected 0600, got {:o}", mode);
    cleanup(&name);
}

/// Fix #6: `akm run` writes a "started" audit entry BEFORE the child exits,
/// AND a matching `run_id` pairs the started/completed entries.
///
/// Codex flagged the previous version of this test as weak: it used `true`
/// (instant exit) and checked after, so it didn't prove the ordering. This
/// version spawns a long-lived child, checks the audit log while it's still
/// alive, then asserts the paired completion entry exists.
#[test]
fn run_writes_started_audit_entry_before_child_exits() {
    use std::thread;
    use std::time::Duration;
    let name = unique_key("STARTED");
    akm()
        .args(["add", &name])
        .write_stdin("started-audit-test-1234567890")
        .assert()
        .success();

    // Spawn a long-lived child in the background.
    let name_c = name.clone();
    let handle = thread::spawn(move || {
        akm()
            .args([
                "run",
                "--only",
                &name_c,
                "--no-redact",
                "--",
                "/bin/sh",
                "-c",
                "sleep 2",
            ])
            .output()
            .unwrap()
    });

    // Give the started entry time to land.
    thread::sleep(Duration::from_millis(500));

    let out = akm()
        .args(["audit", "--json", "--limit", "50"])
        .output()
        .unwrap();
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.contains("\"status\":\"started\""),
        "started entry must appear while child is alive, got: {}",
        body
    );

    let result = handle.join().expect("run thread joined");
    assert!(result.status.success(), "run should succeed");

    // After completion, both started and ok entries must be present and
    // share a run_id.
    let out = akm()
        .args(["audit", "--json", "--limit", "50"])
        .output()
        .unwrap();
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(body.contains("\"status\":\"started\""));
    assert!(body.contains("\"status\":\"ok\""));
    cleanup(&name);
}

/// Fix #8: redactor handles prefix collision (longer secret beats shorter
/// prefix). Tightened per Codex #9: also assert command success AND that the
/// redaction token appears (empty stdout would otherwise satisfy "not contains
/// long_val").
#[test]
fn run_redacts_longer_matching_secret() {
    let short = unique_key("SHORT_PFX");
    let long = unique_key("LONG_PFX");
    let short_val = "prefix-collision-test-xx".to_string();
    let long_val = format!("{}-more-bytes", short_val);

    akm().args(["add", &short]).write_stdin(short_val.clone()).assert().success();
    akm().args(["add", &long]).write_stdin(long_val.clone()).assert().success();

    let out = akm()
        .args([
            "run",
            "--only",
            &format!("{},{}", short, long),
            "--",
            "/bin/sh",
            "-c",
            &format!("echo ${}", long),
        ])
        .output()
        .unwrap();

    assert!(out.status.success(), "run should succeed");
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        !body.contains(&long_val),
        "long value should be redacted, got: {:?}",
        body
    );
    assert!(
        body.contains(&format!("[REDACTED:{}]", long)),
        "expected [REDACTED:{}] in output, got: {:?}",
        long,
        body
    );

    cleanup(&short);
    cleanup(&long);
}
