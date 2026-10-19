//! Framework contracts that need no Keychain items: discovery, help, errors,
//! exit codes, doctor, update and config.
use assert_cmd::Command;
use serde_json::Value;

fn akm() -> Command {
    Command::cargo_bin("akm").unwrap()
}

fn stderr_json(out: &std::process::Output) -> Value {
    serde_json::from_slice(&out.stderr).expect("stderr is one JSON error envelope")
}

#[test]
fn failures_are_actionable_stderr_json() {
    for (args, hint) in [
        (vec!["unknown-command"], "akm agent-info"),
        (vec!["run", "--", "true"], "--help"),
        (
            vec!["agent-info", "--command", "unknown-command"],
            "akm agent-info",
        ),
        (vec!["run", "--only", "A=B,A=C", "--", "true"], "--help"),
        (
            vec!["list", "--bogus"],
            "Flags for `akm list`: --long, --names-only.",
        ),
        (vec!["skill"], "Commands for `akm skill`: install, status."),
    ] {
        let out = akm().args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(3), "{args:?}");
        assert!(out.stdout.is_empty());
        let error = stderr_json(&out);
        assert_eq!(error["version"], "1");
        assert_eq!(error["status"], "error");
        assert_eq!(error["error"]["code"], "bad_input");
        assert_eq!(error["error"]["retryable"], false);
        let suggestion = error["error"]["suggestion"].as_str().unwrap();
        assert!(suggestion.contains(hint), "{args:?}: {suggestion}");
    }
}

#[test]
fn parse_errors_include_usage_and_never_echo_argv() {
    for args in [
        vec!["list", "--credential=synthetic-sensitive-value"],
        vec!["add", "NAME", "value", "synthetic-sensitive-value"],
        vec!["export", "--format", "synthetic-sensitive-value"],
        vec!["synthetic-sensitive-value"],
    ] {
        let out = akm().args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(3));
        assert!(!String::from_utf8_lossy(&out.stderr).contains("synthetic-sensitive-value"));
    }
    let out = akm().args(["list", "--bogus"]).output().unwrap();
    let suggestion = stderr_json(&out)["error"]["suggestion"].clone();
    assert!(suggestion.as_str().unwrap().contains("Usage: akm list"));
}

#[test]
fn manifest_is_raw_and_lists_one_line_per_command() {
    let out = akm().arg("agent-info").output().unwrap();
    assert!(out.status.success());
    let manifest: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(manifest.get("status").is_none() && manifest.get("data").is_none());
    for field in [
        "name",
        "version",
        "description",
        "global_flags",
        "exit_codes",
        "envelope",
        "config",
    ] {
        assert!(manifest.get(field).is_some(), "missing {field}");
    }
    assert_eq!(manifest["auto_json_when_piped"], true);
    assert!(manifest["global_flags"]["--json"].is_object());
    assert!(manifest["global_flags"]["--quiet"].is_object());
    for code in ["0", "1", "2", "3", "4", "6"] {
        assert!(manifest["exit_codes"][code].is_string(), "exit code {code}");
    }
    assert!(manifest["config"]["env_prefix"]
        .as_str()
        .unwrap()
        .ends_with('_'));
    let commands = manifest["commands"].as_object().unwrap();
    assert!(commands.values().all(Value::is_string));
    for path in [
        "doctor",
        "update",
        "config path",
        "skill status",
        "guard scan",
    ] {
        assert!(commands.contains_key(path), "missing {path}");
    }
    assert!(
        !commands.contains_key("contract"),
        "the contract hook is hidden"
    );
}

#[test]
fn discovery_and_alias_are_scoped() {
    let out = akm().args(["info", "--command", "stdin"]).output().unwrap();
    assert!(out.status.success());
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    let keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["commands", "name", "version"]);
    let commands = value["commands"].as_object().unwrap();
    assert_eq!(commands.len(), 1);
    let stdin = &commands["stdin"];
    assert_eq!(stdin["effect"], "mixed");
    let format = stdin["options"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "--format")
        .unwrap();
    assert_eq!(format["default"], "raw");
    assert_eq!(format["values"], serde_json::json!(["raw", "env"]));

    let out = akm()
        .args(["agent-info", "--command", "guard"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["commands"].as_object().unwrap().len(), 3);
}

#[test]
fn help_is_plain_text_unless_json_is_requested() {
    let out = akm().arg("--help").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(serde_json::from_str::<Value>(&text).is_err());
    assert!(text.contains("Tips:") && text.contains("Examples:"));

    for args in [vec!["--json", "--help"], vec!["list", "--help", "--json"]] {
        let out = akm().args(&args).output().unwrap();
        assert!(out.status.success());
        let value: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(value["status"], "success");
        assert!(value["data"]["usage"].as_str().unwrap().contains("Usage:"));
    }
}

#[test]
fn contract_hook_triggers_every_documented_exit_code() {
    let out = akm().args(["contract", "0"]).output().unwrap();
    assert!(out.status.success());
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["status"], "success");
    for (code, error) in [
        (1, "internal_error"),
        (2, "keychain_unavailable"),
        (3, "bad_input"),
        (4, "rate_limited"),
        (6, "not_found"),
    ] {
        let out = akm()
            .args(["contract", &code.to_string()])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(code));
        assert!(out.stdout.is_empty());
        assert_eq!(stderr_json(&out)["error"]["code"], error);
    }
}

#[test]
fn doctor_reports_an_unusable_keychain_as_setup_failure() {
    let home = tempfile::tempdir().unwrap();
    let out = akm()
        .env("HOME", home.path())
        .current_dir(home.path())
        .arg("doctor")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let error = stderr_json(&out);
    assert_eq!(error["error"]["code"], "setup_error");
    let details = &error["error"]["details"];
    let keychain = details["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "keychain")
        .unwrap();
    assert_eq!(keychain["status"], "fail");
    assert!(details["summary"]["fail"].as_u64().unwrap() >= 1);
    for check in details["checks"].as_array().unwrap() {
        assert!(["pass", "warn", "fail"].contains(&check["status"].as_str().unwrap()));
    }
}

#[test]
fn update_returns_instructions_without_checking_releases() {
    let out = akm().args(["update", "--check"]).output().unwrap();
    assert!(out.status.success());
    let data = serde_json::from_slice::<Value>(&out.stdout).unwrap()["data"].clone();
    assert_eq!(data["current_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(data["latest_version"], Value::Null);
    assert_eq!(data["status"], "not_checked");
    assert_eq!(data["after_upgrade"], "akm skill install");
    for field in [
        "install_source",
        "update_mode",
        "release_url",
        "requires_skill_reinstall",
    ] {
        assert!(!data[field].is_null(), "missing {field}");
    }
    assert!(data.get("upgrade_command").is_some());
}

#[test]
fn config_path_reports_the_audit_log() {
    let home = tempfile::tempdir().unwrap();
    let out = akm()
        .env("HOME", home.path())
        .args(["config", "path"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let data = serde_json::from_slice::<Value>(&out.stdout).unwrap()["data"].clone();
    assert!(data["path"].as_str().unwrap().ends_with(".akm/audit.log"));
    assert_eq!(data["config_file"], Value::Null);
}

#[test]
fn audit_reads_newest_records_across_rotated_logs() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join(".akm");
    std::fs::create_dir(&dir).unwrap();
    let records = |ids: std::ops::Range<u32>| -> String {
        ids.map(|id| format!("{{\"id\":{id}}}\n")).collect()
    };
    std::fs::write(dir.join("audit.log.2"), records(0..3)).unwrap();
    std::fs::write(dir.join("audit.log.1"), records(3..6)).unwrap();
    std::fs::write(dir.join("audit.log"), records(6..8)).unwrap();
    let out = akm()
        .env("HOME", home.path())
        .args(["audit", "-n", "5"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    let ids: Vec<_> = value["data"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, [3, 4, 5, 6, 7]);
}

#[test]
fn skill_status_does_not_install_and_install_is_observable() {
    let home = tempfile::tempdir().unwrap();
    let out = akm()
        .env("HOME", home.path())
        .args(["skill", "status"])
        .output()
        .unwrap();
    assert!(!home.path().join(".codex").exists());
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["status"], "success");
    assert_eq!(value["data"]["current"], false);
    akm()
        .env("HOME", home.path())
        .args(["skill", "install"])
        .assert()
        .success();
    let out = akm()
        .env("HOME", home.path())
        .args(["skill", "status"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["data"]["current"], true);
}

#[test]
fn import_preview_does_not_access_keychain_or_echo_values() {
    let home = tempfile::tempdir().unwrap();
    let out = akm()
        .env("HOME", home.path())
        .args(["import", "--dry-run"])
        .write_stdin("EXAMPLE_KEY=synthetic-preview-secret")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("synthetic-preview-secret"));
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["data"]["stored"][0]["action"], "would_store");
}
