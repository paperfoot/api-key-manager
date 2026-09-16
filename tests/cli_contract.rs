use assert_cmd::Command;
use serde_json::Value;

fn akm() -> Command {
    Command::cargo_bin("akm").unwrap()
}

#[test]
fn failures_are_actionable_stderr_json() {
    for args in [
        vec!["unknown-command"],
        vec!["run", "--", "true"],
        vec!["agent-info", "--command", "unknown-command"],
        vec!["run", "--only", "A=B,A=C", "--", "true"],
    ] {
        let out = akm().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(3));
        assert!(out.stdout.is_empty());
        let error: Value = serde_json::from_slice(&out.stderr).unwrap();
        assert_eq!(error["status"], "error");
        assert!(error["error"]["suggestion"]
            .as_str()
            .unwrap()
            .contains("--help"));
    }
}

#[test]
fn parser_does_not_echo_an_accidentally_supplied_secret() {
    let out = akm()
        .args(["list", "--credential=synthetic-sensitive-value"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("synthetic-sensitive-value"));
}

#[test]
fn discovery_and_alias_are_scoped() {
    let out = akm().args(["info", "--command", "stdin"]).output().unwrap();
    assert!(out.status.success());
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    let commands = value["data"]["commands"].as_object().unwrap();
    assert_eq!(commands.len(), 1);
    assert!(commands["stdin"]["options"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["name"] == "--format"));
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
