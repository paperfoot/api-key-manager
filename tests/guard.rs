use assert_cmd::Command;
use std::fs;
use std::path::Path;
use std::process::Command as StdCommand;
use tempfile::TempDir;

const HOOK_SCRIPT: &str = "#!/usr/bin/env sh\n# Installed by akm: scans staged files for known API-key prefixes.\nexec akm guard scan\n";

fn repo() -> TempDir {
    let directory = tempfile::tempdir().expect("temporary directory");
    let status = StdCommand::new("git")
        .args(["init", "--quiet"])
        .current_dir(directory.path())
        .status()
        .expect("git should run");
    assert!(status.success(), "git init should succeed");
    directory
}

fn akm(repo: &Path) -> Command {
    let mut command = Command::cargo_bin("akm").expect("akm binary built");
    command.current_dir(repo);
    command
}

fn hook(repo: &Path) -> std::path::PathBuf {
    repo.join(".git/hooks/pre-commit")
}

fn stage(repo: &Path, path: &str) {
    let status = StdCommand::new("git")
        .args(["add", "--", path])
        .current_dir(repo)
        .status()
        .expect("git should run");
    assert!(status.success(), "git add should succeed");
}

#[test]
fn foreign_hook_is_unchanged_after_rejected_install_and_uninstall() {
    let repo = repo();
    let path = hook(repo.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let original = "#!/bin/sh\necho existing hook\n";
    fs::write(&path, original).unwrap();

    akm(repo.path()).args(["guard", "install"]).assert().code(3);
    assert_eq!(fs::read_to_string(&path).unwrap(), original);

    akm(repo.path())
        .args(["guard", "uninstall"])
        .assert()
        .code(3);
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
}

#[test]
fn owned_hook_installs_reinstalls_and_removes_idempotently() {
    let repo = repo();
    let path = hook(repo.path());

    akm(repo.path())
        .args(["guard", "install"])
        .assert()
        .success();
    assert_eq!(fs::read_to_string(&path).unwrap(), HOOK_SCRIPT);

    akm(repo.path())
        .args(["guard", "install"])
        .assert()
        .success();
    assert_eq!(fs::read_to_string(&path).unwrap(), HOOK_SCRIPT);

    akm(repo.path())
        .args(["guard", "uninstall"])
        .assert()
        .success()
        .stdout(predicates::str::contains("\"removed\":true"));
    assert!(!path.exists());

    akm(repo.path())
        .args(["guard", "uninstall"])
        .assert()
        .success()
        .stdout(predicates::str::contains("\"removed\":false"));
}

#[test]
fn custom_core_hooks_path_is_honored() {
    let repo = repo();
    let status = StdCommand::new("git")
        .args(["config", "core.hooksPath", "custom-hooks"])
        .current_dir(repo.path())
        .status()
        .unwrap();
    assert!(status.success());

    let custom_hook = repo.path().join("custom-hooks/pre-commit");
    akm(repo.path())
        .args(["guard", "install"])
        .assert()
        .success();
    assert_eq!(fs::read_to_string(&custom_hook).unwrap(), HOOK_SCRIPT);
    assert!(!hook(repo.path()).exists());

    akm(repo.path())
        .args(["guard", "uninstall"])
        .assert()
        .success();
    assert!(!custom_hook.exists());
}

#[cfg(unix)]
#[test]
fn symlink_hook_and_target_are_untouched() {
    use std::os::unix::fs::symlink;

    let repo = repo();
    let path = hook(repo.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let target = repo.path().join("shared-pre-commit");
    let original = "#!/bin/sh\necho shared hook\n";
    fs::write(&target, original).unwrap();
    symlink(&target, &path).unwrap();

    akm(repo.path()).args(["guard", "install"]).assert().code(3);
    assert_eq!(fs::read_to_string(&target).unwrap(), original);
    assert!(fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());

    akm(repo.path())
        .args(["guard", "uninstall"])
        .assert()
        .code(3);
    assert_eq!(fs::read_to_string(&target).unwrap(), original);
    assert!(fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn scan_allows_bare_prefixes_and_ellipsis_examples() {
    let repo = repo();
    fs::write(
        repo.path().join("README.md"),
        "Examples: sk-... and sk-ant- and github_pat_...\nToo short: github_pat_abcdefghijklmno\n",
    )
    .unwrap();
    stage(repo.path(), "README.md");

    akm(repo.path())
        .args(["guard", "scan"])
        .assert()
        .success()
        .stdout(predicates::str::contains("\"hits\":[]"));
}

#[test]
fn scan_checks_staged_blob_and_finds_candidate_after_bare_prefix() {
    let repo = repo();
    let body = "abcdefghijklmnop";
    let staged = format!("Documentation: sk-ant-...\nValue: sk-ant-{body}\n");
    let path = repo.path().join("README.md");
    fs::write(&path, staged).unwrap();
    stage(repo.path(), "README.md");

    fs::write(
        &path,
        "The working tree no longer contains the candidate.\n",
    )
    .unwrap();

    let output = akm(repo.path()).args(["guard", "scan"]).output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("\"path\":\"README.md\""));
    assert!(stdout.contains("\"prefix\":\"sk-ant-\""));
    assert!(
        !stdout.contains(body),
        "guard output must not include token bodies"
    );
}
