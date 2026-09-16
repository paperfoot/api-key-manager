use anyhow::Context;
use clap::{Args as ClapArgs, Subcommand};
use serde_json::json;
use std::fs::{create_dir_all, OpenOptions};
use std::io::{ErrorKind, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use crate::cli::Global;
use crate::envelope;
use crate::error::{AkmError, Result};
use crate::exit;

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, Subcommand)]
pub enum Action {
    /// Install the pre-commit hook in the current git repo.
    Install,
    /// Remove the pre-commit hook.
    Uninstall,
    /// Scan staged files for known API-key prefixes. Reads the staged blob
    /// content (not the working-tree file), so a "stage then delete" trick
    /// can't bypass it.
    Scan,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    match args.action {
        Action::Install => install(global),
        Action::Uninstall => uninstall(global),
        Action::Scan => scan(global),
    }
}

fn hook_path() -> Result<PathBuf> {
    let out = StdCommand::new("git")
        .args([
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "hooks/pre-commit",
        ])
        .output()
        .map_err(|e| AkmError::Internal(anyhow::anyhow!("git not in PATH: {e}")))?;
    if !out.status.success() {
        return Err(AkmError::BadInput("not inside a git repository".into()));
    }
    let s = String::from_utf8(out.stdout)
        .map_err(|e| AkmError::Internal(anyhow::anyhow!("invalid utf-8 from git: {e}")))?;
    let trimmed = s.trim();
    let p = PathBuf::from(trimmed);
    if trimmed.is_empty() || !p.is_absolute() {
        return Err(AkmError::Internal(anyhow::anyhow!(
            "git returned an invalid pre-commit hook path: {trimmed:?}"
        )));
    }
    Ok(p)
}

const HOOK_SCRIPT: &str = "#!/usr/bin/env sh
# Installed by akm: scans staged files for known API-key prefixes.
exec akm guard scan
";

enum HookState {
    Missing,
    Owned,
    Different,
    Symlink,
}

fn hook_state(path: &Path) -> Result<HookState> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(HookState::Missing),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() {
        return Ok(HookState::Symlink);
    }
    if !metadata.is_file() {
        return Ok(HookState::Different);
    }
    if std::fs::read(path)? == HOOK_SCRIPT.as_bytes() {
        Ok(HookState::Owned)
    } else {
        Ok(HookState::Different)
    }
}

fn unmanaged_hook_error(path: &Path, state: HookState, suggestion: &str) -> AkmError {
    let kind = match state {
        HookState::Symlink => "a symbolic link",
        _ => "an existing hook AKM does not own",
    };
    AkmError::BadInput(format!(
        "refusing to modify {kind} at {}; AKM left it unchanged. {suggestion}.",
        path.display(),
    ))
}

fn make_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o755);
        file.set_permissions(permissions)?;
    }
    Ok(())
}

fn install(global: &Global) -> Result<u8> {
    let p = hook_path()?;
    match hook_state(&p)? {
        HookState::Owned => make_executable(&p)?,
        state @ (HookState::Different | HookState::Symlink) => {
            return Err(unmanaged_hook_error(
                &p,
                state,
                "Add `akm guard scan` to that hook yourself, or remove it and rerun `akm guard install`",
            ));
        }
        HookState::Missing => {
            if let Some(parent) = p.parent() {
                create_dir_all(parent)?;
            }
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o755);
            }
            match options.open(&p) {
                Ok(mut file) => file.write_all(HOOK_SCRIPT.as_bytes())?,
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    let state = hook_state(&p)?;
                    match state {
                        HookState::Owned => {}
                        _ => {
                            return Err(unmanaged_hook_error(
                                &p,
                                state,
                                "Add `akm guard scan` to that hook yourself, or remove it and rerun `akm guard install`",
                            ));
                        }
                    }
                }
                Err(error) => return Err(error.into()),
            }
            make_executable(&p)?;
        }
    }
    let json_mode = global.json || !std::io::stdout().is_terminal();
    if json_mode {
        println!(
            "{}",
            envelope::ok(json!({ "installed": true, "path": p.display().to_string() }))
        );
    } else if !global.quiet {
        eprintln!("akm: installed pre-commit hook at {}", p.display());
    }
    Ok(exit::SUCCESS)
}

fn uninstall(global: &Global) -> Result<u8> {
    let p = hook_path()?;
    let removed = match hook_state(&p)? {
        HookState::Missing => false,
        HookState::Owned => {
            std::fs::remove_file(&p)?;
            true
        }
        state @ (HookState::Different | HookState::Symlink) => {
            return Err(unmanaged_hook_error(
                &p,
                state,
                "Remove it manually only if you intend to delete it",
            ));
        }
    };
    let json_mode = global.json || !std::io::stdout().is_terminal();
    if json_mode {
        println!(
            "{}",
            envelope::ok(json!({ "removed": removed, "path": p.display().to_string() }))
        );
    }
    Ok(exit::SUCCESS)
}

const PATTERNS: &[(&str, &str)] = &[
    ("OpenAI (project)", "sk-proj-"),
    ("Anthropic", "sk-ant-"),
    ("OpenRouter", "sk-or-"),
    ("OpenAI", "sk-"),
    ("GitHub PAT (fine-grained)", "github_pat_"),
    ("GitHub PAT (classic)", "ghp_"),
    ("GitHub OAuth", "gho_"),
    ("GitLab PAT", "glpat-"),
    ("Slack bot", "xoxb-"),
    ("Slack user", "xoxp-"),
    ("Stripe live", "sk_live_"),
    ("Google API", "AIza"),
    ("Groq", "gsk_"),
    ("xAI", "xai-"),
    ("Perplexity", "pplx-"),
    ("Hugging Face", "hf_"),
    ("Replicate", "r8_"),
    ("Tavily", "tvly-"),
    ("npm token", "npm_"),
    ("DigitalOcean", "dop_v1_"),
    ("Fly.io", "FlyV1 "),
    ("AWS access key id", "AKIA"),
];

const MIN_SECRET_SUFFIX_LEN: usize = 16;

fn candidate_index(content: &[u8], prefix: &str) -> Option<usize> {
    let prefix = prefix.as_bytes();
    let mut search_from = 0;

    while search_from + prefix.len() <= content.len() {
        let relative_index = content[search_from..]
            .windows(prefix.len())
            .position(|window| window == prefix)?;
        let index = search_from + relative_index;
        let suffix_len = content[index + prefix.len()..]
            .iter()
            .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            .count();
        if suffix_len >= MIN_SECRET_SUFFIX_LEN {
            return Some(index);
        }

        search_from = index + prefix.len();
    }
    None
}

/// List the paths of staged blobs as added/copied/modified, NUL-delimited so
/// filenames with spaces / newlines are handled correctly.
fn staged_paths() -> Result<Vec<String>> {
    let out = StdCommand::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"])
        .output()
        .context("failed to run git diff --cached")
        .map_err(AkmError::Internal)?;
    if !out.status.success() {
        return Err(AkmError::Internal(anyhow::anyhow!(
            "git diff --cached failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let paths: Vec<String> = out
        .stdout
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    Ok(paths)
}

/// Read the staged-blob contents for a path (not the working-tree file).
fn staged_blob(path: &str) -> Result<Vec<u8>> {
    let out = StdCommand::new("git")
        .args(["show", &format!(":{}", path)])
        .output()
        .map_err(AkmError::from)?;
    if !out.status.success() {
        return Err(AkmError::Internal(anyhow::anyhow!(
            "git show :{} failed",
            path
        )));
    }
    Ok(out.stdout)
}

fn scan(global: &Global) -> Result<u8> {
    let paths = staged_paths()?;
    let mut hits: Vec<serde_json::Value> = Vec::new();
    for p in &paths {
        let bytes = staged_blob(p)?;
        for (label, needle) in PATTERNS {
            if let Some(idx) = candidate_index(&bytes, needle) {
                let line = bytes[..idx].iter().filter(|byte| **byte == b'\n').count() + 1;
                hits.push(json!({
                    "path": p,
                    "line": line,
                    "label": label,
                    "prefix": needle,
                }));
            }
        }
    }
    let json_mode = global.json || !std::io::stdout().is_terminal();
    if hits.is_empty() {
        if json_mode {
            println!("{}", envelope::ok(json!({ "hits": [] })));
        }
        Ok(exit::SUCCESS)
    } else {
        if json_mode {
            println!("{}", envelope::ok(json!({ "hits": hits })));
        } else {
            eprintln!("akm guard: refusing commit — possible secrets staged:");
            for h in &hits {
                eprintln!(
                    "  {}:{}  {} ({})",
                    h["path"].as_str().unwrap_or(""),
                    h["line"].as_u64().unwrap_or(0),
                    h["label"].as_str().unwrap_or(""),
                    h["prefix"].as_str().unwrap_or(""),
                );
            }
            eprintln!("\nIf these are intentional, bypass with `git commit --no-verify`.");
            eprintln!(
                "Better: store with `akm add NAME` and reference via `akm run --only NAME -- <cmd>`."
            );
        }
        Ok(exit::BAD_INPUT)
    }
}
