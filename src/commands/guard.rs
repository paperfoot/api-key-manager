use anyhow::Context;
use clap::{Args as ClapArgs, Subcommand};
use serde_json::json;
use std::fs::{create_dir_all, write};
use std::io::IsTerminal;
use std::path::PathBuf;
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

fn git_dir() -> Result<PathBuf> {
    let out = StdCommand::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .map_err(|e| AkmError::Internal(anyhow::anyhow!("git not in PATH: {e}")))?;
    if !out.status.success() {
        return Err(AkmError::BadInput("not inside a git repository".into()));
    }
    let s = String::from_utf8(out.stdout)
        .map_err(|e| AkmError::Internal(anyhow::anyhow!("invalid utf-8 from git: {e}")))?;
    let trimmed = s.trim();
    let p = PathBuf::from(trimmed);
    if p.is_absolute() {
        Ok(p)
    } else {
        Ok(std::env::current_dir()
            .map_err(AkmError::from)?
            .join(p))
    }
}

fn hook_path() -> Result<PathBuf> {
    Ok(git_dir()?.join("hooks").join("pre-commit"))
}

const HOOK_SCRIPT: &str = "#!/usr/bin/env sh
# Installed by akm: scans staged files for known API-key prefixes.
exec akm guard scan
";

fn install(global: &Global) -> Result<u8> {
    let p = hook_path()?;
    if let Some(parent) = p.parent() {
        create_dir_all(parent)?;
    }
    write(&p, HOOK_SCRIPT)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&p)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms)?;
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
    let removed = p.exists() && std::fs::remove_file(&p).is_ok();
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
    ("OpenAI", "sk-"),
    ("GitHub PAT (fine-grained)", "github_pat_"),
    ("GitHub PAT (classic)", "ghp_"),
    ("GitHub OAuth", "gho_"),
    ("Slack bot", "xoxb-"),
    ("Slack user", "xoxp-"),
    ("Stripe live", "sk_live_"),
    ("Google API", "AIza"),
    ("Groq", "gsk_"),
    ("AWS access key id", "AKIA"),
];

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
        let bytes = match staged_blob(p) {
            Ok(b) => b,
            Err(_) => continue, // binary or unreadable staged entry — skip
        };
        // Lossy is fine: we are matching ASCII prefixes.
        let content = String::from_utf8_lossy(&bytes);
        for (label, needle) in PATTERNS {
            if let Some(idx) = content.find(needle) {
                let line = content[..idx].matches('\n').count() + 1;
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
            eprintln!("Better: store with `akm add NAME` and reference via `akm run -- <cmd>`.");
        }
        Ok(exit::BAD_INPUT)
    }
}
