use anyhow::{anyhow, Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use serde_json::json;
use std::fs::{create_dir_all, read_dir, read_to_string, write};
use std::io::IsTerminal;
use std::path::PathBuf;

use crate::cli::Global;
use crate::envelope;
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
    /// Scan a list of paths for known key prefixes (used by the hook itself).
    Scan {
        /// Paths to scan.
        paths: Vec<PathBuf>,
    },
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    match args.action {
        Action::Install => install(global),
        Action::Uninstall => uninstall(global),
        Action::Scan { paths } => scan(paths, global),
    }
}

fn git_dir() -> Result<PathBuf> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .context("git not in PATH")?;
    if !out.status.success() {
        return Err(anyhow!("not inside a git repository"));
    }
    let s = String::from_utf8(out.stdout)?;
    let trimmed = s.trim();
    let p = PathBuf::from(trimmed);
    if p.is_absolute() {
        Ok(p)
    } else {
        Ok(std::env::current_dir()?.join(p))
    }
}

fn hook_path() -> Result<PathBuf> {
    Ok(git_dir()?.join("hooks").join("pre-commit"))
}

const HOOK_SCRIPT: &str = "#!/usr/bin/env sh
# Installed by akm: scans staged files for known API-key prefixes.
exec akm guard scan $(git diff --cached --name-only --diff-filter=ACM)
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
    let removed = if p.exists() {
        std::fs::remove_file(&p).is_ok()
    } else {
        false
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
    ("OpenAI", "sk-"),
    ("OpenAI (project)", "sk-proj-"),
    ("Anthropic", "sk-ant-"),
    ("GitHub PAT (classic)", "ghp_"),
    ("GitHub PAT (fine-grained)", "github_pat_"),
    ("GitHub OAuth", "gho_"),
    ("Slack bot", "xoxb-"),
    ("Slack user", "xoxp-"),
    ("Stripe live", "sk_live_"),
    ("Google API", "AIza"),
    ("Groq", "gsk_"),
    ("AWS access key id", "AKIA"),
];

fn scan(paths: Vec<PathBuf>, global: &Global) -> Result<u8> {
    let mut hits: Vec<serde_json::Value> = Vec::new();
    for p in &paths {
        if !p.is_file() {
            continue;
        }
        let content = match read_to_string(p) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for (label, needle) in PATTERNS {
            if let Some(idx) = content.find(needle) {
                let line = content[..idx].matches('\n').count() + 1;
                hits.push(json!({
                    "path": p.display().to_string(),
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

// Silence unused-import warning when `read_dir` is not used in tests.
#[allow(dead_code)]
fn _unused() {
    let _ = read_dir(".");
}
