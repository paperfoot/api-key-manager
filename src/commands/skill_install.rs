use clap::{Args as ClapArgs, Subcommand};
use serde_json::json;
use std::fs::{create_dir_all, write};
use std::io::IsTerminal;
use std::path::PathBuf;

use crate::cli::Global;
use crate::envelope;
use crate::error::Result;
use crate::exit;
use crate::skill::SKILL_MD;

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, Subcommand)]
pub enum Action {
    /// Install or refresh the skill for Claude Code, Codex and Gemini
    Install,
    /// Check whether installed skills match this binary
    Status,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    match args.action {
        Action::Install => install(global),
        Action::Status => status(global),
    }
}

fn install(global: &Global) -> Result<u8> {
    let mut installed = Vec::new();
    for parent in skill_dirs() {
        let dir = parent.join("akm");
        create_dir_all(&dir)?;
        let path = dir.join("SKILL.md");
        if std::fs::read_to_string(&path).ok().as_deref() != Some(SKILL_MD) {
            write(&path, SKILL_MD)?;
        }
        installed.push(path.display().to_string());
    }
    let json_mode = global.json || !std::io::stdout().is_terminal();
    if json_mode {
        println!("{}", envelope::ok(json!({ "installed": installed })));
    } else if !global.quiet {
        for p in &installed {
            eprintln!("akm: installed skill -> {}", p);
        }
    }
    Ok(exit::SUCCESS)
}

fn skill_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = dirs::home_dir() {
        dirs.push(home.join(".claude").join("skills"));
        dirs.push(home.join(".codex").join("skills"));
        dirs.push(home.join(".gemini").join("skills"));
    }
    dirs
}

/// `(path, installed, current)` for each supported agent platform.
pub fn states() -> Vec<(PathBuf, bool, bool)> {
    skill_dirs()
        .into_iter()
        .map(|parent| {
            let path = parent.join("akm/SKILL.md");
            let content = std::fs::read_to_string(&path);
            let current = content.as_deref().ok() == Some(SKILL_MD);
            (path, content.is_ok(), current)
        })
        .collect()
}

fn status(global: &Global) -> Result<u8> {
    let entries: Vec<_> = states()
        .into_iter()
        .map(|(path, installed, current)| {
            json!({"path": path, "installed": installed, "current": current})
        })
        .collect();
    let current = entries.iter().all(|entry| entry["current"] == true);
    if global.json || !std::io::stdout().is_terminal() {
        println!(
            "{}",
            envelope::ok(
                json!({"version":crate::cli::VERSION, "current":current, "skills":entries})
            )
        );
    } else {
        println!(
            "{}",
            if current {
                "akm skills are current"
            } else {
                "Run `akm skill install` to update the installed skills"
            }
        );
    }
    Ok(exit::SUCCESS)
}
