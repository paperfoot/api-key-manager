use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};
use serde_json::json;
use std::fs::{create_dir_all, write};
use std::io::IsTerminal;
use std::path::PathBuf;

use crate::cli::Global;
use crate::envelope;
use crate::exit;
use crate::skill::SKILL_MD;

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, Subcommand)]
pub enum Action {
    /// Install the bundled skill into ~/.claude/skills/akm/SKILL.md (plus codex/gemini).
    Install,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    match args.action {
        Action::Install => install(global),
    }
}

fn install(global: &Global) -> Result<u8> {
    let mut installed = Vec::new();
    for parent in skill_dirs() {
        let dir = parent.join("akm");
        create_dir_all(&dir)?;
        let path = dir.join("SKILL.md");
        write(&path, SKILL_MD)?;
        installed.push(path.display().to_string());
    }
    let json_mode = global.json || !std::io::stdout().is_terminal();
    if json_mode {
        println!(
            "{}",
            envelope::ok(json!({ "installed": installed }))
        );
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
