use anyhow::Result;
use clap::Args as ClapArgs;
use serde_json::json;
use std::io::IsTerminal;

use crate::audit;
use crate::cli::Global;
use crate::envelope;
use crate::exit;
use crate::keychain;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Key name to fetch.
    pub name: String,
    /// Print the raw value (default is masked).
    #[arg(long)]
    pub raw: bool,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    let value = match keychain::get(&args.name) {
        Ok(v) => v,
        Err(_) => {
            let json_mode = global.json || !std::io::stdout().is_terminal();
            if json_mode {
                println!(
                    "{}",
                    envelope::err(
                        "not_found",
                        format!("key '{}' not found", args.name),
                        Some("add it with `akm add <name>`"),
                    )
                );
            } else {
                eprintln!("akm: key '{}' not found", args.name);
            }
            return Ok(exit::NOT_FOUND);
        }
    };

    let _ = audit::append(&audit::Entry {
        ts: audit::now(),
        akm_version: audit::AKM_VERSION,
        command: if args.raw { "get-raw" } else { "get" },
        keys: vec![args.name.clone()],
        input_mode: None,
        child_command: None,
        injected_keys: None,
        push_target: None,
        cwd: audit::cwd_string(),
        ppid: audit::ppid(),
        parent_exe: audit::parent_exe(audit::ppid()),
        status: "ok",
    });

    let display = if args.raw { value.clone() } else { mask(&value) };
    let json_mode = global.json || !std::io::stdout().is_terminal();
    if json_mode {
        println!(
            "{}",
            envelope::ok(json!({
                "name": args.name,
                "value": display,
                "masked": !args.raw,
            }))
        );
    } else {
        println!("{}", display);
    }
    Ok(exit::SUCCESS)
}

pub fn mask(value: &str) -> String {
    let len = value.chars().count();
    if len <= 8 {
        return "*".repeat(len);
    }
    let prefix: String = value.chars().take(4).collect();
    let suffix: String = value.chars().rev().take(4).collect::<String>().chars().rev().collect();
    format!("{}…{}", prefix, suffix)
}
