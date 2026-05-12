use anyhow::{anyhow, Result};
use clap::Args as ClapArgs;
use serde_json::json;
use std::io::{IsTerminal, Read};

use crate::audit;
use crate::cli::Global;
use crate::envelope;
use crate::exit;
use crate::keychain;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Key name (e.g. OPENAI_API_KEY). Convention: env-var-style.
    pub name: String,
    /// Value as argv (creates a copy in `ps` and shell scrollback; stdin is preferred).
    pub value: Option<String>,
    /// Read value from stdin even when argv `value` is present.
    #[arg(long)]
    pub stdin: bool,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    let (value, input_mode) = read_value(&args)?;
    if value.is_empty() {
        return Err(anyhow!("value cannot be empty"));
    }

    keychain::set(&args.name, &value)?;

    let _ = audit::append(&audit::Entry {
        ts: audit::now(),
        akm_version: audit::AKM_VERSION,
        command: "add",
        keys: vec![args.name.clone()],
        input_mode: Some(input_mode),
        child_command: None,
        injected_keys: None,
        push_target: None,
        cwd: audit::cwd_string(),
        ppid: audit::ppid(),
        parent_exe: audit::parent_exe(audit::ppid()),
        status: "ok",
    });

    let json_mode = global.json || !std::io::stdout().is_terminal();
    if json_mode {
        println!(
            "{}",
            envelope::ok(json!({
                "name": args.name,
                "input_mode": input_mode,
            }))
        );
    } else if !global.quiet {
        eprintln!("akm: stored {}", args.name);
    }
    Ok(exit::SUCCESS)
}

fn read_value(args: &Args) -> Result<(String, &'static str)> {
    if args.stdin || args.value.is_none() {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        let trimmed = buf.trim_end_matches(['\n', '\r']).to_string();
        return Ok((trimmed, "stdin"));
    }
    let v = args.value.as_ref().unwrap().clone();
    Ok((v, "argv"))
}
