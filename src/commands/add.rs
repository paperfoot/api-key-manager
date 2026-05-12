use clap::Args as ClapArgs;
use serde_json::json;
use std::io::{IsTerminal, Read};

use crate::audit;
use crate::cli::Global;
use crate::envelope;
use crate::error::{AkmError, Result};
use crate::exit;
use crate::keychain;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Key name. Must match [A-Z_][A-Z0-9_]* (env-var shape).
    pub name: String,
    /// Value as argv. Creates an extra copy in `ps` and scrollback; the agent
    /// SDK's subprocess stdin is the preferred path.
    pub value: Option<String>,
    /// Read value from stdin even when argv `value` is present.
    #[arg(long)]
    pub stdin: bool,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    keychain::validate_name(&args.name).map_err(|e| AkmError::BadInput(e.to_string()))?;

    let (value, input_mode) = read_value(&args)?;
    if value.is_empty() {
        return Err(AkmError::BadInput("value cannot be empty".into()));
    }

    keychain::set(&args.name, &value)?;

    let mut entry = audit::entry_base("add", "ok");
    entry.keys = vec![args.name.clone()];
    entry.input_mode = Some(input_mode);
    if let Err(e) = audit::append(&entry) {
        if !global.quiet {
            eprintln!("akm: warning: audit log write failed: {}", e);
        }
    }

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
