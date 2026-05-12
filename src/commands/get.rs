use clap::Args as ClapArgs;
use serde_json::json;
use std::io::IsTerminal;

use crate::audit;
use crate::cli::Global;
use crate::envelope;
use crate::error::{AkmError, Result};
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
    keychain::validate_name(&args.name).map_err(|e| AkmError::BadInput(e.to_string()))?;

    let value = match keychain::get(&args.name) {
        Ok(v) => v,
        Err(_) => {
            return Err(AkmError::NotFound(format!("key '{}' not found", args.name)));
        }
    };

    let mut entry = audit::entry_base(if args.raw { "get-raw" } else { "get" }, "ok");
    entry.keys = vec![args.name.clone()];
    if let Err(e) = audit::append(&entry) {
        if !global.quiet {
            eprintln!("akm: warning: audit log write failed: {}", e);
        }
    }

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
    let suffix: String = value
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{}…{}", prefix, suffix)
}
