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
    /// Key name to remove.
    pub name: String,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    keychain::validate_name(&args.name).map_err(|e| AkmError::BadInput(e.to_string()))?;

    let existed = keychain::get(&args.name).is_ok();
    if existed {
        keychain::remove(&args.name).map_err(AkmError::Internal)?;
    }

    let mut entry = audit::entry_base("rm", if existed { "ok" } else { "noop" });
    entry.keys = vec![args.name.clone()];
    if let Err(e) = audit::append(&entry) {
        if !global.quiet {
            eprintln!("akm: warning: audit log write failed: {}", e);
        }
    }

    let json_mode = global.json || !std::io::stdout().is_terminal();
    if json_mode {
        println!(
            "{}",
            envelope::ok(json!({ "name": args.name, "removed": existed }))
        );
    } else if !global.quiet {
        if existed {
            eprintln!("akm: removed {}", args.name);
        } else {
            eprintln!("akm: {} not found (noop)", args.name);
        }
    }
    Ok(exit::SUCCESS)
}
