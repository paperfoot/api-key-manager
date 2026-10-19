use clap::Args as ClapArgs;
use serde_json::json;
use std::io::IsTerminal;

use crate::audit;
use crate::cli::Global;
use crate::envelope;
use crate::error::Result;
use crate::exit;
use crate::keychain;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Key name
    pub name: String,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    // Attribute-only check: "not present" is a noop, a search failure is an
    // error, and the value is never decrypted just to delete it.
    let existed = keychain::contains(&args.name)?;
    if existed {
        keychain::remove(&args.name)?;
    }

    let mut entry = audit::entry_base("rm", if existed { "ok" } else { "noop" });
    entry.keys = vec![args.name.clone()];
    if let Err(e) = audit::append(&entry) {
        if !global.quiet {
            eprintln!("akm: warning: audit log write failed: {}", e);
        }
    }
    if existed {
        if let Err(e) = audit::record_removed(&args.name) {
            if !global.quiet {
                eprintln!("akm: warning: key-age index write failed: {e}");
            }
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
