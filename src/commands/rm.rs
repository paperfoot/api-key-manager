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
    /// Key name to remove.
    pub name: String,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    let existed = keychain::get(&args.name).is_ok();
    if existed {
        keychain::remove(&args.name)?;
    }

    let _ = audit::append(&audit::Entry {
        ts: audit::now(),
        akm_version: audit::AKM_VERSION,
        command: "rm",
        keys: vec![args.name.clone()],
        input_mode: None,
        child_command: None,
        injected_keys: None,
        push_target: None,
        cwd: audit::cwd_string(),
        ppid: audit::ppid(),
        parent_exe: audit::parent_exe(audit::ppid()),
        status: if existed { "ok" } else { "noop" },
    });

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
