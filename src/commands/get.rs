use clap::Args as ClapArgs;
use serde_json::json;
use std::io::Write;

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
    /// Print the unmasked value
    #[arg(long)]
    pub raw: bool,
    /// Print only the unmasked value, no JSON or newline (for programs)
    #[arg(long)]
    pub value: bool,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    // Status-aware getter — propagates BadInput / NotFound / Internal so the
    // top-level error mapping returns the right exit code.
    let value = keychain::get_with_status(&args.name)
        .map_err(|e| keychain::with_candidates(e, &args.name))?;

    let command = match (args.value, args.raw) {
        (true, _) => "get-value",
        (false, true) => "get-raw",
        (false, false) => "get",
    };
    let mut entry = audit::entry_base(command, "ok");
    entry.keys = vec![args.name.clone()];
    if let Err(e) = audit::append(&entry) {
        if !global.quiet {
            eprintln!("akm: warning: audit log write failed: {}", e);
        }
    }

    if args.value {
        // An explicit byte stream for programs: exactly the stored value.
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(value.as_bytes())?;
        stdout.flush()?;
        return Ok(exit::SUCCESS);
    }
    let display = if args.raw {
        value.clone()
    } else {
        mask(&value)
    };
    if global.json_mode() {
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
