use clap::Args as ClapArgs;
use serde_json::json;
use std::io::IsTerminal;

use crate::cli::Global;
use crate::envelope;
use crate::error::{AkmError, Result};
use crate::exit;
use crate::keychain;

#[derive(Debug, ClapArgs)]
pub struct Args {}

pub fn run(_args: Args, global: &Global) -> Result<u8> {
    let names = keychain::list_names().map_err(AkmError::Internal)?;
    let json_mode = global.json || !std::io::stdout().is_terminal();
    if json_mode {
        println!(
            "{}",
            envelope::ok(json!({ "count": names.len(), "keys": names }))
        );
    } else if names.is_empty() {
        eprintln!("akm: no keys");
    } else {
        for n in &names {
            println!("{}", n);
        }
    }
    Ok(exit::SUCCESS)
}
