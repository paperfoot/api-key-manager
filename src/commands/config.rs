//! AKM has no config file or AKM_ variables. `config` reports the fixed
//! locations it does use, so framework-style lookups get a truthful answer.
use clap::{Args as ClapArgs, Subcommand};
use serde_json::json;

use crate::cli::Global;
use crate::envelope;
use crate::error::Result;
use crate::exit;
use crate::keychain::{LEGACY_SERVICE, SERVICE};

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, Subcommand)]
pub enum Action {
    /// Show fixed settings: audit log and Keychain services
    Show,
    /// Print the audit log path (AKM has no config file)
    Path,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    let path = crate::audit::log_path().display().to_string();
    let data = match args.action {
        Action::Path => json!({"path": path, "config_file": null}),
        Action::Show => json!({
            "config_file": null,
            "env_vars": [],
            "audit_log": path,
            "keychain_service": SERVICE,
            "legacy_keychain_service": LEGACY_SERVICE,
            "keychain_ui": "disabled",
        }),
    };
    if global.json_mode() {
        println!("{}", envelope::ok(data));
    } else if let Some(fields) = data.as_object().filter(|_| !global.quiet) {
        for (key, value) in fields {
            println!("{key}: {value}");
        }
    }
    Ok(exit::SUCCESS)
}
