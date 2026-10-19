//! Hidden hook that deterministically triggers each documented exit code
//! through the real error mapping, without touching the Keychain.
use clap::Args as ClapArgs;

use crate::cli::Global;
use crate::envelope;
use crate::error::{AkmError, Result};

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Exit code to trigger: 0, 1, 2, 3, 4 or 6
    pub code: u8,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    match args.code {
        0 => {
            if global.json_mode() {
                println!("{}", envelope::ok(serde_json::json!({"exit_code": 0})));
            } else if !global.quiet {
                println!("contract: success");
            }
            Ok(crate::exit::SUCCESS)
        }
        1 => Err(AkmError::Internal(anyhow::anyhow!(
            "contract: runtime error"
        ))),
        2 => Err(AkmError::KeychainUnavailable(
            "contract: setup error".into(),
        )),
        3 => Err(AkmError::BadInput("contract: bad input".into())),
        4 => Err(AkmError::RateLimited("contract: rate limited".into())),
        6 => Err(AkmError::NotFound("contract: not found".into())),
        _ => Err(AkmError::BadInput(
            "unknown contract code; valid: 0, 1, 2, 3, 4, 6".into(),
        )),
    }
}
