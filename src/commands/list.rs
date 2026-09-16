use chrono::{DateTime, Utc};
use clap::Args as ClapArgs;
use serde_json::json;
use std::io::IsTerminal;

use crate::audit;
use crate::cli::Global;
use crate::envelope;
use crate::error::Result;
use crate::exit;
use crate::keychain;

/// Keys last written more than this many days ago are flagged as stale in
/// `--long` output. Display-only rotation hygiene — nothing is blocked.
const STALE_DAYS: i64 = 90;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Show last-updated timestamp and age per key (from the audit log).
    #[arg(long)]
    pub long: bool,

    /// Print one key name per line, without JSON or metadata.
    #[arg(long, conflicts_with = "long")]
    pub names_only: bool,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    let names = keychain::list_names()?;
    if args.names_only {
        for name in names {
            println!("{name}");
        }
        return Ok(exit::SUCCESS);
    }
    let json_mode = global.json || !std::io::stdout().is_terminal();

    let last_set = if args.long || json_mode {
        audit::last_set_map()
    } else {
        Default::default()
    };
    let now = Utc::now();
    let age_days = |name: &str| -> Option<i64> {
        last_set
            .get(name)
            .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
            .map(|t| (now - t.with_timezone(&Utc)).num_days())
    };

    if json_mode {
        let entries: Vec<serde_json::Value> = names
            .iter()
            .map(|n| {
                json!({
                    "name": n,
                    "updated_at": last_set.get(n),
                    "age_days": age_days(n),
                })
            })
            .collect();
        println!(
            "{}",
            envelope::ok(json!({
                "count": names.len(),
                "keys": names,
                "entries": entries,
                "stale_after_days": STALE_DAYS,
            }))
        );
    } else if names.is_empty() {
        eprintln!("akm: no keys");
    } else {
        for n in &names {
            if args.long {
                match (last_set.get(n), age_days(n)) {
                    (Some(ts), Some(age)) => {
                        let date = &ts[..10.min(ts.len())];
                        let stale = if age > STALE_DAYS { "  (stale)" } else { "" };
                        println!("{}\tupdated {} ({}d ago){}", n, date, age, stale);
                    }
                    _ => println!("{}\tupdated unknown", n),
                }
            } else {
                println!("{}", n);
            }
        }
    }
    Ok(exit::SUCCESS)
}
