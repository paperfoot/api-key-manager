use clap::Args as ClapArgs;
use serde_json::{json, Value};
use std::fs::read_to_string;
use std::io::IsTerminal;

use crate::audit;
use crate::cli::Global;
use crate::envelope;
use crate::error::Result;
use crate::exit;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Number of most recent entries to print.
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    let path = audit::log_path();
    let content = read_to_string(&path).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(args.limit);
    let tail = &lines[start..];

    let json_mode = global.json || !std::io::stdout().is_terminal();
    if json_mode {
        let entries: Vec<Value> = tail
            .iter()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        println!(
            "{}",
            envelope::ok(json!({ "entries": entries, "path": path.display().to_string() }))
        );
    } else {
        for l in tail {
            println!("{}", l);
        }
    }
    Ok(exit::SUCCESS)
}
