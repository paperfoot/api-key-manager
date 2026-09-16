use clap::Args as ClapArgs;
use std::process::Command;

use crate::audit;
use crate::cli::Global;
use crate::error::{AkmError, Result};
use crate::keychain;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Keys to inject, comma-separated. Use ENV=STORED_KEY to rename in the child.
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,

    /// Inject ALL stored keys. Disabled by default — large blast radius.
    #[arg(long, conflicts_with = "only")]
    pub all: bool,

    /// Disable the default child stdout/stderr redaction.
    #[arg(long)]
    pub no_redact: bool,

    /// The command to run (and its args) after `--`.
    #[arg(allow_hyphen_values = true, last = true, required = true)]
    pub command: Vec<String>,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    if args.command.is_empty() {
        return Err(AkmError::BadInput("no command provided after `--`".into()));
    }
    if args.only.is_empty() && !args.all {
        return Err(AkmError::BadInput(
            "specify --only KEY[,KEY...] or --all (refusing to inject everything by default)"
                .into(),
        ));
    }

    let mappings = if args.all {
        keychain::list_names()?
            .into_iter()
            .map(|name| (name.clone(), name))
            .collect()
    } else {
        mappings(&args.only)?
    };
    if mappings.is_empty() {
        return Err(AkmError::BadInput("no keys to inject".into()));
    }
    let names: Vec<String> = mappings.iter().map(|(_, source)| source.clone()).collect();
    let mut pairs = Vec::with_capacity(mappings.len());
    for (target, source) in &mappings {
        let value = keychain::get_with_status(source)?;
        pairs.push((target.clone(), value));
    }

    let run_id = audit::new_run_id();
    {
        let mut entry = audit::entry_base("run", "started");
        entry.run_id = Some(run_id.clone());
        entry.keys = names.clone();
        entry.child_command = Some(args.command[0].clone());
        entry.injected_keys = Some(mappings.iter().map(|(target, _)| target.clone()).collect());
        if let Err(e) = audit::append(&entry) {
            if !global.quiet {
                eprintln!("akm: warning: audit log write failed: {}", e);
            }
        }
    }

    let mut cmd = Command::new(&args.command[0]);
    cmd.args(&args.command[1..]);
    for (k, v) in &pairs {
        cmd.env(k, v);
    }

    let redact = !args.no_redact;
    let secret_pairs: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| (v.clone(), format!("[REDACTED:{}]", k)))
        .collect();

    let result = crate::child::run(&mut cmd, None, secret_pairs, redact);
    let code = result.as_ref().copied().unwrap_or(1);

    let mut entry = audit::entry_base(
        "run",
        if result.is_err() {
            "error"
        } else if code == 0 {
            "ok"
        } else {
            "child_nonzero"
        },
    );
    entry.run_id = Some(run_id);
    entry.keys = names.clone();
    entry.child_command = Some(args.command[0].clone());
    entry.injected_keys = Some(mappings.iter().map(|(target, _)| target.clone()).collect());
    if let Err(e) = audit::append(&entry) {
        if !global.quiet {
            eprintln!("akm: warning: audit log write failed: {}", e);
        }
    }

    let code = result?;
    report_exit("run", code, global);
    Ok(code)
}

pub fn report_exit(command: &str, code: u8, global: &Global) {
    // Wrappers are transparent unless completion metadata is explicitly asked
    // for. Never append an AKM success report to a failed child's output.
    if global.json {
        if code == 0 {
            eprintln!(
                "{}",
                crate::envelope::ok(serde_json::json!({"exit_code": code, "command": command}))
            );
        } else {
            eprintln!("{}", crate::envelope::err("child_failed", format!("{command} child exited with code {code}"), Some("Inspect the child diagnostic; do not repeat a write unless its outcome is known.")));
        }
    }
}

fn mappings(specs: &[String]) -> Result<Vec<(String, String)>> {
    let mut mappings = Vec::new();
    for spec in specs {
        let (target, source) = spec.split_once('=').unwrap_or((spec, spec));
        for name in [target, source] {
            keychain::validate_name(name).map_err(|e| AkmError::BadInput(e.to_string()))?;
        }
        if let Some((_, previous)) = mappings.iter().find(|(name, _)| name == target) {
            if previous != source {
                return Err(AkmError::BadInput(format!(
                    "duplicate destination '{target}' in --only"
                )));
            }
            continue;
        }
        mappings.push((target.to_string(), source.to_string()));
    }
    Ok(mappings)
}
