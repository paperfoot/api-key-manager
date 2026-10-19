use clap::Args as ClapArgs;
use std::process::Command;

use crate::audit;
use crate::cli::Global;
use crate::error::{AkmError, Result};
use crate::keychain;

// `akm stdin NAME -- <cmd> [args...]` writes the named value to the child's
// stdin, for any CLI that accepts a secret there. Child output goes through
// the same redactor as `akm run`, so errors cannot echo the value back.
#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Key whose value goes to the child's stdin
    pub name: String,

    /// Stdin format: the raw value, or a shell-quoted NAME=value line
    #[arg(long, default_value = "raw", value_parser = ["raw", "env"])]
    pub format: String,

    /// Do not redact the value from child output
    #[arg(long)]
    pub no_redact: bool,

    /// Command and arguments after --
    #[arg(allow_hyphen_values = true, last = true, required = true)]
    pub command: Vec<String>,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    if args.command.is_empty() {
        return Err(AkmError::BadInput("no command provided after `--`".into()));
    }
    keychain::validate_name(&args.name).map_err(|e| AkmError::BadInput(e.to_string()))?;

    let value = keychain::get_with_status(&args.name)?;

    let run_id = audit::new_run_id();
    {
        let mut entry = audit::entry_base("stdin", "started");
        entry.run_id = Some(run_id.clone());
        entry.keys = vec![args.name.clone()];
        entry.child_command = Some(args.command[0].clone());
        if let Err(e) = audit::append(&entry) {
            if !global.quiet {
                eprintln!("akm: warning: audit log write failed: {}", e);
            }
        }
    }

    let mut cmd = Command::new(&args.command[0]);
    cmd.args(&args.command[1..]);
    let input = if args.format == "env" {
        format!("{}={}\n", args.name, super::export::shell_quote(&value))
    } else {
        value.clone()
    };
    let mut secrets = vec![(value.clone(), format!("[REDACTED:{}]", args.name))];
    if args.format == "env" {
        secrets.push((
            super::export::shell_quote(&value),
            format!("[REDACTED:{}]", args.name),
        ));
    }
    let result = crate::child::run(&mut cmd, Some(input.into_bytes()), secrets, !args.no_redact);
    let code = result.as_ref().copied().unwrap_or(1);

    let mut entry = audit::entry_base(
        "stdin",
        if result.is_err() {
            "error"
        } else if code == 0 {
            "ok"
        } else {
            "child_nonzero"
        },
    );
    entry.run_id = Some(run_id);
    entry.keys = vec![args.name.clone()];
    entry.child_command = Some(args.command[0].clone());
    if let Err(e) = audit::append(&entry) {
        if !global.quiet {
            eprintln!("akm: warning: audit log write failed: {}", e);
        }
    }

    let code = result?;
    super::run::report_exit("stdin", code, global);
    Ok(code)
}
