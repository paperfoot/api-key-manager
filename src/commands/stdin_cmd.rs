use clap::Args as ClapArgs;
use serde_json::json;
use std::io::{IsTerminal, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

use crate::audit;
use crate::cli::Global;
use crate::envelope;
use crate::error::{AkmError, Result};
use crate::exit;
use crate::keychain;
use crate::redact::Redactor;

/// `akm stdin NAME -- <cmd> [args...]`
///
/// Reads the named keychain value and writes it to the child's stdin. Replaces
/// the old `akm push vercel|gh|fly` wrappers — works for any upstream CLI that
/// accepts a secret on stdin. Child stdout/stderr go through the same redactor
/// as `akm run`, so error messages can't echo the value back into the agent's
/// transcript.
#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Key name whose value is written to the child's stdin.
    pub name: String,

    /// Disable child stdout/stderr redaction.
    #[arg(long)]
    pub no_redact: bool,

    /// The command (and its args) to run after `--`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, last = true, required = true)]
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
    cmd.stdin(Stdio::piped());
    if !args.no_redact {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }

    let mut child = cmd.spawn().map_err(AkmError::from)?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| AkmError::Internal(anyhow::anyhow!("failed to open child stdin")))?;
        stdin.write_all(value.as_bytes())?;
    }
    drop(child.stdin.take());

    let code = if args.no_redact {
        let status = child.wait().map_err(AkmError::from)?;
        status_to_code(status)
    } else {
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let secrets = vec![(value.clone(), format!("[REDACTED:{}]", args.name))];
        let secrets_a = secrets.clone();
        let secrets_b = secrets;

        let out_handle = std::thread::spawn(move || {
            if let Some(mut s) = stdout {
                let r = Redactor::new(secrets_a);
                let _ = r.copy(&mut s, std::io::stdout());
            }
        });
        let err_handle = std::thread::spawn(move || {
            if let Some(mut s) = stderr {
                let r = Redactor::new(secrets_b);
                let _ = r.copy(&mut s, std::io::stderr());
            }
        });

        let status = child.wait().map_err(AkmError::from)?;
        let _ = out_handle.join();
        let _ = err_handle.join();
        status_to_code(status)
    };

    let mut entry = audit::entry_base("stdin", if code == 0 { "ok" } else { "child_nonzero" });
    entry.run_id = Some(run_id);
    entry.keys = vec![args.name.clone()];
    entry.child_command = Some(args.command[0].clone());
    if let Err(e) = audit::append(&entry) {
        if !global.quiet {
            eprintln!("akm: warning: audit log write failed: {}", e);
        }
    }

    let json_mode = global.json || !std::io::stdout().is_terminal();
    if json_mode && !global.quiet {
        let envelope = envelope::ok(json!({ "exit_code": code, "command": "stdin" }));
        eprintln!("{}", envelope);
    }
    Ok(code)
}

fn status_to_code(s: std::process::ExitStatus) -> u8 {
    if let Some(code) = s.code() {
        (code & 0xff) as u8
    } else if let Some(sig) = s.signal() {
        (128u32.saturating_add(sig as u32) & 0xff) as u8
    } else {
        exit::TRANSIENT
    }
}
