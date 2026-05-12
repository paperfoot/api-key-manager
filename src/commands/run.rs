use clap::Args as ClapArgs;
use std::io::IsTerminal;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

use crate::audit;
use crate::cli::Global;
use crate::error::{AkmError, Result};
use crate::exit;
use crate::keychain;
use crate::redact::Redactor;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Comma-separated list of keys to inject.
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,

    /// Inject ALL stored keys. Disabled by default — large blast radius.
    #[arg(long, conflicts_with = "only")]
    pub all: bool,

    /// Disable child stdout/stderr redaction. Off-by-default redaction
    /// strips injected values from the child's output before they reach the
    /// agent's transcript.
    #[arg(long)]
    pub no_redact: bool,

    /// The command to run (and its args) after `--`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, last = true, required = true)]
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

    let names = if args.all {
        keychain::list_names().map_err(AkmError::Internal)?
    } else {
        // Validate each --only name (catches "FOO=BAR" attempts).
        for n in &args.only {
            keychain::validate_name(n).map_err(|e| AkmError::BadInput(e.to_string()))?;
        }
        args.only.clone()
    };

    if names.is_empty() {
        return Err(AkmError::BadInput("no keys to inject".into()));
    }

    let mut pairs: Vec<(String, String)> = Vec::with_capacity(names.len());
    for name in &names {
        let v = keychain::get(name).map_err(AkmError::Internal)?;
        pairs.push((name.clone(), v));
    }

    // Write a `started` audit entry BEFORE handoff so we have a record even if
    // the child is long-lived or SIGKILLed before completion.
    {
        let mut entry = audit::entry_base("run", "started");
        entry.keys = names.clone();
        entry.child_command = Some(args.command[0].clone());
        entry.injected_keys = Some(names.clone());
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

    let code = if redact {
        run_with_redaction(&mut cmd, secret_pairs)?
    } else {
        let status = cmd.status().map_err(AkmError::from)?;
        status_to_code(status)
    };

    let mut entry = audit::entry_base("run", if code == 0 { "ok" } else { "child_nonzero" });
    entry.keys = names.clone();
    entry.child_command = Some(args.command[0].clone());
    entry.injected_keys = Some(names);
    if let Err(e) = audit::append(&entry) {
        if !global.quiet {
            eprintln!("akm: warning: audit log write failed: {}", e);
        }
    }

    // Emit the status envelope on STDERR, never stdout — the child owns
    // stdout and our envelope would corrupt machine-consumed pipelines.
    let json_mode = global.json || !std::io::stdout().is_terminal();
    if json_mode && !global.quiet {
        let envelope =
            crate::envelope::ok(serde_json::json!({ "exit_code": code, "command": "run" }));
        eprintln!("{}", envelope);
    }
    Ok(code)
}

fn run_with_redaction(cmd: &mut Command, secrets: Vec<(String, String)>) -> Result<u8> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(AkmError::from)?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
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
    Ok(status_to_code(status))
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
