use anyhow::{anyhow, Result};
use clap::Args as ClapArgs;
use serde_json::json;
use std::io::IsTerminal;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

use crate::audit;
use crate::cli::Global;
use crate::envelope;
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

    /// Disable the child stdout/stderr redactor. Off-by-default redaction is a
    /// last line of defence against build tools that print env values.
    #[arg(long)]
    pub no_redact: bool,

    /// The command to run (and its args) after `--`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, last = true, required = true)]
    pub command: Vec<String>,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    if args.command.is_empty() {
        return Err(anyhow!("no command provided after `--`"));
    }
    if args.only.is_empty() && !args.all {
        return Err(anyhow!(
            "specify --only KEY[,KEY...] or --all (refusing to inject everything by default)"
        ));
    }

    let names = if args.all {
        keychain::list_names()?
    } else {
        args.only.clone()
    };

    if names.is_empty() {
        return Err(anyhow!("no keys to inject"));
    }

    let mut pairs: Vec<(String, String)> = Vec::with_capacity(names.len());
    for name in &names {
        let v = keychain::get(name)?;
        pairs.push((name.clone(), v));
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
        let status = cmd.status()?;
        status_to_code(status)
    };

    let _ = audit::append(&audit::Entry {
        ts: audit::now(),
        akm_version: audit::AKM_VERSION,
        command: "run",
        keys: names.clone(),
        input_mode: None,
        child_command: Some(args.command[0].clone()),
        injected_keys: Some(names),
        push_target: None,
        cwd: audit::cwd_string(),
        ppid: audit::ppid(),
        parent_exe: audit::parent_exe(audit::ppid()),
        status: if code == 0 { "ok" } else { "child_nonzero" },
    });

    let json_mode = global.json || !std::io::stdout().is_terminal();
    if json_mode {
        println!("{}", envelope::ok(json!({ "exit_code": code })));
    }
    Ok(code)
}

fn run_with_redaction(cmd: &mut Command, secrets: Vec<(String, String)>) -> Result<u8> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
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

    let status = child.wait()?;
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
