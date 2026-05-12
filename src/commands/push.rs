use anyhow::Context;
use clap::{Args as ClapArgs, ValueEnum};
use serde_json::json;
use std::io::{IsTerminal, Write};
use std::process::{Command, Stdio};

use crate::audit;
use crate::cli::Global;
use crate::envelope;
use crate::error::{AkmError, Result};
use crate::exit;
use crate::keychain;
use crate::redact::Redactor;

#[derive(Debug, Clone, ValueEnum)]
pub enum Target {
    Vercel,
    Gh,
    Fly,
}

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Where to push the value.
    pub target: Target,
    /// Key name to read from the keychain.
    pub name: String,

    // Vercel options
    /// Vercel env scope (e.g. production, preview, development).
    #[arg(long, default_value = "production")]
    pub env: String,
    /// Vercel project (folder must exist with `vercel link`, or pass --project).
    #[arg(long)]
    pub project: Option<String>,

    // GitHub options
    /// GitHub repo (owner/name). Required for `gh`.
    #[arg(long)]
    pub repo: Option<String>,

    // Fly options
    /// Fly app name. Required for `fly`.
    #[arg(long)]
    pub app: Option<String>,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    keychain::validate_name(&args.name).map_err(|e| AkmError::BadInput(e.to_string()))?;

    let value = keychain::get_with_status(&args.name)?;

    let run_id = audit::new_run_id();
    {
        let mut entry = audit::entry_base("push", "started");
        entry.run_id = Some(run_id.clone());
        entry.keys = vec![args.name.clone()];
        entry.push_target = Some(target_label(&args.target));
        if let Err(e) = audit::append(&entry) {
            if !global.quiet {
                eprintln!("akm: warning: audit log write failed: {}", e);
            }
        }
    }

    let target_str = target_label(&args.target);

    let (cmd_label, exit_status) = match args.target {
        Target::Vercel => push_vercel(&args, &value)?,
        Target::Gh => push_gh(&args, &value)?,
        Target::Fly => push_fly(&args, &value)?,
    };

    let ok = exit_status.success();
    let mut entry = audit::entry_base("push", if ok { "ok" } else { "upstream_failed" });
    entry.run_id = Some(run_id);
    entry.keys = vec![args.name.clone()];
    entry.child_command = Some(cmd_label.clone());
    entry.push_target = Some(target_str);
    if let Err(e) = audit::append(&entry) {
        if !global.quiet {
            eprintln!("akm: warning: audit log write failed: {}", e);
        }
    }

    let code = if ok { exit::SUCCESS } else { exit::TRANSIENT };
    let json_mode = global.json || !std::io::stdout().is_terminal();
    if json_mode {
        println!(
            "{}",
            envelope::ok(json!({
                "target": target_str,
                "name": args.name,
                "ok": ok,
                "command": cmd_label,
            }))
        );
    } else if !global.quiet {
        eprintln!(
            "akm: pushed {} -> {} ({})",
            args.name,
            target_str,
            if ok { "ok" } else { "failed" }
        );
    }
    Ok(code)
}

/// Spawn a child process, write `stdin_payload` to its stdin, and stream its
/// stdout/stderr through a Redactor that scrubs **every variant of the secret**
/// the upstream tool might echo back:
///   - the raw value
///   - the raw value with a trailing newline (some tools include the line)
///   - any other literals the caller passes in `extra_secret_forms`
fn spawn_with_redaction(
    mut cmd: Command,
    stdin_payload: String,
    name: &str,
    raw_value: &str,
    extra_secret_forms: &[String],
    label: String,
) -> Result<(String, std::process::ExitStatus)> {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(AkmError::from)?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| AkmError::Internal(anyhow::anyhow!("failed to open child stdin")))?;
        stdin.write_all(stdin_payload.as_bytes())?;
    }
    // Drop the stdin handle so the child sees EOF and stops waiting for input.
    drop(child.stdin.take());

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let replacement = format!("[REDACTED:{}]", name);
    let mut secrets: Vec<(String, String)> = Vec::new();
    secrets.push((raw_value.to_string(), replacement.clone()));
    for extra in extra_secret_forms {
        if !extra.is_empty() && extra != raw_value {
            secrets.push((extra.clone(), replacement.clone()));
        }
    }
    // Filter out empties or duplicates the Redactor would also filter (≥8
    // bytes); keep the rest. Sorting by descending length is handled inside
    // the Redactor.

    let secrets_out = secrets.clone();
    let secrets_err = secrets;

    let out_handle = std::thread::spawn(move || {
        if let Some(mut s) = stdout {
            let r = Redactor::new(secrets_out);
            let _ = r.copy(&mut s, std::io::stdout());
        }
    });
    let err_handle = std::thread::spawn(move || {
        if let Some(mut s) = stderr {
            let r = Redactor::new(secrets_err);
            let _ = r.copy(&mut s, std::io::stderr());
        }
    });

    let status = child.wait().map_err(AkmError::from)?;
    let _ = out_handle.join();
    let _ = err_handle.join();
    Ok((label, status))
}

fn push_vercel(args: &Args, value: &str) -> Result<(String, std::process::ExitStatus)> {
    which::which("vercel")
        .context("`vercel` CLI not found in PATH")
        .map_err(AkmError::Internal)?;
    // `vercel env add NAME ENV --force` overwrites an existing env without
    // prompting. Without --force the command may go interactive when the var
    // already exists — that breaks agent-driven use.
    let mut cmd = Command::new("vercel");
    cmd.arg("env")
        .arg("add")
        .arg(&args.name)
        .arg(&args.env)
        .arg("--force");
    if let Some(p) = &args.project {
        cmd.arg("--cwd").arg(p);
    }
    let label = format!("vercel env add {} {} --force", args.name, args.env);
    let stdin_payload = format!("{}\n", value);
    // Vercel may echo the value either bare or with the trailing newline; the
    // Redactor needs to know about the raw value.
    spawn_with_redaction(cmd, stdin_payload, &args.name, value, &[], label)
}

fn push_gh(args: &Args, value: &str) -> Result<(String, std::process::ExitStatus)> {
    which::which("gh")
        .context("`gh` CLI not found in PATH")
        .map_err(AkmError::Internal)?;
    let repo = args
        .repo
        .as_ref()
        .ok_or_else(|| AkmError::BadInput("--repo OWNER/NAME is required for `push gh`".into()))?;
    let mut cmd = Command::new("gh");
    cmd.arg("secret")
        .arg("set")
        .arg(&args.name)
        .arg("--repo")
        .arg(repo);
    let label = format!("gh secret set {} --repo {}", args.name, repo);
    spawn_with_redaction(cmd, value.to_string(), &args.name, value, &[], label)
}

fn push_fly(args: &Args, value: &str) -> Result<(String, std::process::ExitStatus)> {
    let bin = which::which("fly")
        .or_else(|_| which::which("flyctl"))
        .context("`fly` / `flyctl` CLI not found in PATH")
        .map_err(AkmError::Internal)?;
    let app = args
        .app
        .as_ref()
        .ok_or_else(|| AkmError::BadInput("--app APPNAME is required for `push fly`".into()))?;
    let mut cmd = Command::new(bin);
    cmd.arg("secrets").arg("import").arg("--app").arg(app);
    let label = format!("fly secrets import --app {}", app);
    let stdin_payload = format!("{}={}\n", args.name, value);
    // Fly may print `NAME=secret` in errors; redact both raw value and the
    // KEY=VALUE form.
    let key_eq_val = format!("{}={}", args.name, value);
    spawn_with_redaction(
        cmd,
        stdin_payload,
        &args.name,
        value,
        &[key_eq_val],
        label,
    )
}

fn target_label(t: &Target) -> &'static str {
    match t {
        Target::Vercel => "vercel",
        Target::Gh => "gh",
        Target::Fly => "fly",
    }
}
