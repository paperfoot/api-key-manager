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

    let value = keychain::get(&args.name)
        .map_err(|_| AkmError::NotFound(format!("key '{}' not found", args.name)))?;

    // Started entry before handoff.
    {
        let mut entry = audit::entry_base("push", "started");
        entry.keys = vec![args.name.clone()];
        entry.push_target = Some(target_label(&args.target));
        if let Err(e) = audit::append(&entry) {
            if !global.quiet {
                eprintln!("akm: warning: audit log write failed: {}", e);
            }
        }
    }

    let target_str = target_label(&args.target);
    let value_for_redact = value.clone();

    let (cmd_label, exit_status) = match args.target {
        Target::Vercel => push_vercel(&args, value)?,
        Target::Gh => push_gh(&args, value)?,
        Target::Fly => push_fly(&args, value)?,
    };

    let ok = exit_status.success();
    let mut entry = audit::entry_base("push", if ok { "ok" } else { "upstream_failed" });
    entry.keys = vec![args.name.clone()];
    entry.child_command = Some(cmd_label.clone());
    entry.push_target = Some(target_str);
    if let Err(e) = audit::append(&entry) {
        if !global.quiet {
            eprintln!("akm: warning: audit log write failed: {}", e);
        }
    }
    // Suppress unused-warning when redaction is not used.
    let _ = value_for_redact;

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

fn spawn_with_redaction(
    mut cmd: Command,
    value: String,
    name: &str,
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
        stdin.write_all(value.as_bytes())?;
    }
    // Close stdin so the child can finish.
    drop(child.stdin.take());

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let secrets = vec![(value, format!("[REDACTED:{}]", name))];

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
    Ok((label, status))
}

fn push_vercel(args: &Args, value: String) -> Result<(String, std::process::ExitStatus)> {
    which::which("vercel")
        .context("`vercel` CLI not found in PATH")
        .map_err(AkmError::Internal)?;
    let mut cmd = Command::new("vercel");
    cmd.arg("env").arg("add").arg(&args.name).arg(&args.env);
    if let Some(p) = &args.project {
        cmd.arg("--cwd").arg(p);
    }
    let label = format!("vercel env add {} {}", args.name, args.env);
    // Vercel reads the value from stdin when piped (one line, then newline).
    let value_with_newline = format!("{}\n", value);
    spawn_with_redaction(cmd, value_with_newline, &args.name, label)
}

fn push_gh(args: &Args, value: String) -> Result<(String, std::process::ExitStatus)> {
    which::which("gh")
        .context("`gh` CLI not found in PATH")
        .map_err(AkmError::Internal)?;
    let repo = args
        .repo
        .as_ref()
        .ok_or_else(|| AkmError::BadInput("--repo OWNER/NAME is required for `push gh`".into()))?;
    // gh secret set NAME --repo X reads from stdin when --body is OMITTED.
    // The earlier code passed `--body -` which would have stored the literal
    // `-` string as the secret.
    let mut cmd = Command::new("gh");
    cmd.arg("secret")
        .arg("set")
        .arg(&args.name)
        .arg("--repo")
        .arg(repo);
    let label = format!("gh secret set {} --repo {}", args.name, repo);
    spawn_with_redaction(cmd, value, &args.name, label)
}

fn push_fly(args: &Args, value: String) -> Result<(String, std::process::ExitStatus)> {
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
    spawn_with_redaction(cmd, stdin_payload, &args.name, label)
}

fn target_label(t: &Target) -> &'static str {
    match t {
        Target::Vercel => "vercel",
        Target::Gh => "gh",
        Target::Fly => "fly",
    }
}
