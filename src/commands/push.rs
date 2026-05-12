use anyhow::{anyhow, Context, Result};
use clap::{Args as ClapArgs, ValueEnum};
use serde_json::json;
use std::io::{IsTerminal, Write};
use std::process::{Command, Stdio};

use crate::audit;
use crate::cli::Global;
use crate::envelope;
use crate::exit;
use crate::keychain;

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
    let value = keychain::get(&args.name)?;

    let (cmd_label, exit_status) = match args.target {
        Target::Vercel => push_vercel(&args, &value)?,
        Target::Gh => push_gh(&args, &value)?,
        Target::Fly => push_fly(&args, &value)?,
    };

    let ok = exit_status.success();
    let target_str = target_label(&args.target);
    let _ = audit::append(&audit::Entry {
        ts: audit::now(),
        akm_version: audit::AKM_VERSION,
        command: "push",
        keys: vec![args.name.clone()],
        input_mode: None,
        child_command: Some(cmd_label.clone()),
        injected_keys: None,
        push_target: Some(target_str),
        cwd: audit::cwd_string(),
        ppid: audit::ppid(),
        parent_exe: audit::parent_exe(audit::ppid()),
        status: if ok { "ok" } else { "upstream_failed" },
    });

    let code = if ok {
        exit::SUCCESS
    } else {
        exit::TRANSIENT
    };
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

fn push_vercel(args: &Args, value: &str) -> Result<(String, std::process::ExitStatus)> {
    which::which("vercel").context("`vercel` CLI not found in PATH")?;
    // `vercel env add NAME [env]` reads the value from stdin when piped.
    let mut cmd = Command::new("vercel");
    cmd.arg("env").arg("add").arg(&args.name).arg(&args.env);
    if let Some(p) = &args.project {
        cmd.arg("--cwd").arg(p);
    }
    cmd.stdin(Stdio::piped());
    let label = format!("vercel env add {} {}", args.name, args.env);
    let mut child = cmd.spawn()?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("failed to open vercel stdin"))?;
        stdin.write_all(value.as_bytes())?;
        stdin.write_all(b"\n")?;
    }
    let status = child.wait()?;
    Ok((label, status))
}

fn push_gh(args: &Args, value: &str) -> Result<(String, std::process::ExitStatus)> {
    which::which("gh").context("`gh` CLI not found in PATH")?;
    let repo = args
        .repo
        .as_ref()
        .ok_or_else(|| anyhow!("--repo OWNER/NAME is required for `push gh`"))?;
    // `gh secret set NAME --repo X --body -` reads from stdin.
    let mut cmd = Command::new("gh");
    cmd.arg("secret")
        .arg("set")
        .arg(&args.name)
        .arg("--repo")
        .arg(repo)
        .arg("--body")
        .arg("-");
    cmd.stdin(Stdio::piped());
    let label = format!("gh secret set {} --repo {}", args.name, repo);
    let mut child = cmd.spawn()?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("failed to open gh stdin"))?;
        stdin.write_all(value.as_bytes())?;
    }
    let status = child.wait()?;
    Ok((label, status))
}

fn push_fly(args: &Args, value: &str) -> Result<(String, std::process::ExitStatus)> {
    // `flyctl secrets set KEY=VALUE` places the value on argv (visible in ps).
    // `flyctl secrets import` reads KEY=VALUE pairs from stdin, which is safer.
    let bin = which::which("fly")
        .or_else(|_| which::which("flyctl"))
        .context("`fly` / `flyctl` CLI not found in PATH")?;
    let app = args
        .app
        .as_ref()
        .ok_or_else(|| anyhow!("--app APPNAME is required for `push fly`"))?;
    let mut cmd = Command::new(bin);
    cmd.arg("secrets").arg("import").arg("--app").arg(app);
    cmd.stdin(Stdio::piped());
    let label = format!("fly secrets import --app {}", app);
    let mut child = cmd.spawn()?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("failed to open fly stdin"))?;
        writeln!(stdin, "{}={}", args.name, value)?;
    }
    let status = child.wait()?;
    Ok((label, status))
}

fn target_label(t: &Target) -> &'static str {
    match t {
        Target::Vercel => "vercel",
        Target::Gh => "gh",
        Target::Fly => "fly",
    }
}
