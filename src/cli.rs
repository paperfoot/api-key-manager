use clap::{Args as ClapArgs, Parser, Subcommand};

use crate::commands;
use crate::envelope;
use crate::error::AkmError;
use crate::exit;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(
    name = "akm",
    version = VERSION,
    about = "Agent-driven macOS Keychain CLI for API keys. Zero human friction.",
    long_about = "akm stores API keys in the macOS Login Keychain and injects them into child processes \
                  without writing plaintext to disk, shell history, or process argv. Designed so that AI \
                  coding agents (Claude Code, Cursor, Codex) can drive the entire workflow with no \
                  human-in-the-loop prompts.",
    after_long_help = "Tips:\n  - From an agent, pass key values via the subprocess stdin API (e.g. Python\n    `subprocess.run([\"akm\",\"add\",\"NAME\"], input=value)`). Avoid wrapping the value in a shell command — it lands in shell history.\n  - Use `akm run --only OPENAI_API_KEY -- <cmd>` to scope injection. `--all` injects every stored key (large blast radius).\n  - Use `akm push vercel <name> --env production` to upload without copy-paste.\n  - Run `akm agent-info --json` for a machine-readable capability manifest.\n  - Install the agent skill: `akm skill install`.\n\nExamples:\n  printf %s \"$VALUE\" | akm add OPENAI_API_KEY\n  akm run --only OPENAI_API_KEY -- python script.py\n  akm push gh OPENAI_API_KEY --repo me/myproj\n  akm list --json | jq '.data.keys[]'"
)]
pub struct Cli {
    #[command(flatten)]
    pub global: Global,

    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Debug, Clone, Default, ClapArgs)]
pub struct Global {
    /// Emit JSON envelope output on stdout (forced on when stdout is piped).
    #[arg(long, global = true)]
    pub json: bool,

    /// Suppress non-essential stderr output.
    #[arg(long, global = true)]
    pub quiet: bool,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Store a key. Reads value from argv or stdin.
    Add(commands::add::Args),
    /// Retrieve a key. Masked by default; use --raw for the unmasked value.
    Get(commands::get::Args),
    /// Run a command with keys injected as environment variables.
    Run(commands::run::Args),
    /// Push a key to a deployment platform (vercel, gh, fly).
    Push(commands::push::Args),
    /// List stored key names.
    List(commands::list::Args),
    /// Remove a key.
    Rm(commands::rm::Args),
    /// Print the audit log.
    Audit(commands::audit_cmd::Args),
    /// Manage the optional pre-commit hook that scans staged files for key prefixes.
    Guard(commands::guard::Args),
    /// Print the machine-readable capability manifest.
    AgentInfo(commands::agent_info::Args),
    /// Install or update the bundled agent skill (Claude Code, Codex, Gemini).
    #[command(name = "skill")]
    Skill(commands::skill_install::Args),
}

pub fn run() -> u8 {
    let Cli { global, command } = Cli::parse();
    let result: Result<u8, AkmError> = match command {
        Cmd::Add(args) => commands::add::run(args, &global),
        Cmd::Get(args) => commands::get::run(args, &global),
        Cmd::Run(args) => commands::run::run(args, &global),
        Cmd::Push(args) => commands::push::run(args, &global),
        Cmd::List(args) => commands::list::run(args, &global),
        Cmd::Rm(args) => commands::rm::run(args, &global),
        Cmd::Audit(args) => commands::audit_cmd::run(args, &global),
        Cmd::Guard(args) => commands::guard::run(args, &global),
        Cmd::AgentInfo(args) => commands::agent_info::run(args, &global),
        Cmd::Skill(args) => commands::skill_install::run(args, &global),
    };
    match result {
        Ok(code) => code,
        Err(err) => {
            // For machine consumers we always emit a JSON error envelope on
            // stdout. For humans (TTY stdout, not --json) we use stderr.
            let json_mode = global.json || !atty::is(atty::Stream::Stdout);
            if json_mode {
                println!(
                    "{}",
                    envelope::err(err.code_str(), err.to_string(), None)
                );
            } else {
                eprintln!("akm: {}: {}", err.code_str(), err);
            }
            // BAD_INPUT cap defensively to avoid leaking surprising codes.
            let code = err.exit_code();
            if code == 0 {
                exit::TRANSIENT
            } else {
                code
            }
        }
    }
}
