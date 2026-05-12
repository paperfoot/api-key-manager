use clap::{Args as ClapArgs, Parser, Subcommand};

use crate::commands;
use crate::envelope;
use crate::exit;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(
    name = "akm",
    version = VERSION,
    about = "Agent-driven macOS Keychain CLI for API keys. Zero human friction.",
    long_about = "akm stores API keys in the macOS Login Keychain and injects them into child processes \
                  without ever writing plaintext to disk, shell history, or process env. Designed so that \
                  AI coding agents (Claude Code, Cursor, Codex) can drive the entire workflow with no \
                  human-in-the-loop prompts.",
    after_long_help = "Tips:\n  - Use `akm run --only OPENAI_API_KEY,ANTHROPIC_API_KEY -- <cmd>` to scope injection.\n  - Use `akm push vercel <name> --project <p> --env production` to upload without copy-paste.\n  - Pipe values into `akm add NAME` via stdin — argv works but creates an extra copy in `ps` and scrollback.\n  - Run `akm agent-info --json` for a machine-readable capability manifest.\n  - Install the Claude Code skill: `akm skill install`.\n\nExamples:\n  echo \"sk-...\" | akm add OPENAI_API_KEY\n  akm run --only OPENAI_API_KEY -- python script.py\n  akm push gh OPENAI_API_KEY --repo me/myproj\n  akm list --json | jq '.data.keys[]'"
)]
pub struct Cli {
    #[command(flatten)]
    pub global: Global,

    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Debug, Clone, Default, ClapArgs)]
pub struct Global {
    /// Emit JSON envelope output on stdout (forced on when piped).
    #[arg(long, global = true)]
    pub json: bool,

    /// Suppress non-essential stderr output.
    #[arg(long, global = true)]
    pub quiet: bool,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Store a key. Reads value from argv, --value, or stdin.
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
    let result = match command {
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
        Err(e) => {
            let json_mode = global.json || !atty::is(atty::Stream::Stdout);
            if json_mode {
                println!("{}", envelope::err("internal_error", e.to_string(), None));
            } else {
                eprintln!("akm: error: {}", e);
            }
            exit::TRANSIENT
        }
    }
}
