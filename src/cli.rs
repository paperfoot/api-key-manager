use clap::{Args as ClapArgs, Parser, Subcommand};
use std::io::IsTerminal;

use crate::commands;
use crate::envelope;
use crate::error::AkmError;
use crate::exit;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(
    name = "akm",
    version = VERSION,
    about = "Use macOS Keychain secrets in commands without copying their values.",
    long_about = "Store API keys in the macOS Login Keychain. Run commands with selected keys as environment variables, or supply a value through stdin. Keychain access is noninteractive; unavailable access returns an error.",
    after_long_help = "Examples:\n  akm run --only OPENAI_API_KEY -- python script.py\n  akm run --only API_KEY=PROJECT_API_KEY -- node server.js\n  akm stdin OPENAI_API_KEY -- gh secret set OPENAI_API_KEY\n  akm list --names-only\n  akm agent-info --command run\n\nStore values through your subprocess API's stdin: subprocess.run([\"akm\",\"add\",\"NAME\"], input=value).\nInstall the optional agent instructions with `akm skill install`."
)]
pub struct Cli {
    #[command(flatten)]
    pub global: Global,

    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Debug, Clone, Default, ClapArgs)]
pub struct Global {
    /// Emit JSON (automatic when piped); run/stdin completion goes to stderr.
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
    /// Write a key value to a child process's stdin (replaces push wrappers).
    Stdin(commands::stdin_cmd::Args),
    /// List stored key names.
    #[command(visible_alias = "ls")]
    List(commands::list::Args),
    /// Export raw key values for backup or migration. Audit-logged.
    Export(commands::export::Args),
    /// Import keys from a .env-style file or stdin.
    Import(commands::import_cmd::Args),
    /// Remove a key.
    Rm(commands::rm::Args),
    /// Print the audit log.
    Audit(commands::audit_cmd::Args),
    /// Manage the optional pre-commit hook that scans staged files for key prefixes.
    Guard(commands::guard::Args),
    /// Print the machine-readable capability manifest.
    #[command(visible_alias = "info")]
    AgentInfo(commands::agent_info::Args),
    /// Install or update the bundled agent skill (Claude Code, Codex, Gemini).
    #[command(name = "skill")]
    Skill(commands::skill_install::Args),
}

pub fn run() -> u8 {
    // Only inspect AKM flags before `--`; flags belonging to the child must
    // never change the wrapper's output format.
    let json_mode = !std::io::stdout().is_terminal()
        || std::env::args_os()
            .skip(1)
            .take_while(|arg| arg != "--")
            .any(|arg| arg == "--json");
    let Cli { global, command } = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            if matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                // Keep help/version plain text, as shell and Homebrew callers
                // have always expected. Discovery is the structured API.
                print!("{err}");
                return exit::SUCCESS;
            }
            // Parser errors can echo argv (including an accidentally supplied
            // credential). Return the error category, never that raw input.
            let message = match err.kind() {
                clap::error::ErrorKind::UnknownArgument => "unknown argument",
                clap::error::ErrorKind::InvalidSubcommand => "unknown command",
                clap::error::ErrorKind::MissingRequiredArgument => "missing required argument",
                clap::error::ErrorKind::ArgumentConflict => "conflicting arguments",
                _ => "invalid command arguments",
            };
            return report_error(&AkmError::BadInput(message.into()), json_mode);
        }
    };
    // AKM uses existing file-based Login Keychain items. This process-local
    // switch makes missing/locked Keychains fail instead of opening modal UI.
    // It does not unlock a Keychain or change permissions on any item.
    let _keychain_ui =
        match security_framework::os::macos::keychain::SecKeychain::disable_user_interaction() {
            Ok(guard) => guard,
            Err(error) => {
                return report_error(
                    &AkmError::KeychainUnavailable(format!(
                        "cannot disable Keychain dialogs: {error}"
                    )),
                    json_mode,
                )
            }
        };
    let result: Result<u8, AkmError> = match command {
        Cmd::Add(args) => commands::add::run(args, &global),
        Cmd::Get(args) => commands::get::run(args, &global),
        Cmd::Run(args) => commands::run::run(args, &global),
        Cmd::Stdin(args) => commands::stdin_cmd::run(args, &global),
        Cmd::List(args) => commands::list::run(args, &global),
        Cmd::Export(args) => commands::export::run(args, &global),
        Cmd::Import(args) => commands::import_cmd::run(args, &global),
        Cmd::Rm(args) => commands::rm::run(args, &global),
        Cmd::Audit(args) => commands::audit_cmd::run(args, &global),
        Cmd::Guard(args) => commands::guard::run(args, &global),
        Cmd::AgentInfo(args) => commands::agent_info::run(args, &global),
        Cmd::Skill(args) => commands::skill_install::run(args, &global),
    };
    match result {
        Ok(code) => code,
        Err(err) => report_error(&err, global.json || !std::io::stdout().is_terminal()),
    }
}

fn report_error(err: &AkmError, json_mode: bool) -> u8 {
    if json_mode {
        eprintln!(
            "{}",
            envelope::err(err.code_str(), err.to_string(), Some(err.suggestion()))
        );
    } else {
        eprintln!("akm: {}: {}\n{}", err.code_str(), err, err.suggestion());
    }
    err.exit_code()
}
