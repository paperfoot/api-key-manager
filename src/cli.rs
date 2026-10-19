use clap::{Args as ClapArgs, Parser, Subcommand};
use std::ffi::OsString;
use std::io::IsTerminal;

use crate::commands;
use crate::envelope;
use crate::error::AkmError;
use crate::exit;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP_FOOTER: &str = "\
Tips:
  - Pass a value to `akm add NAME` on stdin, e.g. subprocess.run([\"akm\",\"add\",\"NAME\"], input=value)
  - `run` injects environment variables; `stdin` writes the value to the child's stdin
  - Both redact supplied values from child output and return the child's exit code
  - Piped output is JSON; `akm agent-info --command run` describes one command
  - Run `akm doctor` when Keychain access fails

Examples:
  akm run --only OPENAI_API_KEY -- python script.py
  akm run --only API_KEY=PROJECT_API_KEY -- node server.js
  akm stdin OPENAI_API_KEY -- gh secret set OPENAI_API_KEY
  akm list --names-only
  akm agent-info --command run";

#[derive(Debug, Parser)]
#[command(
    name = "akm",
    version = VERSION,
    about = "Use macOS Keychain secrets in commands without copying their values.",
    long_about = "Store API keys in the macOS Login Keychain. Run commands with selected keys as environment variables, or supply a value through stdin. Keychain access is noninteractive; unavailable access returns an error.",
    after_long_help = HELP_FOOTER
)]
pub struct Cli {
    #[command(flatten)]
    pub global: Global,

    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Debug, Clone, Default, ClapArgs)]
pub struct Global {
    /// Force JSON output (automatic when piped)
    #[arg(long, global = true)]
    pub json: bool,

    /// Suppress informational stderr output
    #[arg(long, global = true)]
    pub quiet: bool,
}

impl Global {
    /// JSON when asked for or when stdout is not a terminal.
    pub fn json_mode(&self) -> bool {
        self.json || !std::io::stdout().is_terminal()
    }
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Store a key; pass the value on stdin
    Add(commands::add::Args),
    /// Show a key, masked unless --raw
    Get(commands::get::Args),
    /// Run a command with keys as environment variables
    Run(commands::run::Args),
    /// Run a command with a key's value on its stdin
    Stdin(commands::stdin_cmd::Args),
    /// List stored key names
    #[command(visible_alias = "ls")]
    List(commands::list::Args),
    /// Print raw values for backup or migration (audit-logged)
    Export(commands::export::Args),
    /// Store keys from a .env file or stdin
    Import(commands::import_cmd::Args),
    /// Copy keys from an older AKM binary; originals are kept
    Migrate(commands::migrate::Args),
    /// Remove a key
    #[command(visible_alias = "delete")]
    Rm(commands::rm::Args),
    /// Show recent audit log entries
    Audit(commands::audit_cmd::Args),
    /// Optional pre-commit hook that blocks staged key prefixes
    Guard(commands::guard::Args),
    /// Machine-readable capability manifest
    #[command(visible_alias = "info")]
    AgentInfo(commands::agent_info::Args),
    /// Manage the bundled agent skill
    Skill(commands::skill_install::Args),
    /// Show AKM's fixed locations; there is no config file
    Config(commands::config::Args),
    /// Check Keychain access, signature, skill and audit log
    Doctor,
    /// Show how to upgrade this installation
    Update(commands::update::Args),
    /// Hidden: deterministic exit-code trigger for contract tests
    #[command(hide = true)]
    Contract(commands::contract::Args),
}

impl Cmd {
    /// Commands that open the Keychain and so must never show its UI.
    fn uses_keychain(&self) -> bool {
        matches!(
            self,
            Cmd::Add(_)
                | Cmd::Get(_)
                | Cmd::Run(_)
                | Cmd::Stdin(_)
                | Cmd::List(_)
                | Cmd::Export(_)
                | Cmd::Import(_)
                | Cmd::Migrate(_)
                | Cmd::Rm(_)
                | Cmd::Doctor
        )
    }
}

pub fn run() -> u8 {
    // Only inspect AKM flags before `--`; flags belonging to the child must
    // never change the wrapper's output format.
    let json_flag = std::env::args_os()
        .skip(1)
        .take_while(|arg| arg != "--")
        .any(|arg| arg == "--json");
    let json_mode = json_flag || !std::io::stdout().is_terminal();
    let Cli { global, command } = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            if matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                // Help is read, not parsed: plain text even when piped.
                // An explicit --json wraps it in a success envelope.
                if json_flag {
                    let usage = err.to_string();
                    println!(
                        "{}",
                        envelope::ok(serde_json::json!({"usage": usage.trim_end()}))
                    );
                } else {
                    print!("{err}");
                }
                return exit::SUCCESS;
            }
            let args: Vec<OsString> = std::env::args_os().skip(1).collect();
            return report_error(&explain_parse_error(&err, &args), json_mode);
        }
    };
    // AKM uses existing file-based Login Keychain items. This process-local
    // switch makes missing/locked Keychains fail instead of opening modal UI.
    // It does not unlock a Keychain or change permissions on any item.
    let _keychain_ui = if command.uses_keychain() {
        match security_framework::os::macos::keychain::SecKeychain::disable_user_interaction() {
            Ok(guard) => Some(guard),
            Err(error) => {
                return report_error(
                    &AkmError::KeychainUnavailable(format!(
                        "cannot disable Keychain dialogs: {error}"
                    )),
                    json_mode,
                )
            }
        }
    } else {
        None
    };
    let result: Result<u8, AkmError> = match command {
        Cmd::Add(args) => commands::add::run(args, &global),
        Cmd::Get(args) => commands::get::run(args, &global),
        Cmd::Run(args) => commands::run::run(args, &global),
        Cmd::Stdin(args) => commands::stdin_cmd::run(args, &global),
        Cmd::List(args) => commands::list::run(args, &global),
        Cmd::Export(args) => commands::export::run(args, &global),
        Cmd::Import(args) => commands::import_cmd::run(args, &global),
        Cmd::Migrate(args) => commands::migrate::run(args, &global),
        Cmd::Rm(args) => commands::rm::run(args, &global),
        Cmd::Audit(args) => commands::audit_cmd::run(args, &global),
        Cmd::Guard(args) => commands::guard::run(args, &global),
        Cmd::AgentInfo(args) => commands::agent_info::run(args),
        Cmd::Skill(args) => commands::skill_install::run(args, &global),
        Cmd::Config(args) => commands::config::run(args, &global),
        Cmd::Doctor => commands::doctor::run(&global),
        Cmd::Update(args) => commands::update::run(args, &global),
        Cmd::Contract(args) => commands::contract::run(args, &global),
    };
    match result {
        Ok(code) => code,
        Err(err) => report_error(&err, global.json_mode()),
    }
}

fn report_error(err: &AkmError, json_mode: bool) -> u8 {
    if json_mode {
        eprintln!(
            "{}",
            envelope::err(
                err.code_str(),
                err.to_string(),
                &err.suggestion(),
                err.retryable(),
                err.details(),
            )
        );
    } else {
        eprintln!("akm: {}: {}\n{}", err.code_str(), err, err.suggestion());
        if let Some(details) = err.details() {
            eprintln!("{details:#}");
        }
    }
    err.exit_code()
}

/// A command's own arguments: no globals, hidden args, or help/version.
pub fn own_args(command: &clap::Command) -> impl Iterator<Item = &clap::Arg> {
    use clap::ArgAction;
    command.get_arguments().filter(|a| {
        !a.is_hide_set()
            && !a.is_global_set()
            && !matches!(
                a.get_action(),
                ArgAction::Help | ArgAction::HelpShort | ArgAction::HelpLong | ArgAction::Version
            )
    })
}

/// Longest flag or subcommand list a parse-error hint spells out; past it,
/// the hint names the scoped `agent-info` lookup instead.
const INLINE_LIMIT: usize = 12;

/// What the command at `path` accepts, in one sentence: its flags, or the
/// subcommands of a group, so a retry needs no lookup.
pub fn accepts(command: &clap::Command, path: &str) -> String {
    let shown = format!("akm {path}").trim_end().to_string();
    let (kind, names): (&str, Vec<String>) = if command.has_subcommands() {
        let names = command
            .get_subcommands()
            .filter(|c| !c.is_hide_set() && c.get_name() != "help")
            .map(|c| c.get_name().to_string());
        ("Commands", names.collect())
    } else {
        let names = own_args(command).filter_map(|a| {
            let long = a.get_long()?;
            Some(match a.get_short() {
                Some(short) => format!("-{short}/--{long}"),
                None => format!("--{long}"),
            })
        });
        ("Flags", names.collect())
    };
    match names.len() {
        0 if kind == "Flags" => format!("`{shown}` takes no flags."),
        n if n <= INLINE_LIMIT => format!("{kind} for `{shown}`: {}.", names.join(", ")),
        _ if path.is_empty() => "List commands with: akm agent-info".to_string(),
        _ => format!(
            "See all {}: akm agent-info --command \"{path}\"",
            kind.to_lowercase()
        ),
    }
}

/// A parse error as an AKM error. The message names the problem; the
/// suggestion lists what the deepest command in `args` accepts plus its usage
/// line. Argv can hold an accidentally supplied credential, so only text
/// derived from the command definition is used, never the offending token.
pub fn explain_parse_error(err: &clap::Error, args: &[OsString]) -> AkmError {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    use clap::CommandFactory;

    let mut root = Cli::command();
    root.build();
    let mut command = &root;
    let mut path = Vec::new();
    for arg in args {
        if arg == "--" || !command.has_subcommands() {
            break;
        }
        if let Some(sub) = command.find_subcommand(arg) {
            path.push(sub.get_name());
            command = sub;
        }
    }
    let path = path.join(" ");
    let shown = format!("akm {path}").trim_end().to_string();

    // Context kinds whose values come from the command definition.
    let context = |kind: ContextKind| -> Vec<String> {
        match err.get(kind) {
            Some(ContextValue::String(s)) => vec![s.clone()],
            Some(ContextValue::Strings(v)) => v.clone(),
            _ => Vec::new(),
        }
    };
    let defined_arg = || context(ContextKind::InvalidArg).join(", ");
    let did_you_mean = |kind: ContextKind| match context(kind).first() {
        Some(suggested) => format!("; did you mean `{suggested}`?"),
        None => String::new(),
    };

    let message = match err.kind() {
        ErrorKind::InvalidSubcommand => format!(
            "unknown command for `{shown}`{}",
            did_you_mean(ContextKind::SuggestedSubcommand)
        ),
        ErrorKind::UnknownArgument => format!(
            "unexpected argument for `{shown}`{}",
            did_you_mean(ContextKind::SuggestedArg)
        ),
        ErrorKind::MissingRequiredArgument => {
            format!("missing required argument: {}", defined_arg())
        }
        ErrorKind::ArgumentConflict => format!(
            "{} cannot be used with {}",
            defined_arg(),
            context(ContextKind::PriorArg).join(", ")
        ),
        ErrorKind::InvalidValue => {
            let valid = context(ContextKind::ValidValue);
            if valid.is_empty() {
                format!("invalid value for {}", defined_arg())
            } else {
                format!(
                    "invalid value for {}; accepted: {}",
                    defined_arg(),
                    valid.join(", ")
                )
            }
        }
        ErrorKind::ValueValidation => format!("invalid value for {}", defined_arg()),
        ErrorKind::MissingSubcommand | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            format!("`{shown}` needs a subcommand")
        }
        ErrorKind::TooManyValues | ErrorKind::TooFewValues | ErrorKind::WrongNumberOfValues => {
            format!("wrong number of values for {}", defined_arg())
        }
        _ => format!("invalid arguments for `{shown}`"),
    };

    let mut suggestion = accepts(command, &path);
    if !command.has_subcommands() {
        let usage = command.clone().render_usage().to_string();
        let usage = usage.trim();
        suggestion.push_str(&format!(
            " Usage: {}",
            usage.strip_prefix("Usage: ").unwrap_or(usage)
        ));
    }
    AkmError::Usage {
        message,
        suggestion,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, ArgAction, Command};

    #[test]
    fn long_flag_lists_point_at_scoped_discovery() {
        let mut wide = Command::new("wide");
        for i in 0..=INLINE_LIMIT {
            let name: &'static str = format!("f{i}").leak();
            wide = wide.arg(Arg::new(name).long(name).action(ArgAction::SetTrue));
        }
        assert_eq!(
            accepts(&wide, "wide"),
            "See all flags: akm agent-info --command \"wide\""
        );
        let narrow = Command::new("narrow").arg(Arg::new("n").long("limit").short('n'));
        assert_eq!(
            accepts(&narrow, "narrow"),
            "Flags for `akm narrow`: -n/--limit."
        );
        assert_eq!(
            accepts(&Command::new("bare"), "bare"),
            "`akm bare` takes no flags."
        );
    }

    #[test]
    fn parse_errors_name_accepted_flags_without_echoing_argv() {
        let argv = ["list", "--credential=synthetic-sensitive-value"];
        let err = Cli::try_parse_from(std::iter::once("akm").chain(argv)).unwrap_err();
        let args: Vec<OsString> = argv.iter().map(OsString::from).collect();
        let error = explain_parse_error(&err, &args);
        let (message, suggestion) = (error.to_string(), error.suggestion());
        assert!(!message.contains("synthetic"));
        assert!(!suggestion.contains("synthetic"));
        assert!(suggestion.starts_with("Flags for `akm list`: --long, --names-only."));
        assert!(suggestion.contains("Usage: akm list"));
        assert_eq!(error.exit_code(), 3);
    }
}
