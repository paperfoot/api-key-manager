//! Discovery derived from the same Clap tree that executes commands.
//! The default manifest lists one generated signature line per command;
//! `--command PATH` returns the selected commands in full, with the semantic
//! annotations below (effects, examples, result fields).
use std::fmt::Write;

use clap::{Arg, ArgAction, Args as ClapArgs, Command, CommandFactory};
use serde_json::{json, Map, Value};

use crate::cli::{own_args, Cli, VERSION};
use crate::error::{AkmError, Result};

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Inspect one command or group, e.g. run or "skill status"
    #[arg(long, value_name = "PATH")]
    pub command: Option<String>,
}

fn argument(arg: &Arg) -> Value {
    let boolean = matches!(arg.get_action(), ArgAction::SetTrue | ArgAction::SetFalse);
    let mut value = json!({
        "name": arg.get_long().map(|s| format!("--{s}"))
            .unwrap_or_else(|| arg.get_id().to_string()),
        "type": if boolean { "bool" } else { "string" },
        "required": arg.is_required_set(),
        "description": arg.get_help().map(ToString::to_string).unwrap_or_default(),
    });
    if arg.is_positional() {
        value["kind"] = json!("positional");
    }
    if arg.is_last_set() {
        value["after_double_dash"] = json!(true);
    }
    if matches!(arg.get_action(), ArgAction::Append) {
        value["repeats"] = json!(true);
    }
    if let Some(delimiter) = arg.get_value_delimiter() {
        value["delimiter"] = json!(delimiter.to_string());
    }
    if let Some(short) = arg.get_short() {
        value["short"] = json!(format!("-{short}"));
    }
    if let Some(default) = arg.get_default_values().first() {
        let default = default.to_string_lossy();
        value["default"] = if boolean {
            json!(default == "true")
        } else {
            json!(default)
        };
    }
    // SetTrue/SetFalse are switches, not value-taking boolean options.
    if let Some(values) = arg
        .get_value_parser()
        .possible_values()
        .filter(|_| !boolean)
    {
        value["values"] = values
            .filter(|v| !v.is_hide_set())
            .map(|v| json!(v.get_name()))
            .collect();
    }
    value
}

/// Every public leaf command by canonical path ("skill status"), in Clap order.
fn leaves<'a>(root: &'a Command, prefix: &str, result: &mut Vec<(String, &'a Command)>) {
    for command in root.get_subcommands().filter(|c| !c.is_hide_set()) {
        // Clap's generated help command is presentation, not a domain command.
        if command.get_name() == "help" {
            continue;
        }
        let path = format!("{prefix}{}", command.get_name());
        if command.has_subcommands() {
            leaves(command, &format!("{path} "), result);
        } else {
            result.push((path, command));
        }
    }
}

/// The command in full: description, args, options, defaults, values, aliases.
fn full(command: &Command) -> Value {
    let (args, options): (Vec<&Arg>, Vec<&Arg>) =
        own_args(command).partition(|a| a.is_positional());
    let mut value = json!({
        "description": command.get_about().map(ToString::to_string).unwrap_or_default(),
        "args": args.into_iter().map(argument).collect::<Vec<_>>(),
        "options": options.into_iter().map(argument).collect::<Vec<_>>(),
    });
    let aliases: Vec<_> = command.get_visible_aliases().collect();
    if !aliases.is_empty() {
        value["aliases"] = json!(aliases);
    }
    value
}

/// One line for the default manifest: `<name> [value] --stdin: Store a key`.
/// `<x>` required, `[x]` optional, `...` repeats, `--flag=` takes a value,
/// `--flag=<flag>` is a required flag, `--flag` alone is a switch, and
/// `-- <x...>` is everything after the double dash.
pub fn line(command: &Command) -> String {
    let mut line = String::new();
    for arg in own_args(command) {
        let id = arg.get_id().as_str();
        let many = if matches!(arg.get_action(), ArgAction::Append) {
            "..."
        } else {
            ""
        };
        if arg.is_positional() {
            let (open, close) = if arg.is_required_set() {
                ('<', '>')
            } else {
                ('[', ']')
            };
            let dashes = if arg.is_last_set() { "-- " } else { "" };
            let _ = write!(line, "{dashes}{open}{id}{many}{close} ");
        } else if let Some(long) = arg.get_long() {
            let value = match (arg.get_action().takes_values(), arg.is_required_set()) {
                (false, _) => String::new(),
                (true, false) => "=".into(),
                (true, true) => format!("=<{id}>"),
            };
            let _ = write!(line, "--{long}{value}{many} ");
        }
    }
    let about = command
        .get_about()
        .map(ToString::to_string)
        .unwrap_or_default();
    let mut line = match (line.trim_end(), about.as_str()) {
        ("", about) => about.to_string(),
        (syntax, "") => syntax.to_string(),
        (syntax, about) => format!("{syntax}: {about}"),
    };
    let aliases: Vec<_> = command.get_visible_aliases().collect();
    if !aliases.is_empty() {
        let _ = write!(line, " (alias: {})", aliases.join(", "));
    }
    line
}

/// Claims about behavior, not syntax. Tests check coverage and that every
/// example parses against the real CLI.
fn annotations() -> Value {
    json!({
        "add": {
            "effect": "write", "idempotent": true,
            "stdin": "the value (preferred); argv `value` is visible in ps and scrollback",
            "examples": [["add", "OPENAI_API_KEY"]],
            "output_fields": ["name", "input_mode"]
        },
        "get": {
            "effect": "read", "idempotent": true,
            "effect_detail": "Masked by default; --raw unmasks inside the JSON envelope (data.value); --value prints only the value, no newline, for programs (prefer run or stdin)",
            "examples": [["get", "OPENAI_API_KEY"], ["get", "OPENAI_API_KEY", "--value"]],
            "exit_behavior": "6 when missing, with similar stored names in error.details.candidates",
            "output_fields": ["name", "value", "masked"]
        },
        "run": {
            "effect": "mixed", "idempotent": false,
            "effect_detail": "Reads the named keys and runs the child; the child's effects are its own",
            "requires": "--only NAME[,NAME...] or --all",
            "transport": "env",
            "examples": [
                ["run", "--only", "OPENAI_API_KEY", "--", "node", "server.js"],
                ["run", "--only", "STRIPE_SECRET_KEY=PCC1_STRIPE_SECRET_KEY", "--", "node", "script.js"]
            ],
            "output": "child streams with injected values redacted; a completion envelope goes to stderr only with explicit --json",
            "exit_behavior": "the child's exit code (128+signal when killed); AKM's own failures use the manifest exit codes, with error.details.candidates on exit 6"
        },
        "stdin": {
            "effect": "mixed", "idempotent": false,
            "effect_detail": "Reads the key and writes it to the child's stdin; the child's effects are its own",
            "transport": "stdin",
            "examples": [
                ["stdin", "OPENAI_API_KEY", "--", "gh", "secret", "set", "OPENAI_API_KEY"],
                ["stdin", "OPENAI_API_KEY", "--format", "env", "--", "flyctl", "secrets", "import"]
            ],
            "output": "child streams with the supplied value redacted; a completion envelope goes to stderr only with explicit --json",
            "exit_behavior": "the child's exit code (128+signal when killed); AKM's own failures use the manifest exit codes, with error.details.candidates on exit 6"
        },
        "list": {
            "effect": "read", "idempotent": true,
            "effect_detail": "--names-only prints one name per line, even when piped",
            "examples": [["list"], ["list", "--names-only"]],
            "output_fields": ["count", "keys", "entries", "stale_after_days"]
        },
        "export": {
            "effect": "read", "idempotent": true,
            "effect_detail": "Prints raw secret values; use only for a requested backup or migration",
            "examples": [["export", "--only", "OPENAI_API_KEY", "--format", "env"]],
            "output_fields": ["count", "keys"]
        },
        "import": {
            "effect": "write", "idempotent": true,
            "effect_detail": "Creates or updates keys; never deletes the source file",
            "examples": [["import", ".env", "--dry-run"]],
            "output_fields": ["stored", "skipped", "count", "dry_run"]
        },
        "migrate": {
            "effect": "write", "idempotent": true,
            "effect_detail": "Copies values from the older binary through private pipes; originals are preserved",
            "examples": [["migrate", "--from", "/opt/homebrew/Cellar/akm/0.2.0/bin/akm", "--dry-run"]],
            "output_fields": ["dry_run", "migrated", "skipped", "originals_preserved"]
        },
        "rm": {
            "effect": "write", "idempotent": true,
            "effect_detail": "Removes the key from both namespaces; a missing key is a no-op",
            "examples": [["rm", "OLD_API_KEY"]],
            "output_fields": ["name", "removed"]
        },
        "audit": {
            "effect": "read", "idempotent": true,
            "examples": [["audit", "--limit", "10"]],
            "output_fields": ["entries", "path"]
        },
        "guard install": {
            "effect": "write", "idempotent": true,
            "effect_detail": "Writes .git/hooks/pre-commit; refuses to replace a hook AKM did not write",
            "examples": [["guard", "install"]],
            "output_fields": ["installed", "path"]
        },
        "guard uninstall": {
            "effect": "write", "idempotent": true,
            "effect_detail": "Removes only AKM's own hook",
            "examples": [["guard", "uninstall"]],
            "output_fields": ["removed", "path"]
        },
        "guard scan": {
            "effect": "read", "idempotent": true,
            "effect_detail": "Prefix matching can flag documentation examples",
            "examples": [["guard", "scan"]],
            "output_fields": ["hits"],
            "exit_behavior": "0 when clean; 3 with error.details.hits when candidates are staged"
        },
        "agent-info": {
            "effect": "read", "idempotent": true,
            "examples": [["agent-info", "--command", "run"], ["agent-info", "--command", "skill"]]
        },
        "skill install": {
            "effect": "write", "idempotent": true,
            "effect_detail": "Writes akm/SKILL.md under ~/.claude/skills, ~/.codex/skills and ~/.gemini/skills",
            "examples": [["skill", "install"]],
            "output_fields": ["installed"]
        },
        "skill status": {
            "effect": "read", "idempotent": true,
            "examples": [["skill", "status"]],
            "output_fields": ["version", "current", "skills"]
        },
        "config show": {
            "effect": "read", "idempotent": true,
            "examples": [["config", "show"]],
            "output_fields": ["config_file", "env_vars", "audit_log", "keychain_service", "legacy_keychain_service", "keychain_ui"]
        },
        "config path": {
            "effect": "read", "idempotent": true,
            "examples": [["config", "path"]],
            "output_fields": ["path", "config_file"]
        },
        "doctor": {
            "effect": "read", "idempotent": true,
            "examples": [["doctor"]],
            "output_fields": ["version", "checks", "summary"],
            "exit_behavior": "0 with no failed checks; 2 with the report in error.details"
        },
        "update": {
            "effect": "read", "idempotent": true,
            "effect_detail": "Returns the upgrade command for the owning install channel; never queries releases, downloads or replaces the binary",
            "examples": [["update", "--check"]],
            "output_fields": ["current_version", "latest_version", "status", "install_source", "update_mode", "upgrade_command", "release_url", "requires_skill_reinstall", "after_upgrade"]
        }
    })
}

fn root() -> Command {
    let mut root = Cli::command();
    root.build();
    root
}

/// Every public leaf command in full, with its semantic annotations.
fn entries(root: &Command) -> Map<String, Value> {
    let mut paths = Vec::new();
    leaves(root, "", &mut paths);
    let mut entries: Map<String, Value> = paths
        .into_iter()
        .map(|(path, command)| (path, full(command)))
        .collect();
    for (path, metadata) in annotations().as_object().expect("static object") {
        let entry = entries
            .get_mut(path)
            .and_then(Value::as_object_mut)
            .expect("annotation names a public command");
        entry.extend(metadata.as_object().expect("static object").clone());
    }
    entries
}

/// `agent-info --command PATH`: name, version, and the selected commands in
/// full. A leaf path selects itself; a group selects its descendants.
pub fn scoped(filter: &str) -> Result<Value> {
    let path = filter.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut entries = entries(&root());
    let prefix = format!("{path} ");
    entries.retain(|key, _| key == &path || key.starts_with(&prefix));
    if path.is_empty() || entries.is_empty() {
        return Err(AkmError::Usage {
            message: "unknown command path".into(),
            suggestion: "Use a command key from `akm agent-info`, e.g. run or \"skill status\"."
                .into(),
        });
    }
    Ok(json!({"name": "akm", "version": VERSION, "commands": entries}))
}

/// The default manifest: everything an agent needs to start, with one
/// generated line per command.
pub fn manifest() -> Value {
    let root = root();
    let mut paths = Vec::new();
    leaves(&root, "", &mut paths);
    let lines: Map<String, Value> = paths
        .into_iter()
        .map(|(path, command)| (path, json!(line(command))))
        .collect();
    let globals: Map<String, Value> = root
        .get_arguments()
        .filter(|a| a.is_global_set())
        .map(|a| {
            let mut value = argument(a);
            let name = value["name"].as_str().unwrap_or_default().to_string();
            value.as_object_mut().map(|v| v.remove("name"));
            (name, value)
        })
        .collect();
    json!({
        "name": "akm",
        "version": VERSION,
        "description": env!("CARGO_PKG_DESCRIPTION"),
        "platforms": ["macos"],
        "commands": lines,
        "global_flags": globals,
        "exit_codes": {
            "0": "Success",
            "1": "Runtime failure; check the outcome before retrying a write",
            "2": "Setup: Keychain unavailable, locked or denying access; run akm doctor",
            "3": "Invalid input; fix the request",
            "4": "Rate limited (not used by AKM)",
            "6": "Key not found; similar stored names are in error.details.candidates"
        },
        "child_exit_codes": "run and stdin exit with the child's code (128+signal when killed)",
        "envelope": {
            "version": crate::envelope::VERSION,
            "success": "{version,status:\"success\",data} on stdout",
            "error": "{version,status:\"error\",error:{code,message,suggestion,retryable?,details?}} on stderr"
        },
        "config": {
            "path": crate::audit::log_path().display().to_string(),
            "env_prefix": "AKM_",
            "note": "No config file or AKM_ variables; path is the audit log",
            "keychain_service": crate::keychain::SERVICE,
            "legacy_keychain_service": crate::keychain::LEGACY_SERVICE
        },
        "auto_json_when_piped": true
    })
}

pub fn run(args: Args) -> Result<u8> {
    let value = match args.command.as_deref() {
        Some(path) => scoped(path)?,
        None => manifest(),
    };
    println!("{value}");
    Ok(crate::exit::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn every_command_is_annotated_and_examples_parse() {
        let entries = entries(&root());
        assert_eq!(entries.len(), annotations().as_object().unwrap().len());
        for (path, entry) in &entries {
            assert!(
                matches!(entry["effect"].as_str(), Some("read" | "write" | "mixed")),
                "{path} needs a framework effect"
            );
            assert!(entry["idempotent"].is_boolean(), "{path} needs idempotent");
            if entry["effect"] == "mixed" {
                assert!(entry["effect_detail"].is_string(), "{path} explains mixed");
            }
            for example in entry["examples"].as_array().unwrap() {
                let argv = std::iter::once("akm").chain(
                    example
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap()),
                );
                assert!(Cli::try_parse_from(argv).is_ok(), "bad example: {example}");
            }
        }
    }

    #[test]
    fn scoped_discovery_selects_leaves_and_groups() {
        let full = entries(&root());
        let scoped_run = scoped("run").unwrap();
        assert_eq!(scoped_run["commands"]["run"], full["run"]);
        assert_eq!(scoped_run["commands"].as_object().unwrap().len(), 1);
        assert_eq!(
            scoped("skill").unwrap()["commands"]
                .as_object()
                .unwrap()
                .len(),
            2
        );
        assert!(scoped("does-not-exist").is_err());
        assert!(scoped("  ").is_err());
    }

    #[test]
    fn manifest_lines_match_the_parser() {
        let value = manifest();
        let commands = &value["commands"];
        assert_eq!(
            commands["run"],
            "--only=... --all --no-redact -- <command...>: Run a command with keys as environment variables"
        );
        assert_eq!(
            commands["list"],
            "--long --names-only: List stored key names (alias: ls)"
        );
        assert_eq!(commands["rm"], "<name>: Remove a key (alias: delete)");
        for flag in value["global_flags"].as_object().unwrap().values() {
            assert_eq!(flag["type"], "bool");
            assert!(flag.get("values").is_none());
        }
        assert!(Cli::try_parse_from(["akm", "list", "--long=true"]).is_err());
    }

    #[test]
    fn lines_render_required_optional_repeated_and_switch_syntax() {
        let command = Command::new("send")
            .about("Send a message")
            .visible_alias("s")
            .arg(Arg::new("to").required(true))
            .arg(Arg::new("files").action(ArgAction::Append))
            .arg(Arg::new("channel").long("channel").required(true))
            .arg(Arg::new("tag").long("tag").action(ArgAction::Append))
            .arg(Arg::new("limit").long("limit").short('n'))
            .arg(Arg::new("dry").long("dry-run").action(ArgAction::SetTrue));
        assert_eq!(
            line(&command),
            "<to> [files...] --channel=<channel> --tag=... --limit= --dry-run: Send a message (alias: s)"
        );
    }
}
