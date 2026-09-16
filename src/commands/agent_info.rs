//! Command syntax is derived from Clap; examples describe AKM's transports.
use crate::cli::{Cli, Global, VERSION};
use crate::error::{AkmError, Result};
use clap::{Arg, ArgAction, Args as ClapArgs, Command, CommandFactory};
use serde_json::{json, Map, Value};

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Inspect one command or group, e.g. run or "skill status".
    #[arg(long)]
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
    if arg.get_index().is_some() {
        value["kind"] = json!("positional");
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

fn commands(root: &Command, prefix: &str, result: &mut Map<String, Value>) {
    for command in root.get_subcommands().filter(|c| !c.is_hide_set()) {
        // Clap's generated help command is presentation, not a domain command.
        if command.get_name() == "help" {
            continue;
        }
        let path = format!("{prefix}{}", command.get_name());
        if command.get_subcommands().next().is_some() {
            commands(command, &format!("{path} "), result);
            continue;
        }
        let mut args = Vec::new();
        let mut options = Vec::new();
        for arg in command
            .get_arguments()
            .filter(|a| !a.is_hide_set() && !a.is_global_set())
        {
            if matches!(
                arg.get_action(),
                ArgAction::Help | ArgAction::HelpShort | ArgAction::HelpLong | ArgAction::Version
            ) {
                continue;
            }
            if arg.get_index().is_some() {
                args.push(argument(arg));
            } else {
                options.push(argument(arg));
            }
        }
        let mut value = json!({
            "description": command.get_about().map(ToString::to_string).unwrap_or_default(),
            "args": args,
            "options": options,
        });
        let aliases: Vec<_> = command.get_visible_aliases().collect();
        if !aliases.is_empty() {
            value["aliases"] = json!(aliases);
        }
        result.insert(path, value);
    }
}

fn annotations() -> Value {
    json!({
        "add": {"effect":"write", "stdin":"value when argv is omitted", "examples":[["add","OPENAI_API_KEY"]]},
        "get": {"effect":"read", "default":"masked", "raw_output":"JSON envelope when piped; --raw selects the unmasked value, not output format"},
        "run": {"effect":"execute", "requires":"--only NAME[,NAME...] or --all", "transport":"env", "use_when":"the child reads environment variables", "examples":[["run","--only","OPENAI_API_KEY","--","node","server.js"],["run","--only","STRIPE_SECRET_KEY=PCC1_STRIPE_SECRET_KEY","--","node","script.js"]], "output":"child streams, exact injected values redacted; completion on stderr only with explicit --json", "exit_behavior":"child exit code, including 128+signal; wrapper errors on stderr"},
        "stdin": {"effect":"execute", "transport":"stdin", "use_when":"the child reads the secret from stdin", "examples":[["stdin","OPENAI_API_KEY","--","gh","secret","set","OPENAI_API_KEY"],["stdin","OPENAI_API_KEY","--format","env","--","flyctl","secrets","import"]], "output":"child streams, exact supplied value redacted; completion on stderr only with explicit --json"},
        "list": {"effect":"read", "examples":[["list"],["list","--long"]]},
        "export": {"effect":"read", "use_when":"explicit backup or migration; output contains raw secrets", "audited":true},
        "import": {"effect":"write", "use_when":"requested dotenv migration; source file is never deleted", "examples":[["import",".env","--dry-run"]]},
        "rm": {"effect":"write", "idempotent":true},
        "audit": {"effect":"read", "examples":[["audit","--limit","10"]]},
        "guard install": {"effect":"write", "preserves_existing_hooks":true},
        "guard uninstall": {"effect":"write", "preserves_existing_hooks":true},
        "guard scan": {"effect":"read", "use_when":"explicit optional staged-secret scan; prefix matching can flag examples"},
        "skill install": {"effect":"write", "examples":[["skill","install"]]},
        "skill status": {"effect":"read", "examples":[["skill","status"]]},
        "agent-info": {"effect":"read", "examples":[["agent-info","--command","run"]]}
    })
}

fn manifest(filter: Option<&str>) -> Result<Value> {
    let mut root = Cli::command();
    root.build();
    let mut entries = Map::new();
    commands(&root, "", &mut entries);
    for (path, metadata) in annotations().as_object().unwrap() {
        let entry = entries.get_mut(path).expect("metadata matches Clap");
        entry
            .as_object_mut()
            .unwrap()
            .extend(metadata.as_object().unwrap().clone());
    }
    if let Some(filter) = filter {
        let path = filter.split_whitespace().collect::<Vec<_>>().join(" ");
        let prefix = format!("{path} ");
        entries.retain(|key, _| key == &path || key.starts_with(&prefix));
        if path.is_empty() || entries.is_empty() {
            return Err(AkmError::BadInput(
                "unknown command path; use a canonical path from `akm --help`".into(),
            ));
        }
    }
    let globals: Vec<_> = root
        .get_arguments()
        .filter(|arg| arg.is_global_set())
        .map(argument)
        .collect();
    Ok(json!({
        "name":"akm", "version":VERSION, "platforms":["macos"],
        "commands":entries, "global_flags":globals,
        "exit_codes":{"0":"success","1":"runtime failure","2":"setup","3":"bad_input","6":"not_found"},
        "output":{"envelope_version":"1","success":"ok","errors":"stderr","discovery":"data.commands in the existing success envelope", "help_version":"plain text"},
        "keychain":{"backend":"macOS Login Keychain","service":"com.paperfoot.akm", "interactive":false, "unavailable":"keychain_unavailable on stderr; check HOME and unlock the existing Keychain"},
        "threat_model":{"protects":"accidental disclosure through files, argv and child output", "trusts":"processes running as your user"}
    }))
}

pub fn run(args: Args, _global: &Global) -> Result<u8> {
    println!(
        "{}",
        crate::envelope::ok(manifest(args.command.as_deref())?)
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn metadata_covers_commands_and_examples_parse() {
        let manifest = manifest(None).unwrap();
        let commands = manifest["commands"].as_object().unwrap();
        assert_eq!(commands.len(), annotations().as_object().unwrap().len());
        for entry in commands.values() {
            assert!(entry.get("effect").is_some());
            if let Some(examples) = entry["examples"].as_array() {
                for example in examples {
                    let args = std::iter::once("akm").chain(
                        example
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|v| v.as_str().unwrap()),
                    );
                    assert!(Cli::try_parse_from(args).is_ok(), "bad example: {example}");
                }
            }
        }
    }

    #[test]
    fn scoped_discovery_preserves_contract() {
        let full = manifest(None).unwrap();
        let scoped = manifest(Some("run")).unwrap();
        assert_eq!(scoped["commands"]["run"], full["commands"]["run"]);
        assert_eq!(scoped["commands"].as_object().unwrap().len(), 1);
        assert_eq!(
            manifest(Some("skill")).unwrap()["commands"]
                .as_object()
                .unwrap()
                .len(),
            2
        );
        assert!(manifest(Some("does-not-exist")).is_err());
    }
}
