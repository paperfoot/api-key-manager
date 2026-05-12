use clap::Args as ClapArgs;
use serde_json::json;

use crate::cli::{Global, VERSION};
use crate::envelope;
use crate::error::Result;
use crate::exit;

#[derive(Debug, ClapArgs)]
pub struct Args {}

pub fn run(_args: Args, _global: &Global) -> Result<u8> {
    let manifest = json!({
        "name": "akm",
        "version": VERSION,
        "description": "Agent-driven macOS Keychain CLI for API keys. Zero human friction.",
        "platforms": ["macos"],
        "envelope_schema": {
            "version": "1",
            "fields": ["version", "status", "data"],
            "error_fields": ["version", "status", "error.code", "error.message", "error.suggestion"]
        },
        "exit_codes": {
            "0": "success",
            "1": "transient",
            "2": "config",
            "3": "bad_input",
            "4": "rate_limited",
            "6": "not_found"
        },
        "commands": {
            "add":  {
                "args": ["name", "[value]"],
                "flags": ["--stdin", "--json"],
                "stdin": "value if no argv",
                "name_pattern": "[A-Z_][A-Z0-9_]*"
            },
            "get":  { "args": ["name"], "flags": ["--raw", "--json"], "default": "masked" },
            "run":  {
                "args": ["-- <cmd> [args...]"],
                "flags": ["--only KEY,KEY", "--all", "--no-redact"],
                "transport": "env",
                "redacts_child_output": true,
                "envelope_on": "stderr",
                "use_when": "the upstream tool reads secrets from environment variables"
            },
            "stdin": {
                "args": ["name", "-- <cmd> [args...]"],
                "flags": ["--no-redact", "--json"],
                "transport": "stdin",
                "redacts_child_output": true,
                "use_when": "the upstream tool reads the secret from standard input (e.g. `vercel env add`, `gh secret set` without --body, `flyctl secrets import` with NAME=VALUE format)"
            },
            "list": { "flags": ["--json"] },
            "rm":   { "args": ["name"], "flags": ["--json"] },
            "audit":{ "flags": ["--limit N", "--json"], "log_path": "$HOME/.akm/audit.log", "log_mode": "0600" },
            "guard":{ "subcommands": ["install", "uninstall", "scan"], "scans": "staged blobs (git show :PATH)" },
            "skill":{ "subcommands": ["install"], "description": "Install agent skill so AI coding agents reach for akm" },
            "agent-info": { "flags": ["--json"], "description": "This manifest" }
        },
        "keychain": {
            "backend": "macOS Login Keychain",
            "service": "com.paperfoot.akm",
            "enumeration": "SecItemCopyMatching via security-framework::item::ItemSearchOptions"
        },
        "audit_log": "$HOME/.akm/audit.log",
        "threat_model": {
            "in_scope": [
                "plaintext .env on disk",
                "keys in shell history",
                "keys in `ps -ef` argv",
                "keys committed to git",
                "keys re-appearing in agent transcripts",
                "build-tool printouts"
            ],
            "out_of_scope": [
                "malware running as the same user",
                "hostile agent that calls `akm get --raw` itself",
                "`ps -E` of own processes by the same user"
            ]
        }
    });
    println!("{}", envelope::ok(manifest));
    Ok(exit::SUCCESS)
}
