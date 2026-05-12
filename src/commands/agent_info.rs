use anyhow::Result;
use clap::Args as ClapArgs;
use serde_json::json;

use crate::cli::{Global, VERSION};
use crate::envelope;
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
            "add":  { "args": ["name", "[value]"], "flags": ["--stdin", "--json"], "stdin": "value if no argv" },
            "get":  { "args": ["name"], "flags": ["--raw", "--json"] },
            "run":  { "args": ["-- <cmd> [args...]"], "flags": ["--only KEY,KEY", "--all", "--no-redact"] },
            "push": { "args": ["target", "name"], "flags": ["--env", "--project", "--repo", "--app", "--json"], "targets": ["vercel","gh","fly"] },
            "list": { "flags": ["--json"] },
            "rm":   { "args": ["name"], "flags": ["--json"] },
            "audit":{ "flags": ["--limit N", "--json"] },
            "guard":{ "subcommands": ["install", "uninstall", "scan"] },
            "skill":{ "subcommands": ["install"], "description": "Install Claude Code skill so agents reach for akm automatically" },
            "agent-info": { "flags": ["--json"], "description": "This manifest" }
        },
        "keychain": {
            "backend": "macOS Login Keychain",
            "service": "com.paperfoot.akm"
        },
        "audit_log": "$HOME/.akm/audit.log"
    });
    println!("{}", envelope::ok(manifest));
    Ok(exit::SUCCESS)
}
