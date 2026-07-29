use clap::Args as ClapArgs;
use serde_json::json;
use std::io::{IsTerminal, Read};

use crate::audit;
use crate::cli::Global;
use crate::envelope;
use crate::error::{AkmError, Result};
use crate::exit;
use crate::keychain;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Path to a .env-style file. "-" (or omitted) reads stdin.
    pub file: Option<String>,

    /// Parse and report what would be stored without touching the keychain.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, PartialEq)]
pub struct Skip {
    pub line: usize,
    pub reason: String,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    let (content, input_mode) = match args.file.as_deref() {
        None | Some("-") => {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            (buf, "stdin")
        }
        Some(path) => {
            let s = std::fs::read_to_string(path).map_err(|e| {
                AkmError::BadInput(format!("cannot read '{}': {}", path, e))
            })?;
            (s, "file")
        }
    };

    let (entries, skipped) = parse_dotenv(&content);
    if entries.is_empty() && skipped.is_empty() {
        return Err(AkmError::BadInput("no NAME=VALUE lines found".into()));
    }

    let mut stored: Vec<serde_json::Value> = Vec::with_capacity(entries.len());
    for (name, value) in &entries {
        let existed = if args.dry_run {
            keychain::exists(name).unwrap_or(false)
        } else {
            let e = keychain::exists(name)?;
            keychain::set(name, value)?;
            e
        };
        stored.push(json!({
            "name": name,
            "action": if existed { "updated" } else { "created" },
        }));
    }

    if !args.dry_run && !entries.is_empty() {
        let mut entry = audit::entry_base("import", "ok");
        entry.keys = entries.iter().map(|(n, _)| n.clone()).collect();
        entry.input_mode = Some(input_mode);
        if let Err(e) = audit::append(&entry) {
            if !global.quiet {
                eprintln!("akm: warning: audit log write failed: {}", e);
            }
        }
    }

    let skipped_json: Vec<serde_json::Value> = skipped
        .iter()
        .map(|s| json!({ "line": s.line, "reason": s.reason }))
        .collect();

    let json_mode = global.json || !std::io::stdout().is_terminal();
    if json_mode {
        println!(
            "{}",
            envelope::ok(json!({
                "stored": stored,
                "skipped": skipped_json,
                "count": entries.len(),
                "dry_run": args.dry_run,
            }))
        );
    } else if !global.quiet {
        let verb = if args.dry_run { "would store" } else { "stored" };
        eprintln!("akm: {} {} key(s)", verb, entries.len());
        for s in &skipped {
            eprintln!("akm: skipped line {}: {}", s.line, s.reason);
        }
    }
    Ok(exit::SUCCESS)
}

/// Parse .env-style content: `NAME=VALUE` per line, `export ` prefix allowed,
/// `#` comments and blank lines ignored, single/double quotes stripped,
/// unquoted trailing ` # comment` stripped. Later duplicates win (matches
/// dotenv-loader behaviour). Invalid names and empty values are skipped with
/// a reason — never stored silently wrong.
pub fn parse_dotenv(content: &str) -> (Vec<(String, String)>, Vec<Skip>) {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut skipped: Vec<Skip> = Vec::new();

    for (idx, raw) in content.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some(eq) = line.find('=') else {
            skipped.push(Skip {
                line: lineno,
                reason: "no '=' separator".into(),
            });
            continue;
        };
        let name = line[..eq].trim();
        let mut value = line[eq + 1..].trim();

        let first = value.chars().next();
        if first == Some('"') || first == Some('\'') {
            // Quoted value: take everything inside the matching close quote,
            // dropping any trailing inline comment. Unterminated quotes fall
            // through and keep the raw value.
            let q = first.unwrap();
            if let Some(end) = value[1..].find(q) {
                value = &value[1..1 + end];
            }
        } else if let Some(hash) = value.find(" #") {
            value = value[..hash].trim_end();
        }

        if let Err(e) = keychain::validate_name(name) {
            skipped.push(Skip {
                line: lineno,
                reason: e.to_string(),
            });
            continue;
        }
        if value.is_empty() {
            skipped.push(Skip {
                line: lineno,
                reason: format!("empty value for '{}'", name),
            });
            continue;
        }
        // Later duplicate wins.
        out.retain(|(n, _)| n != name);
        out.push((name.to_string(), value.to_string()));
    }
    (out, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_export_lines() {
        let (e, s) = parse_dotenv("FOO=bar\nexport BAZ=qux\n");
        assert_eq!(
            e,
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("BAZ".to_string(), "qux".to_string())
            ]
        );
        assert!(s.is_empty());
    }

    #[test]
    fn strips_quotes_and_comments() {
        let (e, _) = parse_dotenv("A=\"with space\"\nB='single'\nC=plain # trailing\n# whole line\n\n");
        assert_eq!(
            e,
            vec![
                ("A".to_string(), "with space".to_string()),
                ("B".to_string(), "single".to_string()),
                ("C".to_string(), "plain".to_string())
            ]
        );
    }

    #[test]
    fn quoted_hash_preserved() {
        let (e, _) = parse_dotenv("A=\"val #notcomment\"\n");
        assert_eq!(e, vec![("A".to_string(), "val #notcomment".to_string())]);
    }

    #[test]
    fn quoted_value_with_trailing_comment() {
        let (e, _) = parse_dotenv("A=\"quoted value\" # test\n");
        assert_eq!(e, vec![("A".to_string(), "quoted value".to_string())]);
    }

    #[test]
    fn skips_bad_names_and_empty_values() {
        let (e, s) = parse_dotenv("lower=x\nGOOD=\nOK=1\nnoequals\n");
        assert_eq!(e, vec![("OK".to_string(), "1".to_string())]);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].line, 1);
        assert_eq!(s[1].line, 2);
        assert_eq!(s[2].line, 4);
    }

    #[test]
    fn later_duplicate_wins() {
        let (e, _) = parse_dotenv("A=first\nA=second\n");
        assert_eq!(e, vec![("A".to_string(), "second".to_string())]);
    }
}
