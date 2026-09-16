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
            if std::io::stdin().is_terminal() {
                return Err(AkmError::BadInput(
                    "provide a file path or pipe NAME=VALUE lines on stdin".into(),
                ));
            }
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            (buf, "stdin")
        }
        Some(path) => {
            let s = std::fs::read_to_string(path)
                .map_err(|e| AkmError::BadInput(format!("cannot read '{}': {}", path, e)))?;
            (s, "file")
        }
    };

    let (entries, skipped) = parse_dotenv(&content);
    if entries.is_empty() && skipped.is_empty() {
        return Err(AkmError::BadInput("no NAME=VALUE lines found".into()));
    }

    let mut stored: Vec<serde_json::Value> = Vec::with_capacity(entries.len());
    for (name, value) in &entries {
        let action = if args.dry_run {
            "would_store"
        } else {
            let existed = keychain::exists(name)?;
            keychain::set(name, value)?;
            if existed {
                "updated"
            } else {
                "created"
            }
        };
        stored.push(json!({
            "name": name,
            "action": action,
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
        let verb = if args.dry_run {
            "would store"
        } else {
            "stored"
        };
        eprintln!("akm: {} {} key(s)", verb, entries.len());
        for s in &skipped {
            eprintln!("akm: skipped line {}: {}", s.line, s.reason);
        }
    }
    Ok(exit::SUCCESS)
}

/// Parse .env-style content: `NAME=VALUE` per line, `export ` prefix allowed,
/// `#` comments and blank lines ignored, single/double quotes stripped,
/// unquoted trailing ` # comment` stripped; multiline quoted values supported. Later duplicates win (matches
/// dotenv-loader behaviour). Invalid names and empty values are skipped with
/// a reason — never stored silently wrong.
pub fn parse_dotenv(content: &str) -> (Vec<(String, String)>, Vec<Skip>) {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut skipped: Vec<Skip> = Vec::new();

    let mut lines = content.lines().enumerate().peekable();
    while let Some((idx, raw)) = lines.next() {
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
        if let Err(error) = keychain::validate_name(name) {
            skipped.push(Skip {
                line: lineno,
                reason: error.to_string(),
            });
            continue;
        }
        let mut raw_value = line[eq + 1..].trim_start().to_string();
        let value = loop {
            match parse_value(&raw_value) {
                Ok(value) => break Some(value),
                Err(()) => match lines.next() {
                    Some((_, next)) => {
                        raw_value.push('\n');
                        raw_value.push_str(next);
                    }
                    None => {
                        skipped.push(Skip {
                            line: lineno,
                            reason: "unterminated quoted value".into(),
                        });
                        break None;
                    }
                },
            }
        };
        let Some(value) = value else { continue };
        if value.is_empty() || value.contains('\0') {
            skipped.push(Skip {
                line: lineno,
                reason: "empty value or NUL byte".into(),
            });
            continue;
        }
        out.retain(|(n, _)| n != name);
        out.push((name.to_string(), value));
    }
    (out, skipped)
}

/// Literal dotenv/shell-quoted values, including AKM's export representation.
/// Never evaluate expansions, command substitutions, or shell code.
fn parse_value(input: &str) -> std::result::Result<String, ()> {
    let mut output = String::new();
    let mut chars = input.chars().peekable();
    let mut quote = None;
    let mut trailing_space = 0;
    while let Some(ch) = chars.next() {
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                } else {
                    output.push(ch);
                }
                trailing_space = 0;
            }
            Some('"') => {
                match ch {
                    '"' => quote = None,
                    '\\' => match chars.next() {
                        Some('n') => output.push('\n'),
                        Some('r') => output.push('\r'),
                        Some('t') => output.push('\t'),
                        Some(c @ ('"' | '\\' | '$' | '`')) => output.push(c),
                        Some(c) => {
                            output.push('\\');
                            output.push(c);
                        }
                        None => return Err(()),
                    },
                    _ => output.push(ch),
                }
                trailing_space = 0;
            }
            _ => match ch {
                '\'' | '"' => {
                    quote = Some(ch);
                    trailing_space = 0;
                }
                '#' if output.is_empty() || trailing_space > 0 => break,
                '\\' => {
                    let next = chars.next().ok_or(())?;
                    output.push(next);
                    trailing_space = 0;
                }
                _ => {
                    output.push(ch);
                    trailing_space = if ch.is_whitespace() {
                        trailing_space + ch.len_utf8()
                    } else {
                        0
                    };
                }
            },
        }
    }
    if quote.is_some() {
        return Err(());
    }
    output.truncate(output.len() - trailing_space);
    Ok(output)
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
        let (e, _) =
            parse_dotenv("A=\"with space\"\nB='single'\nC=plain # trailing\n# whole line\n\n");
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

#[cfg(test)]
mod roundtrip_tests {
    use super::*;
    #[test]
    fn exported_values_round_trip_without_evaluation() {
        for value in [
            "a'b",
            "a\nb",
            " leading and trailing ",
            "double\"quote",
            "back\\slash",
            "$(touch never) $HOME",
            "a # b",
        ] {
            let text = format!("KEY={}\n", crate::commands::export::shell_quote(value));
            let (entries, skipped) = parse_dotenv(&text);
            assert!(skipped.is_empty());
            assert_eq!(entries, vec![("KEY".to_string(), value.to_string())]);
        }
    }
    #[test]
    fn rejects_unterminated_quotes() {
        let (entries, skipped) = parse_dotenv("KEY='unfinished");
        assert!(entries.is_empty());
        assert_eq!(skipped[0].reason, "unterminated quoted value");
    }
}
