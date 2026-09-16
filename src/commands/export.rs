use clap::Args as ClapArgs;
use serde_json::json;

use crate::audit;
use crate::cli::Global;
use crate::envelope;
use crate::error::{AkmError, Result};
use crate::exit;
use crate::keychain;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Comma-separated subset of keys to export (default: all stored keys).
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,

    /// Output format: "json" (envelope with raw values) or "env"
    /// (shell-safe NAME=value lines, suitable for `> backup.env`).
    #[arg(long, default_value = "json", value_parser = ["json", "env"])]
    pub format: String,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    let names = if args.only.is_empty() {
        keychain::list_names()?
    } else {
        for n in &args.only {
            keychain::validate_name(n).map_err(|e| AkmError::BadInput(e.to_string()))?;
        }
        args.only.clone()
    };

    if names.is_empty() {
        return Err(AkmError::NotFound("no keys stored".into()));
    }

    let mut pairs: Vec<(String, String)> = Vec::with_capacity(names.len());
    for name in &names {
        let v = keychain::get_with_status(name)?;
        pairs.push((name.clone(), v));
    }

    let mut entry = audit::entry_base("export", "ok");
    entry.keys = names.clone();
    if let Err(e) = audit::append(&entry) {
        if !global.quiet {
            eprintln!("akm: warning: audit log write failed: {}", e);
        }
    }

    if args.format == "env" {
        for (k, v) in &pairs {
            println!("{}={}", k, shell_quote(v));
        }
    } else {
        let mut map = serde_json::Map::new();
        for (k, v) in &pairs {
            map.insert(k.clone(), json!(v));
        }
        println!(
            "{}",
            envelope::ok(json!({ "count": pairs.len(), "keys": map }))
        );
    }
    Ok(exit::SUCCESS)
}

/// Quote a value for NAME=value output so the file survives `source` and
/// dotenv parsers. Values made of safe chars pass through unquoted.
pub fn shell_quote(v: &str) -> String {
    let safe = v
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_-./:+=@%,".contains(c));
    if safe && !v.is_empty() {
        v.to_string()
    } else {
        format!("'{}'", v.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::shell_quote;

    #[test]
    fn safe_values_unquoted() {
        assert_eq!(shell_quote("sk-abc123_DEF"), "sk-abc123_DEF");
    }

    #[test]
    fn spaces_get_quoted() {
        assert_eq!(shell_quote("a b"), "'a b'");
    }

    #[test]
    fn single_quotes_escaped() {
        assert_eq!(shell_quote("a'b"), r"'a'\''b'");
    }
}
