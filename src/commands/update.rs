//! Instructions-only update (agent-cli-framework update standard). AKM does
//! not query releases or replace itself: the installation's owner upgrades it.
use clap::Args as ClapArgs;
use serde_json::json;
use std::path::{Path, PathBuf};

use crate::cli::{Global, VERSION};
use crate::envelope;
use crate::error::Result;
use crate::exit;

const RELEASES: &str = "https://github.com/paperfoot/api-key-manager/releases/latest";

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Check only; AKM never installs, so this matches the default
    #[arg(long)]
    pub check: bool,
}

/// `(install_source, update_mode, upgrade_command, note)` for an executable.
fn channel(
    exe: &Path,
    cargo_bin: Option<&Path>,
) -> (
    &'static str,
    &'static str,
    Option<&'static str>,
    &'static str,
) {
    let path = exe.to_string_lossy();
    if path.contains("/Cellar/") {
        return (
            "homebrew",
            "package_manager",
            Some("brew upgrade paperfoot/tap/akm"),
            "The Homebrew build is signed, so Keychain access carries over",
        );
    }
    if cargo_bin.is_some_and(|bin| exe.starts_with(bin)) {
        return (
            "cargo",
            "package_manager",
            Some("cargo install api-key-manager --locked"),
            "Cargo builds are ad-hoc signed; the rebuilt binary can need authorizing in Keychain Access before it reads existing keys. Keep the old binary until the new one reads a key",
        );
    }
    (
        "unknown",
        "instructions_only",
        None,
        "Download the signed release from release_url",
    )
}

fn cargo_bin() -> Option<PathBuf> {
    std::env::var_os("CARGO_HOME")
        .map(|home| PathBuf::from(home).join("bin"))
        .or_else(|| dirs::home_dir().map(|home| home.join(".cargo").join("bin")))
}

pub fn run(_args: Args, global: &Global) -> Result<u8> {
    let exe = std::env::current_exe()?;
    // Homebrew links bin/akm into the Cellar; resolve to see the owner.
    let exe = exe.canonicalize().unwrap_or(exe);
    let cargo_bin = cargo_bin().map(|bin| bin.canonicalize().unwrap_or(bin));
    let (source, mode, command, note) = channel(&exe, cargo_bin.as_deref());
    let data = json!({
        "current_version": VERSION,
        "latest_version": null,
        "status": "not_checked",
        "install_source": source,
        "update_mode": mode,
        "upgrade_command": command,
        "release_url": RELEASES,
        "requires_skill_reinstall": true,
        "after_upgrade": "akm skill install",
        "note": note,
    });
    if global.json_mode() {
        println!("{}", envelope::ok(data));
    } else if !global.quiet {
        println!("akm {VERSION} installed via {source}; latest version not checked");
        match command {
            Some(command) => println!("Upgrade with: {command}"),
            None => println!("Release: {RELEASES}"),
        }
        println!("{note}.\nAfter upgrading, run: akm skill install");
    }
    Ok(exit::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_the_owning_channel() {
        let cargo = Path::new("/Users/u/.cargo/bin");
        let brew = channel(
            Path::new("/opt/homebrew/Cellar/akm/0.4.0/bin/akm"),
            Some(cargo),
        );
        assert_eq!(brew.0, "homebrew");
        assert_eq!(brew.2, Some("brew upgrade paperfoot/tap/akm"));
        let cargo_install = channel(Path::new("/Users/u/.cargo/bin/akm"), Some(cargo));
        assert_eq!(cargo_install.0, "cargo");
        assert_eq!(
            cargo_install.2,
            Some("cargo install api-key-manager --locked")
        );
        let unknown = channel(Path::new("/usr/local/bin/akm"), Some(cargo));
        assert_eq!(
            (unknown.0, unknown.1, unknown.2),
            ("unknown", "instructions_only", None)
        );
    }
}
