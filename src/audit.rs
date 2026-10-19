use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// The live log rotates to `audit.log.1` (then `.2`) past this size, so the
/// three files together stay under 48 MB.
pub const ROTATE_BYTES: u64 = 16 * 1024 * 1024;
const ROTATED_FILES: usize = 2;

#[derive(Debug, Serialize)]
pub struct Entry<'a> {
    pub ts: String,
    pub akm_version: &'a str,
    pub command: &'a str,
    /// Pairs the `started` and `ok|child_nonzero|upstream_failed` entries of a
    /// single run/push so log consumers can correlate them under concurrent
    /// invocations. None for one-shot operations (add, get, rm, list).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub keys: Vec<String>,
    pub input_mode: Option<&'a str>,
    pub child_command: Option<String>,
    pub injected_keys: Option<Vec<String>>,
    pub push_target: Option<&'a str>,
    pub cwd: Option<String>,
    pub ppid: i32,
    pub parent_exe: Option<String>,
    pub status: &'a str,
}

pub fn log_path() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".akm").join("audit.log")
    } else {
        PathBuf::from("/tmp/akm-audit.log")
    }
}

/// `audit.log.1`, `audit.log.2`: rotated copies of `log`, newest first.
fn rotated_of(log: &Path) -> Vec<PathBuf> {
    (1..=ROTATED_FILES)
        .map(|n| {
            let mut name = log.as_os_str().to_owned();
            name.push(format!(".{n}"));
            PathBuf::from(name)
        })
        .collect()
}

/// Rotated logs next to the live one, newest first.
pub fn rotated_paths() -> Vec<PathBuf> {
    rotated_of(&log_path())
}

/// Create the log's directory (0700) when missing; tighten it when loosened.
fn ensure_dir(log: &Path) -> Result<()> {
    if let Some(parent) = log.parent() {
        create_dir_all(parent)?;
        if let Ok(meta) = std::fs::metadata(parent) {
            let mut perms = meta.permissions();
            if perms.mode() & 0o077 != 0 {
                perms.set_mode(0o700);
                let _ = std::fs::set_permissions(parent, perms);
            }
        }
    }
    Ok(())
}

/// An exclusive `flock` on `audit.lock` beside the log, held for rotation
/// and key-age updates. The kernel releases it if the process dies.
struct Lock(#[allow(dead_code)] File);

fn lock(log: &Path) -> Result<Lock> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(log.with_file_name("audit.lock"))?;
    // SAFETY: flock on a file descriptor this process owns.
    while unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    Ok(Lock(file))
}

fn open_append(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    // OpenOptions::mode only applies at create time. Re-chmod so upgrades
    // from earlier akm versions get tightened, and accidental chmods by other
    // tooling are fixed.
    if let Ok(meta) = file.metadata() {
        let mut perms = meta.permissions();
        if perms.mode() & 0o077 != 0 {
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    Ok(file)
}

/// Rename `audit.log` to `audit.log.1` (shifting `.1` to `.2`) unless another
/// process already rotated the file `current` refers to. Writers still
/// holding the old file keep appending to it under its new name, so no
/// record is lost.
fn rotate(log: &Path, current: &File) -> Result<()> {
    let _lock = lock(log)?;
    let current = current.metadata()?;
    let unchanged = std::fs::metadata(log)
        .is_ok_and(|live| live.ino() == current.ino() && live.dev() == current.dev());
    if !unchanged {
        return Ok(());
    }
    let rotated = rotated_of(log);
    for pair in rotated.windows(2).rev() {
        match std::fs::rename(&pair[0], &pair[1]) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    std::fs::rename(log, &rotated[0])?;
    Ok(())
}

fn append_line(log: &Path, line: &[u8]) -> Result<()> {
    ensure_dir(log)?;
    let mut file = open_append(log)?;
    if file.metadata()?.len() >= ROTATE_BYTES {
        rotate(log, &file)?;
        file = open_append(log)?;
    }
    file.write_all(line)?;
    Ok(())
}

/// Append a JSONL entry to the audit log.
///
/// # Guarantees and the lack thereof
///
/// - Files are created with mode 0600 so other users on the machine cannot
///   read them. Same-user processes (including any agent that runs as you)
///   can still read AND write them; the audit log is best-effort
///   tamper-evident, not tamper-proof.
/// - Each record is one short JSON object plus a `\n`, written with
///   `write_all` to an `O_APPEND` descriptor. Under heavy concurrent writers,
///   records can interleave at `write_all` chunk boundaries. We accept this:
///   the log is for forensic review, not for high-rate observability.
/// - Past `ROTATE_BYTES` the log rotates under a lock; see `rotate`.
/// - Append failures are surfaced to the caller (no silent `let _ =`); each
///   command prints them on stderr unless `--quiet`.
pub fn append(entry: &Entry) -> Result<()> {
    let mut line = serde_json::to_vec(entry)?;
    line.push(b'\n');
    append_line(&log_path(), &line)
}

pub fn now() -> String {
    Utc::now().to_rfc3339()
}

/// Key name to the time of its last successful write. Kept in a small 0600
/// index so `list` costs the same however large the audit log grows.
pub type Ages = BTreeMap<String, String>;

fn ages_path(log: &Path) -> PathBuf {
    log.with_file_name("key-ages.json")
}

fn read_ages(log: &Path) -> Option<Ages> {
    serde_json::from_slice(&std::fs::read(ages_path(log)).ok()?).ok()
}

fn write_ages(log: &Path, ages: &Ages) -> Result<()> {
    let path = ages_path(log);
    let temp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(&serde_json::to_vec(ages)?)?;
    file.sync_all()?;
    std::fs::rename(&temp, &path)?;
    Ok(())
}

/// Rebuild ages from the audit logs, oldest file first: the last successful
/// `add` or `import` of each key. Best-effort: a missing or partially corrupt
/// log yields a partial map, never an error. This is display metadata (key
/// age for rotation hygiene), not access control.
fn backfill(log: &Path) -> Ages {
    let mut ages = Ages::new();
    let mut logs = rotated_of(log);
    logs.reverse();
    logs.push(log.to_path_buf());
    for path in logs {
        let Ok(file) = File::open(&path) else {
            continue;
        };
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else {
                break;
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            let cmd = v.get("command").and_then(|c| c.as_str()).unwrap_or("");
            if !matches!(cmd, "add" | "import" | "rm") {
                continue;
            }
            if v.get("status").and_then(|s| s.as_str()) != Some("ok") {
                continue;
            }
            let Some(ts) = v.get("ts").and_then(|t| t.as_str()) else {
                continue;
            };
            let keys = v.get("keys").and_then(|k| k.as_array());
            for k in keys.into_iter().flatten().filter_map(|k| k.as_str()) {
                if cmd == "rm" {
                    ages.remove(k);
                } else {
                    ages.insert(k.to_string(), ts.to_string());
                }
            }
        }
    }
    ages
}

/// The index for `log`, built from the logs once when absent or unreadable.
fn ages_at(log: &Path) -> Ages {
    if let Some(ages) = read_ages(log) {
        return ages;
    }
    let Ok(_lock) = ensure_dir(log).and_then(|_| lock(log)) else {
        return backfill(log);
    };
    // Another process may have built it while this one waited.
    if let Some(ages) = read_ages(log) {
        return ages;
    }
    let ages = backfill(log);
    let _ = write_ages(log, &ages);
    ages
}

fn update_ages(log: &Path, change: impl FnOnce(&mut Ages)) -> Result<()> {
    ensure_dir(log)?;
    let _lock = lock(log)?;
    let mut ages = read_ages(log).unwrap_or_else(|| backfill(log));
    change(&mut ages);
    write_ages(log, &ages)
}

/// Ages for `list`. The first call after an upgrade builds the index from
/// the existing logs; later calls read only the small index.
pub fn key_ages() -> Ages {
    ages_at(&log_path())
}

/// Record that `names` were written now (`add`, `import`).
pub fn record_set(names: &[String]) -> Result<()> {
    let ts = now();
    update_ages(&log_path(), |ages| {
        for name in names {
            ages.insert(name.clone(), ts.clone());
        }
    })
}

/// Forget a removed key's age (`rm`).
pub fn record_removed(name: &str) -> Result<()> {
    update_ages(&log_path(), |ages| {
        ages.remove(name);
    })
}

pub fn ppid() -> i32 {
    // SAFETY: getppid is always safe.
    unsafe { libc::getppid() }
}

pub fn parent_exe(ppid: i32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let n = unsafe {
        extern "C" {
            fn proc_pidpath(pid: libc::c_int, buf: *mut libc::c_void, bufsize: u32) -> i32;
        }
        proc_pidpath(ppid, buf.as_mut_ptr() as *mut _, buf.len() as u32)
    };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}

pub fn cwd_string() -> Option<String> {
    std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
}

pub const AKM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Generate a unique run id by combining the current PID with a nanosecond
/// timestamp. Not cryptographically random — just enough to pair `started`
/// and `ok|child_nonzero` entries under concurrent runs.
pub fn new_run_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{pid}-{nanos}")
}

/// Build a baseline entry for the calling command. Caller fills the
/// command-specific fields.
pub fn entry_base(command: &'static str, status: &'static str) -> Entry<'static> {
    Entry {
        ts: now(),
        akm_version: AKM_VERSION,
        command,
        run_id: None,
        keys: Vec::new(),
        input_mode: None,
        child_command: None,
        injected_keys: None,
        push_target: None,
        cwd: cwd_string(),
        ppid: ppid(),
        parent_exe: parent_exe(ppid()),
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(command: &str, key: &str, ts: &str) -> Vec<u8> {
        format!("{{\"ts\":\"{ts}\",\"command\":\"{command}\",\"keys\":[\"{key}\"],\"status\":\"ok\"}}\n")
            .into_bytes()
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn rotates_past_the_limit_and_keeps_two_files() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        for round in 1..=3u64 {
            append_line(&log, b"{}\n").unwrap();
            // A sparse file reaches the limit without writing 16 MB.
            OpenOptions::new()
                .write(true)
                .open(&log)
                .unwrap()
                .set_len(ROTATE_BYTES + round)
                .unwrap();
            append_line(&log, b"{\"after\":true}\n").unwrap();
            assert_eq!(std::fs::read(&log).unwrap(), b"{\"after\":true}\n");
        }
        let rotated = rotated_of(&log);
        assert_eq!(
            std::fs::metadata(&rotated[0]).unwrap().len(),
            ROTATE_BYTES + 3
        );
        assert_eq!(
            std::fs::metadata(&rotated[1]).unwrap().len(),
            ROTATE_BYTES + 2
        );
        assert!(!PathBuf::from(format!("{}.3", log.display())).exists());
        for path in [&log, &rotated[0], &rotated[1]] {
            assert_eq!(mode(path), 0o600);
        }
    }

    #[test]
    fn concurrent_writers_rotate_once_and_lose_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        append_line(&log, b"{}\n").unwrap();
        let file = OpenOptions::new().write(true).open(&log).unwrap();
        file.set_len(ROTATE_BYTES).unwrap();
        let writers: Vec<_> = (0..8)
            .map(|_| {
                let log = log.clone();
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        append_line(&log, b"{\"n\":1}\n").unwrap();
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        let rotated = rotated_of(&log);
        assert!(!rotated[1].exists(), "rotated more than once");
        let lines = |path: &Path| {
            std::fs::read(path)
                .unwrap()
                .split(|b| *b == b'\n')
                .filter(|l| l.starts_with(b"{\"n\""))
                .count()
        };
        assert_eq!(lines(&log) + lines(&rotated[0]), 200);
    }

    #[test]
    fn ages_backfill_once_then_follow_writes_and_survive_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        let rotated = rotated_of(&log);
        std::fs::write(
            &rotated[0],
            record("add", "OLD_KEY", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        let mut current = record("import", "NEW_KEY", "2026-02-01T00:00:00Z");
        current.extend(record("get", "NEW_KEY", "2026-03-01T00:00:00Z"));
        current.extend(record("add", "OLD_KEY", "2026-04-01T00:00:00Z"));
        current.extend(record("add", "GONE_KEY", "2026-04-02T00:00:00Z"));
        current.extend(record("rm", "GONE_KEY", "2026-04-03T00:00:00Z"));
        std::fs::write(&log, current).unwrap();

        let ages = ages_at(&log);
        assert_eq!(ages["OLD_KEY"], "2026-04-01T00:00:00Z");
        assert_eq!(ages["NEW_KEY"], "2026-02-01T00:00:00Z");
        assert!(!ages.contains_key("GONE_KEY"), "removed keys drop out");
        assert_eq!(mode(&ages_path(&log)), 0o600);

        // Once built, the index is the source: the logs can rotate away.
        std::fs::remove_file(&log).unwrap();
        std::fs::remove_file(&rotated[0]).unwrap();
        update_ages(&log, |ages| {
            ages.remove("OLD_KEY");
            ages.insert("ADDED".into(), "2026-05-01T00:00:00Z".into());
        })
        .unwrap();
        let ages = ages_at(&log);
        assert_eq!(ages.len(), 2);
        assert_eq!(ages["NEW_KEY"], "2026-02-01T00:00:00Z");
        assert_eq!(ages["ADDED"], "2026-05-01T00:00:00Z");
    }
}
