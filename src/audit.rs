use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

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

/// Append a JSONL entry to the audit log.
///
/// # Guarantees and the lack thereof
///
/// - File is created with mode 0600 so other users on the machine cannot read
///   it. Same-user processes (including any agent that runs as you) can still
///   read AND write it — the audit log is best-effort tamper-evident, not
///   tamper-proof.
/// - Each record is one short JSON object plus a `\n`, written with
///   `write_all`. POSIX `O_APPEND` makes each `write(2)` append atomically
///   (the kernel seeks to end before the write), but Rust's `write_all` is
///   permitted to issue multiple syscalls. Under heavy concurrent writers,
///   records can interleave at `write_all` chunk boundaries. We accept this:
///   the log is for forensic review, not for high-rate observability.
/// - Append failures are surfaced to the caller (no silent `let _ =`); each
///   command prints them on stderr unless `--quiet`.
pub fn append(entry: &Entry) -> Result<()> {
    let path = log_path();
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(parent) {
                let mut perms = meta.permissions();
                if perms.mode() & 0o077 != 0 {
                    perms.set_mode(0o700);
                    let _ = std::fs::set_permissions(parent, perms);
                }
            }
        }
    }

    let mut opts = OpenOptions::new();
    opts.create(true).append(true).mode(0o600);
    let mut f = opts.open(&path)?;

    // OpenOptions::mode only applies at create time. Re-chmod every append so
    // upgrades from earlier akm versions get tightened, and accidental chmods
    // by other tooling are fixed.
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = f.metadata() {
            let mut perms = meta.permissions();
            if perms.mode() & 0o077 != 0 {
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(&path, perms);
            }
        }
    }

    let mut line = serde_json::to_vec(entry)?;
    line.push(b'\n');
    f.write_all(&line)?;
    Ok(())
}

pub fn now() -> String {
    Utc::now().to_rfc3339()
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
