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
/// Notes on guarantees (and the lack thereof):
///
/// - File is created with mode 0600 so other users on the machine cannot read
///   it. Same-user processes (including any agent that runs as you) can still
///   read AND write it — by design we treat the audit log as best-effort
///   tamper-evident, not tamper-proof.
/// - Each call writes the JSON object plus a trailing `\n` in a single
///   `write_all`. The Linux/macOS kernel guarantees atomicity for writes up to
///   `PIPE_BUF` (≥ 512 bytes) under `O_APPEND`, which is well above the size
///   of any record we emit. So concurrent `akm` processes will not interleave
///   bytes inside a record.
/// - Append failures are returned to the caller (no more silent `let _ =`).
///   Commands surface them on stderr unless `--quiet` is set.
pub fn append(entry: &Entry) -> Result<()> {
    let path = log_path();
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
        // Tighten directory perms too (best-effort).
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

    // OpenOptions::mode only applies at create time. If the file existed
    // already (e.g. upgraded from an earlier akm that didn't chmod) ensure
    // 0600 every time we append. This is a no-op when the perms are already
    // correct and protects against accidental chmods by other tooling.
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

    // Build the line, then a single write_all so bytes within a record stay
    // contiguous. POSIX guarantees atomicity for writes < PIPE_BUF under
    // O_APPEND. Our records are well under that.
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

/// Build a baseline entry for the calling command. Caller fills in the
/// command-specific fields.
pub fn entry_base(command: &'static str, status: &'static str) -> Entry<'static> {
    Entry {
        ts: now(),
        akm_version: AKM_VERSION,
        command,
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
