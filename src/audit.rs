use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
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

pub fn append(entry: &Entry) -> Result<()> {
    let path = log_path();
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    let line = serde_json::to_string(entry)?;
    writeln!(f, "{}", line)?;
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
    // proc_pidpath: returns the executable path for a given pid on macOS.
    let mut buf = vec![0u8; 4096];
    let n = unsafe {
        // proc_pidpath is provided by libproc on macOS; we declare it inline to
        // avoid an extra dependency.
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
