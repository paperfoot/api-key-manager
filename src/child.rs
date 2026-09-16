//! Shared subprocess transport. Drain output before writing stdin, propagate
//! cancellation, and surface transport failures instead of silently succeeding.
use std::io::{IsTerminal, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};

use crate::error::{AkmError, Result};
use crate::redact::Redactor;

static TARGET: AtomicI32 = AtomicI32::new(0);
static PENDING: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward(signal: libc::c_int) {
    PENDING.store(signal, Ordering::SeqCst);
    let target = TARGET.load(Ordering::SeqCst);
    if target != 0 {
        // kill is async-signal-safe; no allocation or locks in the handler.
        unsafe { libc::kill(target, signal) };
    }
}

struct Signals(Vec<(i32, libc::sigaction)>);

impl Signals {
    fn install() -> std::io::Result<Self> {
        let mut saved = Self(Vec::new());
        PENDING.store(0, Ordering::SeqCst);
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            // sigaction's fields are initialized before use.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = forward as *const () as usize;
            action.sa_flags = libc::SA_RESTART;
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            if unsafe { libc::sigaction(signal, &action, &mut old) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            saved.0.push((signal, old));
        }
        Ok(saved)
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        TARGET.store(0, Ordering::SeqCst);
        for (signal, old) in &self.0 {
            unsafe { libc::sigaction(*signal, old, std::ptr::null_mut()) };
        }
    }
}

pub fn run(
    cmd: &mut Command,
    input: Option<Vec<u8>>,
    secrets: Vec<(String, String)>,
    redact: bool,
) -> Result<u8> {
    let _signals = Signals::install()?;
    // Noninteractive agent jobs get a group so cancellation reaches their
    // descendants. Keep terminal jobs in the foreground group for stdin.
    let grouped = !std::io::stdin().is_terminal();
    if grouped {
        cmd.process_group(0);
    }
    if input.is_some() {
        cmd.stdin(Stdio::piped());
    }
    if redact {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let mut child = cmd.spawn()?;
    let target = if grouped {
        -(child.id() as i32)
    } else {
        child.id() as i32
    };
    TARGET.store(target, Ordering::SeqCst);
    let pending = PENDING.load(Ordering::SeqCst);
    if pending != 0 {
        unsafe { libc::kill(target, pending) };
    }

    let copy = move |result: std::io::Result<()>| {
        if result.is_err() {
            // A closed consumer must not leave a producer blocked on a pipe.
            unsafe { libc::kill(target, libc::SIGTERM) };
        }
        result
    };
    let out_secrets = secrets.clone();
    let out = child.stdout.take().map(|stdout| {
        std::thread::spawn(move || copy(Redactor::new(out_secrets).copy(stdout, std::io::stdout())))
    });
    let err = child.stderr.take().map(|stderr| {
        std::thread::spawn(move || copy(Redactor::new(secrets).copy(stderr, std::io::stderr())))
    });
    // This writer runs alongside both readers: a verbose child may fill its
    // stdout pipe before reading the supplied secret from stdin.
    let writer = input
        .zip(child.stdin.take())
        .map(|(bytes, mut stdin)| std::thread::spawn(move || stdin.write_all(&bytes)));
    let status = child.wait()?;
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)) as u8;
    for handle in [out, err].into_iter().flatten() {
        handle
            .join()
            .map_err(|_| AkmError::Internal(anyhow::anyhow!("output forwarding failed")))??;
    }
    if let Some(writer) = writer {
        let result = writer
            .join()
            .map_err(|_| AkmError::Internal(anyhow::anyhow!("stdin forwarding failed")))?;
        // Preserve a failing child's diagnostic and exit code if it rejected
        // stdin early. A successful child must have received all input.
        if code == 0 {
            result?;
        }
    }
    Ok(code)
}
