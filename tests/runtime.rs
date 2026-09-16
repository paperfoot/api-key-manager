//! Runtime regressions for the transparent `run` and `stdin` wrappers.
//!
//! Every Keychain item is synthetic and uniquely named. Each test also gives
//! AKM uniquely named fixtures without changing HOME (macOS uses it for Keychain).

#![cfg(target_os = "macos")]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdout, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tempfile::TempDir;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(8);
const EVENT_TIMEOUT: Duration = Duration::from_secs(3);
static UNIQUE: AtomicU64 = AtomicU64::new(0);
static KEYCHAIN_TEST_LOCK: Mutex<()> = Mutex::new(());

struct Harness {
    _keychain_serial: MutexGuard<'static, ()>,
    scratch: TempDir,
    keys: Vec<String>,
}

impl Harness {
    fn new() -> Self {
        Self {
            _keychain_serial: KEYCHAIN_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            scratch: tempfile::tempdir().unwrap(),
            keys: Vec::new(),
        }
    }

    fn command(&self) -> Command {
        Command::new(env!("CARGO_BIN_EXE_akm"))
    }

    fn add(&mut self, tag: &str, value: &[u8]) -> String {
        let name = unique_key(tag);
        // Register before attempting the write so panic cleanup still removes
        // an item if AKM stored it but failed while reporting completion.
        self.keys.push(name.clone());
        let mut command = self.command();
        command.args(["add", &name]);
        let output = run_capture(command, Some(value), COMMAND_TIMEOUT);
        assert!(
            output.status.success(),
            "failed to store synthetic test key (exit {:?})",
            output.status.code()
        );
        name
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        for name in self.keys.iter().rev() {
            let mut command = self.command();
            let _ = command
                .args(["rm", name])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

struct ManagedChild {
    child: Child,
}

impl ManagedChild {
    fn spawn(mut command: Command) -> Self {
        Self {
            child: command.spawn().expect("spawn AKM test process"),
        }
    }

    fn wait_until(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait().expect("wait for AKM test process") {
                Some(status) => return Some(status),
                None if Instant::now() >= deadline => return None,
                None => thread::sleep(Duration::from_millis(10)),
            }
        }
    }

    fn terminate(&mut self) {
        let pid = self.child.id() as i32;
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        if self.wait_until(Duration::from_secs(1)).is_none() {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            let _ = self.child.wait();
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            self.terminate();
        }
    }
}

fn unique_key(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let serial = UNIQUE.fetch_add(1, Ordering::Relaxed);
    format!("AKM_IT_{tag}_{}_{serial}_{nanos}", std::process::id())
}

fn read_all<R: Read + Send + 'static>(mut reader: R) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .expect("read captured output");
        bytes
    })
}

fn run_capture(mut command: Command, input: Option<&[u8]>, timeout: Duration) -> Output {
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut process = ManagedChild::spawn(command);
    let stdout = read_all(process.child.stdout.take().expect("capture stdout"));
    let stderr = read_all(process.child.stderr.take().expect("capture stderr"));
    let writer = input.map(|bytes| {
        let bytes = bytes.to_vec();
        let mut stdin = process.child.stdin.take().expect("capture stdin");
        thread::spawn(move || stdin.write_all(&bytes))
    });

    let status = match process.wait_until(timeout) {
        Some(status) => status,
        None => {
            process.terminate();
            let _ = stdout.join();
            let _ = stderr.join();
            if let Some(writer) = writer {
                let _ = writer.join();
            }
            panic!("AKM test process exceeded bounded timeout");
        }
    };
    if let Some(writer) = writer {
        writer
            .join()
            .expect("join AKM stdin writer")
            .expect("write AKM stdin");
    }
    Output {
        status,
        stdout: stdout.join().expect("join stdout reader"),
        stderr: stderr.join().expect("join stderr reader"),
    }
}

fn checksum(bytes: &[u8]) -> u64 {
    bytes.iter().map(|byte| u64::from(*byte)).sum()
}

fn line_event(stdout: ChildStdout) -> (mpsc::Receiver<Vec<u8>>, thread::JoinHandle<Vec<u8>>) {
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut first = Vec::new();
        reader
            .read_until(b'\n', &mut first)
            .expect("read child event");
        let _ = sender.send(first.clone());
        let mut rest = Vec::new();
        reader
            .read_to_end(&mut rest)
            .expect("read remaining stdout");
        first.extend(rest);
        first
    });
    (receiver, reader)
}

fn finish_streaming_process(
    process: &mut ManagedChild,
    stdout: thread::JoinHandle<Vec<u8>>,
    stderr: thread::JoinHandle<Vec<u8>>,
) -> Output {
    let Some(status) = process.wait_until(COMMAND_TIMEOUT) else {
        process.terminate();
        let _ = stdout.join();
        let _ = stderr.join();
        panic!("streaming AKM test process exceeded bounded timeout");
    };
    Output {
        status,
        stdout: stdout.join().expect("join streaming stdout reader"),
        stderr: stderr.join().expect("join streaming stderr reader"),
    }
}

#[test]
fn run_forwards_short_nonmatching_output_before_child_eof() {
    let mut harness = Harness::new();
    let name = harness.add("STREAM", b"zz-synthetic-stream-secret-123456789");
    let mut command = harness.command();
    command
        .args([
            "run",
            "--only",
            &name,
            "--",
            "/bin/sh",
            "-c",
            "printf 'ready\\n'; IFS= read -r marker; test \"$marker\" = proceed",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut process = ManagedChild::spawn(command);
    let (event, stdout) = line_event(process.child.stdout.take().expect("capture stdout"));
    let stderr = read_all(process.child.stderr.take().expect("capture stderr"));

    let ready = event.recv_timeout(EVENT_TIMEOUT).unwrap_or_else(|_| {
        process.terminate();
        panic!("short nonmatching output was buffered until child EOF")
    });
    assert_eq!(ready, b"ready\n");
    let mut stdin = process.child.stdin.take().expect("capture AKM stdin");
    stdin
        .write_all(b"proceed\n")
        .expect("release child fixture");
    drop(stdin);

    let output = finish_streaming_process(&mut process, stdout, stderr);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
}

#[test]
fn default_run_with_quiet_child_leaves_stderr_empty() {
    let mut harness = Harness::new();
    let name = harness.add("QUIET", b"synthetic-quiet-secret-123456789");
    let mut command = harness.command();
    command.args(["run", "--only", &name, "--", "/usr/bin/true"]);
    let output = run_capture(command, None, COMMAND_TIMEOUT);

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        output.stderr.is_empty(),
        "default run wrote wrapper noise to stderr"
    );
}

#[test]
fn run_mapping_injects_target_and_redacts_with_target_label() {
    let mut harness = Harness::new();
    let value = b"synthetic-mapped-secret-123456789";
    let source = harness.add("MAPPED_SOURCE", value);
    let target = unique_key("MAPPED_TARGET");
    let expected_len = value.len().to_string();
    let expected_sum = checksum(value).to_string();
    let script = r#"import os,sys
source,target,expected_len,expected_sum=sys.argv[1:]
value=os.environ.get(target)
ok=(value is not None and source not in os.environ and len(value.encode())==int(expected_len) and sum(value.encode())==int(expected_sum))
if not ok: raise SystemExit(41)
print(value)
"#;
    let mapping = format!("{target}={source}");
    let mut command = harness.command();
    command.args([
        "run",
        "--only",
        &mapping,
        "--",
        "/usr/bin/python3",
        "-c",
        script,
        &source,
        &target,
        &expected_len,
        &expected_sum,
    ]);
    let output = run_capture(command, None, COMMAND_TIMEOUT);

    assert!(output.status.success());
    assert!(!output
        .stdout
        .windows(value.len())
        .any(|window| window == value));
    let expected = format!("[REDACTED:{target}]\n");
    assert!(
        output.stdout == expected.as_bytes(),
        "mapped value was not redacted with its injected target name"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn run_redacts_short_secret() {
    let mut harness = Harness::new();
    let value = b"abc123";
    let name = harness.add("SHORT", value);
    let script = format!("printf %s \"${{{name}}}\"");
    let mut command = harness.command();
    command.args(["run", "--only", &name, "--", "/bin/sh", "-c", &script]);
    let output = run_capture(command, None, COMMAND_TIMEOUT);

    assert!(output.status.success());
    assert!(!output
        .stdout
        .windows(value.len())
        .any(|window| window == value));
    assert!(output.stdout == format!("[REDACTED:{name}]").as_bytes());
    assert!(output.stderr.is_empty());
}

#[test]
fn run_preserves_child_exit_42() {
    let mut harness = Harness::new();
    let name = harness.add("EXIT", b"synthetic-exit-secret-123456789");
    let mut command = harness.command();
    command.args(["run", "--only", &name, "--", "/bin/sh", "-c", "exit 42"]);
    let output = run_capture(command, None, COMMAND_TIMEOUT);

    assert_eq!(output.status.code(), Some(42));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn run_missing_executable_reports_json_only_on_stderr() {
    let mut harness = Harness::new();
    let name = harness.add("SPAWN", b"synthetic-spawn-secret-123456789");
    let missing = format!("/AKM_IT_EXECUTABLE_DOES_NOT_EXIST_{}", std::process::id());
    let mut command = harness.command();
    command.args(["--json", "run", "--only", &name, "--", &missing]);
    let output = run_capture(command, None, COMMAND_TIMEOUT);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stdout.is_empty(),
        "spawn failure polluted child stdout"
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("spawn failure stderr is one JSON envelope");
    assert_eq!(envelope["status"], "error");
    assert_eq!(envelope["error"]["code"], "internal_error");
}

#[test]
fn stdin_supplies_raw_bytes_and_parseable_env_assignment() {
    let mut harness = Harness::new();
    let raw = "synthetic first line\nsecond: λ-value".as_bytes();
    let raw_name = harness.add("STDIN_RAW", raw);
    let raw_len = raw.len().to_string();
    let raw_sum = checksum(raw).to_string();
    let raw_script = r#"import sys
data=sys.stdin.buffer.read()
ok=(len(data)==int(sys.argv[1]) and sum(data)==int(sys.argv[2]))
print('raw-ok' if ok else 'raw-bad')
raise SystemExit(0 if ok else 41)
"#;
    let mut command = harness.command();
    command.args([
        "stdin",
        &raw_name,
        "--",
        "/usr/bin/python3",
        "-c",
        raw_script,
        &raw_len,
        &raw_sum,
    ]);
    let output = run_capture(command, None, COMMAND_TIMEOUT);
    assert!(output.status.success());
    assert!(output.stdout == b"raw-ok\n");
    assert!(output.stderr.is_empty());

    let env_value = b"synthetic value with a ' quote";
    let env_name = harness.add("STDIN_ENV", env_value);
    let env_len = env_value.len().to_string();
    let env_sum = checksum(env_value).to_string();
    let env_script = r#"import shlex,sys
parts=shlex.split(sys.stdin.read(), posix=True)
ok=(len(parts)==1 and '=' in parts[0])
if ok:
    name,value=parts[0].split('=',1)
    encoded=value.encode()
    ok=(name==sys.argv[1] and len(encoded)==int(sys.argv[2]) and sum(encoded)==int(sys.argv[3]))
print('env-ok' if ok else 'env-bad')
raise SystemExit(0 if ok else 41)
"#;
    let mut command = harness.command();
    command.args([
        "stdin",
        &env_name,
        "--format",
        "env",
        "--",
        "/usr/bin/python3",
        "-c",
        env_script,
        &env_name,
        &env_len,
        &env_sum,
    ]);
    let output = run_capture(command, None, COMMAND_TIMEOUT);
    assert!(output.status.success());
    assert!(output.stdout == b"env-ok\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn stdin_preserves_exit_when_child_closes_input_early() {
    let mut harness = Harness::new();
    let value = vec![b'v'; 16 * 1024];
    let name = harness.add("STDIN_EARLY_CLOSE", &value);
    let script = "import os; os.close(0); raise SystemExit(42)";
    let mut command = harness.command();
    command.args(["stdin", &name, "--", "/usr/bin/python3", "-c", script]);
    let output = run_capture(command, None, COMMAND_TIMEOUT);

    assert_eq!(output.status.code(), Some(42));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn stdin_drains_verbose_child_while_writing_large_value() {
    let mut harness = Harness::new();
    let value: Vec<u8> = (0..16 * 1024)
        .map(|index| b'a' + (index % 23) as u8)
        .collect();
    let name = harness.add("STDIN_VERBOSE", &value);
    let expected_len = value.len().to_string();
    let expected_sum = checksum(&value).to_string();
    let script = r#"import sys
sys.stdout.buffer.write(b'x' * (256 * 1024))
sys.stdout.buffer.flush()
data=sys.stdin.buffer.read()
ok=(len(data)==int(sys.argv[1]) and sum(data)==int(sys.argv[2]))
raise SystemExit(0 if ok else 41)
"#;
    let mut command = harness.command();
    command.args([
        "stdin",
        &name,
        "--",
        "/usr/bin/python3",
        "-c",
        script,
        &expected_len,
        &expected_sum,
    ]);
    let output = run_capture(command, None, COMMAND_TIMEOUT);

    assert!(output.status.success());
    assert_eq!(output.stdout.len(), 256 * 1024);
    assert!(output.stdout.iter().all(|byte| *byte == b'x'));
    assert!(output.stderr.is_empty());
}

struct PidCleanup(Vec<i32>);

impl Drop for PidCleanup {
    fn drop(&mut self) {
        for pid in &self.0 {
            unsafe {
                libc::kill(*pid, libc::SIGKILL);
            }
        }
    }
}

fn pid_exists(pid: i32) -> bool {
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn pid_disappears(pid: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if !pid_exists(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn sigterm_to_akm_terminates_child_and_grandchild() {
    let mut harness = Harness::new();
    let name = harness.add("CANCEL", b"synthetic-cancel-secret-123456789");
    let child_pid_path = harness.scratch.path().join("child.pid");
    let grandchild_pid_path = harness.scratch.path().join("grandchild.pid");
    let script = r#"import os,pathlib,signal,subprocess,sys
grandchild=subprocess.Popen(['/bin/sleep','60'])
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
pathlib.Path(sys.argv[2]).write_text(str(grandchild.pid))
print('ready', flush=True)
signal.pause()
"#;
    let mut command = harness.command();
    command
        .args([
            "run",
            "--only",
            &name,
            "--",
            "/usr/bin/python3",
            "-c",
            script,
            child_pid_path.to_str().expect("UTF-8 child pid path"),
            grandchild_pid_path
                .to_str()
                .expect("UTF-8 grandchild pid path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut process = ManagedChild::spawn(command);
    let akm_pid = process.child.id() as i32;
    let (event, stdout) = line_event(process.child.stdout.take().expect("capture stdout"));
    let stderr: thread::JoinHandle<Vec<u8>> =
        read_all(process.child.stderr.take().expect("capture stderr"));
    let ready = event.recv_timeout(EVENT_TIMEOUT).unwrap_or_else(|_| {
        process.terminate();
        panic!("child fixture did not report its bounded ready event")
    });
    assert_eq!(ready, b"ready\n");

    let child_pid: i32 = fs::read_to_string(&child_pid_path)
        .expect("child pid file exists after ready")
        .parse()
        .expect("child pid is numeric");
    let grandchild_pid: i32 = fs::read_to_string(&grandchild_pid_path)
        .expect("grandchild pid file exists after ready")
        .parse()
        .expect("grandchild pid is numeric");
    let mut pid_cleanup = PidCleanup(vec![child_pid, grandchild_pid]);
    assert!(pid_exists(child_pid));
    assert!(pid_exists(grandchild_pid));

    assert_eq!(unsafe { libc::kill(akm_pid, libc::SIGTERM) }, 0);
    let output = finish_streaming_process(&mut process, stdout, stderr);
    assert_eq!(output.status.code(), Some(128 + libc::SIGTERM));
    assert!(output.stderr.is_empty());
    assert!(
        pid_disappears(child_pid, EVENT_TIMEOUT),
        "AKM child survived direct SIGTERM cancellation"
    );
    assert!(
        pid_disappears(grandchild_pid, EVENT_TIMEOUT),
        "AKM grandchild survived direct SIGTERM cancellation"
    );
    pid_cleanup.0.clear();
}

#[test]
fn missing_home_keychain_fails_without_a_dialog_or_hang() {
    let _serial = KEYCHAIN_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_akm"));
    command
        .env("HOME", home.path())
        .args(["add", &unique_key("NO_HOME")]);
    let output = run_capture(
        command,
        Some(b"synthetic-no-keychain-value"),
        COMMAND_TIMEOUT,
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["code"], "keychain_unavailable");
    assert!(error["error"]["suggestion"]
        .as_str()
        .unwrap()
        .contains("HOME"));
}
