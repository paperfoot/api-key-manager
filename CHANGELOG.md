# Changelog

## 0.4.0

- Adopt the agent-cli-framework contracts. `agent-info` prints the raw manifest with one parser-generated line per command (2.6 KB, from 8.2 KB); `agent-info --command PATH` returns full objects with effects, idempotence, examples and output fields.
- Parse errors list the failing command's flags or subcommands and its usage line, without echoing argv. `--help` gains Tips; `--json --help` returns `data.usage`.
- Add `doctor` (Keychain lock state, signature, v2 and legacy key counts, skill, audit log, guard hook; counts only, never names or values), `update` (upgrade command for the owning install channel; no network), and `config show`/`config path` (AKM has no config file; they report the audit log and Keychain services).
- Add `get NAME --value`: exactly the stored value on stdout, with no JSON and no newline, for programs. Prefer `run` or `stdin`.
- A missing key (exit 6) lists up to five similar stored names in `error.details.candidates` and its suggestion.
- Rotate the audit log at 16 MB, keeping `audit.log.1` and `.2`; `audit --limit` reads across them. Key ages come from a small index instead of a full log scan, so `list --long` drops from about 1.1 B to 115 M instructions.
- Redact child output at about 3 instructions per byte, from about 49, with the same matching and streaming behaviour.
- `rm` and `import` check existence without decrypting values. Add the `rm` alias `delete` and `audit -n`. `guard scan` hits are an error envelope on stderr.

Compatibility: success envelopes say `"status":"success"` instead of `"ok"`; `data` shapes are unchanged, so `get --raw` still returns `data.value`. `agent-info` output is no longer wrapped in an envelope. Keychain setup failures (`keychain_unavailable`) exit 2 instead of 1. `migrate --from` accepts sources that report either status. In JSON mode, `guard scan` hits move from stdout to `error.details.hits` on stderr; exit 3 is unchanged.

## 0.3.0

- Prevent macOS Keychain dialogs from blocking agent jobs. Report unavailable access with a recovery suggestion; keep existing Keychain items and permissions.
- Sign release binaries with a stable Developer ID. Add an explicit, resumable `migrate --from` path from older executables into a new service namespace; preserve originals and never overwrite destination entries.
- Forward ordinary child output immediately, redact short secrets and chunk-spanning values, drain output while writing stdin, and forward cancellation to noninteractive child process groups.
- Keep wrapper output quiet by default. Emit completion metadata only with explicit `--json`, with failure status for a nonzero child. Preserve child exit codes and record spawn/transport failures in the audit lifecycle.
- Send parser and runtime errors to stderr with recovery suggestions. Invalid arguments use exit 3 and do not echo potential credentials.
- Add `run --only TARGET=STORED`, `stdin --format env`, `list --names-only`, `ls`, `info`, scoped `agent-info --command`, and `skill status`.
- Generate discovery syntax from the CLI parser. Keep the established success envelope, plain-text help/version, and missing-key exit 6.
- Shorten the agent skill, remove automatic dotenv migration/deletion, and make skill installation idempotent.
- Preserve foreign Git hooks and symlinks, respect `core.hooksPath`, and stop flagging bare key-prefix examples.
- Support literal multiline/shell-quoted export/import round trips. Dry-run import no longer reads Keychain.
- Tail audit logs from the end with bounded record size instead of loading the complete file.
- Upgrade security-framework to 3.7 and remove unused dependencies. Repair CI; test Apple Silicon macOS 26, Intel macOS 15, and Rust 1.85.

Compatibility: scripts that relied on errors on stdout or automatic wrapper completion messages must read stderr or explicitly request `--json`. `get --raw` remains JSON when piped. The full agent-cli-framework protocol is not adopted; AKM preserves its existing envelope and exit-code conventions.
