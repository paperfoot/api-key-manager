# Changelog

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
