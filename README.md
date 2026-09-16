# AKM

Use macOS Keychain secrets in commands without copying their values into scripts, shell history, or agent conversations.

```sh
akm run --only OPENAI_API_KEY -- node server.js
akm run --only API_KEY=PROJECT_API_KEY -- python script.py
akm stdin DEPLOY_TOKEN -- gh secret set DEPLOY_TOKEN
```

AKM is a small local CLI. It needs no account, server, background process, or separate vault. It uses your existing macOS Login Keychain and returns an error when access is unavailable, without opening Keychain dialogs.

## Install

```sh
brew install paperfoot/tap/akm
# Source build (requires a stable signing identity for seamless upgrades):
cargo install api-key-manager --locked
```

macOS only, with Apple Silicon and Intel CI coverage. The source requires Rust 1.85 or newer. CI runs on macOS 26 (Apple Silicon) and macOS 15 (Intel); this does not imply every older macOS release has been tested.

Optional instructions for Claude Code, Codex, and Gemini:

```sh
akm skill install
akm skill status
```

Updating the binary does not update an already installed skill automatically; run `akm skill install` after an upgrade.

## Upgrade from 0.1 or 0.2

Homebrew and GitHub releases use a stable Developer ID signature. Older local
builds used a signature tied to one executable; a replacement can lose access to
its Keychain items. Keep a copy of the working binary **before upgrading**:

```sh
mkdir -p ~/.akm/legacy
cp "$(command -v akm)" ~/.akm/legacy/akm-before-upgrade
brew upgrade akm
akm migrate --from ~/.akm/legacy/akm-before-upgrade --dry-run
akm migrate --from ~/.akm/legacy/akm-before-upgrade
akm skill install
```

Migration copies values through private pipes into `com.paperfoot.akm.v2`,
verifies each write, skips existing destination entries, and preserves the old
`com.paperfoot.akm` entries. Values never appear in its output or temporary files.
Use `--only NAME,NAME` to select a subset. It stops on the first source failure or
five-second timeout and can be rerun. The older source executable may request
Keychain access; migration cannot suppress another process's dialogs.

New items take precedence; readable legacy entries remain a fallback. `rm`
removes both copies so an old value cannot reappear. After migration, write new
values with the new binary; old binaries still see the preserved original values.
Source builds need consistent code signing too; replacing an ad-hoc signed
binary can require authorizing the new executable in Keychain Access. Do not
remove the only binary that can read your keys before verifying its replacement.

## Store and use a key

Supply new values through your subprocess API's stdin. For example, with a value already held by your application:

```python
subprocess.run(["akm", "add", "OPENAI_API_KEY"], input=value, text=True, check=True)
```

`akm add NAME` replaces an existing value. Names use `[A-Z_][A-Z0-9_]*`. AKM does not prompt for input; add/import with terminal stdin returns an error. Piped input to `add` has trailing CR/LF stripped.

Choose the transport the receiving command accepts:

| Need | Command |
|---|---|
| Environment variables | `akm run --only OPENAI_API_KEY,ANTHROPIC_API_KEY -- npm test` |
| Rename a stored key for one child | `akm run --only API_KEY=PROJECT_API_KEY -- python script.py` |
| Raw value on stdin | `akm stdin TOKEN -- gh secret set TOKEN` |
| Shell-quoted `NAME=value` on stdin | `akm stdin TOKEN --format env -- flyctl secrets import` |
| Find stored names | `akm list --names-only` |
| Discover one command | `akm agent-info --command run` |

`run` and `stdin` preserve child exit codes and redact exact supplied values from both child streams, including values split across reads. Normal progress output is forwarded as it arrives. For noninteractive jobs, SIGINT, SIGTERM, and SIGHUP received by AKM are forwarded to the child's process group.

Redaction pipes the child streams and matches exact bytes; transformed, encoded, or partial values are outside that match. `--no-redact` inherits the original output streams for tools that need a terminal or byte-for-byte output. `--all` explicitly selects every stored key.

## Output contract

- Commands return JSON automatically when stdout is piped, or with `--json`. Success uses the existing `{"version":"1","status":"ok","data":...}` envelope.
- Errors go to **stderr**, include a code and recovery suggestion, and leave stdout available for data.
- `run` and `stdin` forward child output without a completion message by default. Explicit `--json` adds a completion envelope to stderr, after any child stderr.
- `--help` and `--version` remain plain text. `list --names-only` explicitly produces one name per line.
- Exit codes: `0` success, `1` runtime failure, `3` bad input, `6` missing key. Wrappers preserve the child's code (or `128 + signal`), so interpret it in the command's context.

`get --raw` means **unmasked**, not plain-text output: it still returns a JSON envelope when piped. Prefer `run` or `stdin` for ordinary credential use. `get --raw` and `export` intentionally expose values for requested retrieval or backup.

## Other commands

| Command | Behavior |
|---|---|
| `akm get NAME` | Show a masked value. |
| `akm list --long` | Show names and last-write ages recorded in the audit log. |
| `akm import .env --dry-run` | Preview names and skipped lines without accessing Keychain. |
| `akm import .env` | Import literal dotenv values; never execute substitutions or delete the source. |
| `akm export --only NAME --format env` | Export raw values with shell quoting; AKM can import this format. |
| `akm rm NAME` | Remove a key; already absent succeeds. |
| `akm audit --limit 50` | Read the latest complete audit records. |
| `akm guard install` | Install an optional staged-secret hook, preserving existing hooks and symlinks. |
| `akm guard uninstall` | Remove only an unchanged AKM-owned hook. |
| `akm guard scan` | Scan staged content for known prefixes followed by token-like text. |

Check an import's `skipped` entries and validate your replacement configuration before removing its source. Import is not transactional: a Keychain error can leave earlier entries stored. The optional guard is a heuristic, not a complete secret scanner; it does not flag bare prefix examples such as `sk-...`.

## macOS access and audit

Keep `HOME` set to your actual macOS account home when using Keychain. If AKM reports `keychain_unavailable`, check the existing Login Keychain in Keychain Access and unlock it if needed. AKM never resets a Keychain, changes its access controls, or disables system-wide security prompts. Dialog suppression is limited to the AKM process.

AKM keeps the file-based Keychain backend. Signed releases and the explicit migration above address access changes when replacing older executables. Apple's data-protection Keychain has different code-signing and entitlement requirements; switching backends would require a separate migration.

Successful operations and subprocess lifecycles are recorded in `~/.akm/audit.log` with mode `0600`, using names and metadata, never secret values or complete child arguments. Logs are best effort: failed lookups before execution and forced kills may have no terminal record. The log is writable by the same user and is not a tamper-proof access control.

AKM reduces accidental disclosure. A process running as your user can still retrieve keys, and child environment variables are accessible to same-user inspection. It does not provide isolation from an agent you have allowed to execute arbitrary commands as you.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
```

Integration tests create and remove uniquely named synthetic Keychain entries. Preserve the real `HOME`; redirecting it can hide macOS Keychain configuration. A dedicated regression verifies that unavailable Keychain access fails without a dialog.

See [the September 2026 review](docs/review-2026-09-16.md) for usage evidence, changes, and validation scope.

MIT. Built by [Paperfoot](https://paperfoot.com).
