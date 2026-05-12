# psst findings

## What it is

psst (v0.7.0) is a Bun + TypeScript CLI for secrets that AI agents can *use* without *seeing*. Same core thesis as akm. Single binary built via `bun build --compile` (`package.json:25`). Two pluggable storage backends: encrypted SQLite (default) or AWS Secrets Manager (`src/vault/backend.ts:43-93`). Threat model: secrets never enter agent context — `psst SECRET -- cmd` and `psst run cmd` inject env vars into a subprocess, and child stdout/stderr is regex-replaced with `[REDACTED]` in real time (`src/commands/exec.ts:135-150`). Command surface: `init` (`--backend sqlite|aws`, `--global`, `--env`), `set/get/list/rm` (`--tag`, `--stdin`, `--json`, `--quiet`), `import/export` (.env), `tag/untag`, `history/rollback`, `scan` (`--staged`, `--path`), `run`, and the bare `psst NAME [NAME...] -- cmd` exec pattern (`src/main.ts:166-186`). Global flags `--json`, `-q`, `--global`, `--env <n>`, `--tag <t>` (repeatable). Cross-platform (macOS/Linux/Windows). Manual arg parser, no framework. Name pattern enforced: `^[A-Z][A-Z0-9_]*$` (`src/commands/set.ts:17`).

## Backing store

**SQLite backend** — single `vault.db` per environment under `.psst/envs/<name>/vault.db` (plus a legacy `.psst/vault.db`) (`src/vault/vault.ts:38-40,242-267`). Schema: a `secrets` table (name PK, `encrypted_value` BLOB, `iv` BLOB, `tags` TEXT-JSON, timestamps) and a `secrets_history` table capped at 10 versions per secret with auto-pruning (`src/vault/sqlite-backend.ts:49-85,345-352`). **Crypto**: AES-256-GCM via WebCrypto, 12-byte random IV per encryption, key derivation either base64-decode (if 32 bytes) or SHA-256 hash of the password — *no PBKDF2, no salt* (`src/vault/crypto.ts:9-20`). **Encryption key**: random 32-byte base64 stored in OS keychain (`security add-generic-password` on darwin, `secret-tool` on Linux, `cmdkey` on Windows) (`src/vault/keychain.ts:62-127`). Fallback: `PSST_PASSWORD` env var. **Disk permissions**: not set explicitly anywhere — file mode is whatever the OS umask gives you (no `chmod 0600` enforcement in `database.ts` or vault init). **AWS backend**: maps `NAME → <prefix>NAME` in Secrets Manager with a JSON envelope `{"value":...,"tags":[...]}`, tagged `psst:managed=true` for tenant isolation, uses native AWS versioning + `BatchGetSecretValue` chunked at 20 (`src/vault/aws-backend.ts:65-181,409-444`). No client-side encryption with the AWS backend; KMS only.

## Agent integration

**Surprisingly thin.** No MCP server. No `agent-info` manifest. No `skill install`. The "agent integration" is essentially:

1. A two-line `AGENTS.md` at the repo root telling the model how the codebase is laid out (`AGENTS.md:1-36`) — for developers of psst, not consumers.
2. A `.claude/settings.json` shipped *in the psst repo itself* that hooks `Bash` PreToolUse → `.claude/hooks/psst-block.sh` and PostToolUse → `.claude/hooks/psst-scan.sh` (`/tmp/akm-research/psst/.claude/settings.json:1-26`). **The two hook scripts referenced do not exist in the repo** — only the settings file does.
3. `psst init` prints "Next steps: ... `psst onboard`" (`src/commands/init.ts:281`) but **no `onboard` command is implemented** — the switch in `src/main.ts:189-376` has no case for it.
4. The `security/benchmark.sh` script (a Claude Code red-team harness with 12 prompts trying to extract `BENCHMARK_SECRET`) calls `psst install-hooks --force` (`security/benchmark.sh:91`) but **no `install-hooks` command is implemented either**.
5. Every command supports `--json` and semantic exit codes (0/1/2/3/5 in `src/utils/exit-codes.ts:1-6`), which is the only real machine-readable contract.

The README's "For Agents" section (`README.md:279-335`) is just a usage doc, not a capability manifest. There is no programmatic discovery surface.

## Things akm doesn't have (potential adoptions)

- **Pluggable storage backend abstraction** — `VaultBackend` trait in `src/vault/backend.ts:43-93`, dispatched at constructor time via `config.json` per vault (`src/vault/vault.ts:73-96`). Default sqlite, AWS Secrets Manager second. Lets the same CLI talk to local-or-cloud without changing commands. **High value, medium effort** — would let akm grow into a team product (AWS Secrets Manager, 1Password Connect, vault.so) without rewriting verbs. Useful even if only ever wired to one extra backend.
- **`config.json` per vault** — a tiny JSON file in the vault directory that selects backend + holds backend-specific settings (`src/vault/config.ts:38-83`). Absent file = sqlite default, preserves zero-config (`src/vault/vault.ts:97-102`). **High value, low effort** if backends are adopted; otherwise skip.
- **Version history + rollback** — `secrets_history` table, `psst history NAME` and `psst rollback NAME --to N`, capped at 10 versions, archives raw ciphertext (no decrypt/re-encrypt cost), and rollback re-archives current value so it is itself reversible (`src/vault/sqlite-backend.ts:124-172,278-334`). **High value, low-medium effort** — single recovery story that solves a real "I just overwrote my prod key" pain. akm's keychain has no notion of versions.
- **Tags as first-class** — `--tag` on set, list, run, exec. OR-logic filtering (`src/vault/sqlite-backend.ts:213-217`). Lets the agent say "inject all `aws`-tagged secrets" without enumerating names. **Medium value, low effort** — useful if akm wants `run --tag` semantics for grouping.
- **Environments via vault path** — `.psst/envs/<name>/vault.db` plus `PSST_ENV` env var override (`src/main.ts:104-115`, `src/vault/vault.ts:242-267`). akm has one keychain namespace; environments would let the same agent juggle dev/staging/prod. **Medium value, medium effort** — keychain naming convention is `psst:<env>:NAME`.
- **`psst run` (no name list) — inject everything tagged X** (`src/commands/run.ts:52-60`). akm has `run --only NAME`; adding `run --tag <t>` or `run --all` would close the gap.
- **`scan` checks vault values, not regex prefixes** (`src/commands/scan.ts:265-312`) — searches files for actual secret strings (≥4 chars, `MIN_SECRET_LENGTH` at `src/commands/scan.ts:22`). Zero false positives vs akm's `sk-`/`ghp_` prefix scan. **High value, low effort** — akm could keep its prefix scan and *also* offer `akm guard scan --against-vault`.
- **Bare `psst NAME -- cmd` syntax** — no `run --only NAME --` prefix needed (`src/main.ts:166-186`). Shorter for agents to type. **Low value, low effort** (cosmetic).
- **`PSST_PASSWORD` headless fallback** — falls through to env var when keychain is unavailable, with `PSST_PASSWORD` stripped from the child env so it can't leak (`src/vault/sqlite-backend.ts:100-105`, `src/commands/exec.ts:121`). akm is macOS-only Keychain — this would unblock CI/Docker. **Medium value, medium effort**.
- **`--stdin` everywhere + `psst import .env`** for batch onboarding (`src/commands/import.ts:97-128`). **Medium value, low effort**.
- **Realtime output masking** — pipes child stdio through a `split(secret).join("[REDACTED]")` filter (`src/commands/exec.ts:161-168`). akm already has this; worth confirming the redaction set matches. **No effort, already there**.

## Things akm does better

- **No phantom commands.** psst's init prints `psst onboard` as a "next step" but the command does not exist; the security benchmark calls `psst install-hooks` which also does not exist. akm's CLI surface is honest.
- **Real agent manifest.** akm ships `agent-info --json`, `skill install`, and the AGENTS.md generation flow. psst exposes nothing programmatic beyond per-command `--json`.
- **Real audit log.** akm writes JSONL audit records (`started`/`ok` pairs with `run_id`, mode 0600). psst's "audit" story is just secrets history (not run-event history) and the file mode is the OS default.
- **Pre-commit hook is shipped and tested.** akm's `guard install/scan` is real code. psst references `.claude/hooks/psst-block.sh` and `.claude/hooks/psst-scan.sh` in `.claude/settings.json` but those scripts are not in the repo.
- **Tighter name validation in messaging.** psst's name regex is `^[A-Z][A-Z0-9_]*$` (`src/commands/set.ts:17`) but the README and AGENTS.md describe the same pattern inconsistently.
- **No SHA-256-of-password shortcut.** akm presumably uses keychain-only random keys; psst will silently SHA-256 a user-typed `PSST_PASSWORD` with no salt, no PBKDF2, no iteration count (`src/vault/crypto.ts:19`). That is genuinely weak against offline attack on `vault.db`.
- **Targeted `push` to vercel/gh/fly.** psst has no concept of pushing secrets *out* to deployment platforms.
- **macOS-native, single Rust binary** vs Bun runtime requirement (`package.json:25` builds compiled output, but the SDK path requires Bun, and `src/utils/input.ts:23,42,76,95` shells out to `stty` which won't work the same everywhere).

## Footguns / bugs / weak spots

- **Two commands documented but unimplemented**: `psst onboard` (`src/commands/init.ts:281`) and `psst install-hooks` (`security/benchmark.sh:91`). The init message is misleading and the security benchmark *cannot run as written*.
- **Password key derivation is SHA-256 with no salt / no KDF** (`src/vault/crypto.ts:19`). If `PSST_PASSWORD` is a human-chosen password, an attacker who exfiltrates `vault.db` can brute-force offline at SHA-256 speeds. Should be PBKDF2/scrypt/argon2 with a salt stored in the vault.
- **Vault files have no enforced mode.** `openDatabase()` (`src/vault/database.ts:45-50`) just opens; nothing chmods the directory or db file to 0600. `config.json` is written with `writeFileSync` default mode (`src/vault/config.ts:78-82`).
- **Output masking is naive `split/join` substring match** (`src/commands/exec.ts:161-168`). Splits on the raw bytes — won't catch base64-/URL-encoded variants, won't catch JSON-escaped (`\n` → `\\n`) embeddings, and a one-character secret would mangle output catastrophically. The `MIN_SECRET_LENGTH = 4` filter is in scan.ts but not in exec.ts.
- **Manual env-var expansion is a foot-gun for arg quoting** (`src/commands/exec.ts:14-23`). `psst KEY -- echo "$KEY"` expands inside psst, then bash spawns with `shell: false`, so the agent's shell quoting expectations may not match. Fine for documented cases; surprising for adjacent ones.
- **`getSecrets()` on AWS does an N-call DescribeSecret managed-check before each batch get** (`src/vault/aws-backend.ts:374-444`). On a 100-secret vault that's 100 extra round-trips even with chunking. Marketing claims "batched reads"; the managed-check undoes most of the speedup.
- **No timing-attack mitigation** anywhere — string compares on names are fine, but the masking pass is O(text × secrets) with raw `String.split`, which can be slow on large child output.
- **`PSST_SKIP_SCAN=1`** is referenced as a bypass hint (`src/commands/scan.ts:174`) but I see no code reading it. It's a UX promise the scanner doesn't honor.
- **Vault discovery is path-based** (`src/vault/vault.ts:242-267`) and finds the first `.psst/` walking from cwd-or-home — running `psst` from inside a project but expecting the global vault is easy to misfire on. akm's audit/log story would catch this; psst's would not.
- **`isUnlocked()` is meaningless on AWS** (`src/vault/vault.ts:119-122`) — always returns true. Fine, but the SDK exposes this and consumers might trust it.

## Verdict

Three ideas worth genuinely stealing, in order:

1. **`VaultBackend` trait + per-vault `config.json`.** Even if akm only ever ships sqlite + keychain, the trait makes "add 1Password / AWS / Vault.so" a one-file PR later. Set up the seam now.
2. **Version history + rollback (`secrets_history`, max-N, ciphertext-copy archival).** Solves an immediate user pain ("I just overwrote prod") that akm doesn't address. Low complexity, high recoverability. Borrow the "archive current before restoring → reversible rollback" trick verbatim.
3. **Tag-based grouping with `run --tag` injection.** Cleanest UX win for multi-secret scripts; lets the agent say `run --tag aws -- deploy.sh` without enumerating ten env vars. Tags also unlock future filtered audit views.

Avoid copying: the unsalted SHA-256 password fallback, the phantom `onboard`/`install-hooks` commands, and the substring-only masking approach.
