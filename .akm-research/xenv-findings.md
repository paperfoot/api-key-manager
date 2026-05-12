# xenv findings

## What it is
xenv is a TypeScript single-binary (compiled with Bun) dotenv replacement that pairs encrypted vaults with a 7-layer environment cascade and a stdio MCP server. It targets **project-scoped secrets committed to the repo as `.xenv.{env}.enc` files**, decrypted in memory at runtime, then injected as env into a child process (`xenv @production -- ./server`). Distribution is `curl | sh` from GitHub releases (install.sh:38-104). Crypto is AES-256-GCM, keys are 32-byte hex, and every command emits `--json`.

## Backing store
Vault files live next to code as `.xenv.{env}.enc`. Format: `xenv:v1:` header + hex(iv ‖ ciphertext+tag), AES-256-GCM with 96-bit IV, 128-bit tag, 256-bit key (src/vault.ts:7-12, 312-340). WebCrypto's `crypto.subtle` does the work. Keys themselves are plaintext hex in two files:
- `.xenv.keys` in project root, `chmod 600` (src/vault.ts:504), gitignored, with a multi-line "AI agent, do not commit this" header (src/vault.ts:14-70).
- `~/.xenv.keys` global keyfile, `chmod 600`, with `# root: /absolute/path` directives that scope keys to a project tree, "most specific path wins" (src/vault.ts:132-209).

Key lookup is an 8-step cascade: env var specific/generic → local keys specific/generic → global root-scoped specific/generic → global fallback specific/generic (src/vault.ts:223-244). No OS keychain integration. Rotation re-encrypts vault FIRST then updates keyfile — deliberately crash-safe (src/vault.ts:581-638).

## 7-layer cascade
Defined in `resolveEnv` (src/resolve.ts:17-77). Later layers overwrite earlier:

1. `.env` — legacy base (src/resolve.ts:29)
2. `.xenv` — modern base (src/resolve.ts:31)
3. `.env.local` / `.xenv.local` — developer-local overrides (src/resolve.ts:33)
4. `.env.{env}` / `.xenv.{env}` — env-specific plaintext (src/resolve.ts:35)
5. `.xenv.{env}.enc` — encrypted vault, decrypted in memory (src/resolve.ts:54-68)
6. `.env.{env}.local` / `.xenv.{env}.local` — env-specific local overrides (src/resolve.ts:39)
7. `process.env` — always wins, but `XENV_KEY*` are filtered out before injection (src/resolve.ts:71-74)

Within a group both filenames load in order via `Object.assign` so `.xenv.*` beats `.env.*` at the same tier. Env names validated `[a-zA-Z0-9_-]+` to block path traversal (src/resolve.ts:21-23). A safer twin `resolveCascadeOnly` only lets `process.env` override keys already in cascade files — used for `resolve --json` and MCP responses so the agent can't dump the whole shell (src/resolve.ts:84-135).

## MCP server (13 tools)
Zero-dependency JSON-RPC 2.0 over stdio (src/mcp.ts:337-447). Tools (src/mcp.ts:47-188):

1. `init` — bootstrap project: gitignore + keygen + starter env + agent configs (mcp.ts:49)
2. `resolve_env` — return merged 7-layer cascade as JSON (mcp.ts:60)
3. `set_secret` — atomic decrypt-in-memory → patch → re-encrypt (mcp.ts:71)
4. `delete_secret` — atomic remove key from vault (mcp.ts:84)
5. `list_secrets` — key names only, never values (mcp.ts:96)
6. `encrypt` — encrypt `.xenv.{env}` plaintext into `.enc` vault (mcp.ts:107)
7. `diff` — added/removed/changed between plaintext and vault, `keys_only` default true (mcp.ts:118)
8. `rotate_key` — new key, re-encrypt vault, update keyfile (mcp.ts:130)
9. `audit` — project security scan, returns `{ok, findings[]}` (mcp.ts:141)
10. `validate` — required-key + empty-secret + vault/key sync (mcp.ts:149)
11. `doctor` — overall project + agent-integration health, "call this FIRST" (mcp.ts:165)
12. `hook_install` — install git pre-commit hook (mcp.ts:173)
13. `hook_check` — scan staged diff for leaked secrets (mcp.ts:181)

Env name validation `[a-zA-Z0-9_-]+` is centralized on every call (src/mcp.ts:286-292); required-param checks are generic (src/mcp.ts:296-307).

## Agent integration model
**MCP-first, with a triple safety net.** Primary path is the stdio MCP server (`xenv mcp`), but `xenv init` *also* writes a Claude Code slash command + Cursor MCP config + VS Code MCP config in one shot (src/init.ts:87-120, 166-182). The Claude slash command (src/init.ts:122-164) is essentially a skill — lists commands and security rules so the agent can shell out without MCP. So:

- MCP server for IDE-side tool calling (Cursor, VS Code/Copilot auto-discovery)
- Claude Code `/xenv` slash command for terminal agents
- Every CLI command takes `--json` for shell + JSON agents (src/cli.ts:43, 50, 56, 63, 86)

`doctor` is the recommended entry point — "the agent calls this first" (src/mcp.ts:165-171, src/doctor.ts:24-102). `init` is idempotent (src/init.ts:18-82).

## Things akm doesn't have (potential adoptions)

- **`xenv doctor` — single-command health check with per-issue fix commands** (src/doctor.ts:24-102). akm has `agent-info`, but `doctor` is different — returns `{name, ok, message, fix}` quadruples so the agent literally knows the next shell command to run. **low effort / high value** — drop-in agent UX win.

- **`xenv audit` — security scanner with structured findings** (src/audit.ts:25-164). akm has audit-*logging*; xenv has audit-*scanning*: orphan vaults, orphan keys, sensitive-looking values, key values found in tracked files (src/audit.ts:134-158). The "scan tracked files for known key material" check is the killer — akm could grep git-tracked files for any value present in Keychain. **medium effort / high value**.

- **`validate --require K,Y,Z` and `.xenv.required` manifest** (src/validate.ts:25-122). Lets a project declare "production MUST have DATABASE_URL, STRIPE_KEY" and fail CI. akm has nothing like this. **low effort / medium value**.

- **Atomic in-memory vault edit pattern (`set_secret`/`delete_secret`)** — decrypt → mutate → re-encrypt, plaintext never lands on disk (src/edit.ts:80-115). akm's Keychain gives this per-key for free, but worth preserving as an invariant if akm ever adds file-backed vaults. **low value while Keychain-only**.

- **Pre-commit hook that knows real secrets** (src/hook.ts:43-72, 113-187). akm has `guard install/scan` already, so this is roughly parity — but xenv's "decrypt vault, exact substring match in staged diff" is more aggressive than pure pattern-matching. akm could pull all known values from Keychain into the scanner. **low effort / medium value**.

- **`diff` between two snapshots, keys-only by default** (src/diff.ts:24-94). For akm this would be "diff between machines / repos". **medium effort / low value** until akm grows multi-source sync.

- **Auto-write `.cursor/mcp.json` + `.vscode/mcp.json` in `init`** (src/init.ts:87-120). If akm ever ships an MCP server, this triple-write pattern is the move. **low effort / medium value** as a follow-on.

- **AI-aware keyfile header** (src/vault.ts:14-70). akm has no keyfile, but the *principle* — embed system-prompt-style warnings in any file an LLM might read — is portable. **low effort / low value**.

- **MCP server itself.** akm already ships a Claude/Codex/Gemini skill — MCP would primarily benefit Cursor / Windsurf / Continue / Zed users. **medium effort / medium value**. See verdict.

## Things akm does better

- **OS keychain integration.** akm uses macOS Login Keychain — keys protected by login session + Secure Enclave. xenv stores 256-bit keys as plaintext hex in `~/.xenv.keys` or `.xenv.keys` (chmod 600) — strictly weaker at rest.
- **No `.gitignore` failure mode.** akm has zero files in the repo. xenv's entire threat model assumes `.gitignore` is right; audit/hook tooling exists *because* the failure mode is real.
- **No prompts ever.** akm's "stdin or argv, never interactive" is stricter than xenv's `EDITOR`-based flow which spawns vim by default (src/edit.ts:130, 167-173).
- **Rust single binary, no Bun runtime.** xenv ships ~10MB Bun runtime + JS.
- **Typed errors + stable exit codes.** xenv throws JS `Error` with messages; recovery means string-matching.
- **Push to vercel/gh/fly built in.** xenv has no `push` (README:443-454).
- **Child stdout/stderr redaction.** xenv injects env and lets the child print whatever.
- **JSONL audit log with `run_id` correlation.** xenv has no per-invocation log.

## Footguns / bugs / weak spots

- **Plaintext keys on disk by default.** `.xenv.keys` lives in the working tree; all the audit/hook/header scaffolding compensates for this choice (src/vault.ts:14-70, src/audit.ts:30-39, src/hook.ts:122-129). Wrong `.gitignore` = shipped keys.
- **Gitignore parser is naive.** Exact match + `*` wildcard only (src/audit.ts:212-221); real gitignore has `**`, `/`-anchoring, directory rules, ordering for `!`. `audit` can miss legitimate ignores or false-positive (src/audit.ts:193-210).
- **MCP `initialized` flag is process-global module-level state** (src/mcp.ts:258). Fine for stdio + one client, but blocks multi-client reuse and breaks test isolation.
- **`process.env` overrides cascade unconditionally** in `resolveEnv` (src/resolve.ts:71-74). A stray `DATABASE_URL` in the shell silently overrides a vault value. The safer `resolveCascadeOnly` exists (used by `resolve --json` and MCP) but `run` doesn't use it.
- **`hook_check` uses `includes()` for substring match** (src/hook.ts:144-149) with an 8-char minimum. A value like `"password"` matches any line containing the word "password". 8-char floor is the only guard.
- **`extract_value_from_line` regex** (src/hook.ts:301-304) is `^\s*\+?\s*\w+=...` — only matches dotenv-style `KEY=VALUE`, missing JSON, YAML, code literals, shell `export FOO=...`.
- **No AAD in vault format** (src/vault.ts:7-8) — anyone with the key can swap context (e.g., a staging vault repackaged as prod) with no integrity signal.
- **Bun-only.** Source uses `Bun.file`, `Bun.write`, `Bun.spawn`, `Bun.hash`, `Bun.stdin.stream()` throughout.

## Verdict
akm should adopt three things and skip MCP for now: (1) a `doctor` command that returns structured `{name, ok, message, fix}` triples so agents always know the next command — this is xenv's biggest UX win; (2) an `audit scan` mode that loads all Keychain key *values* and searches git-tracked files for them (xenv/src/audit.ts:134-158) — a 50-line addition that catches the worst class of leak; (3) a `.akm.required` manifest + `validate --require` flag for CI pre-flight. **akm should NOT add an MCP server yet** — the skill already covers Claude/Codex/Gemini and akm's Keychain-backed, file-less design means there's no "vault to manage from inside the IDE" the way xenv has. Add MCP only if/when Cursor/Windsurf users start filing issues; the skill is doing the work.
