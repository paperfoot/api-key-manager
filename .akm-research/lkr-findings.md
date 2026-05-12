# lkr (llm-key-ring) findings

## What it is

Single-user macOS Rust CLI structured as a workspace of `lkr-core` (library) + `lkr-cli` (clap binary), workspace v0.3.4 (`/tmp/akm-research/lkr/Cargo.toml:6`). README banner: "no longer actively maintained" (`README.md:3`). Stores keys as JSON blobs `{"value":"...","kind":"runtime|admin"}` (`crates/lkr-core/src/keymanager.rs:50-58`) inside a dedicated `~/Library/Keychains/lkr.keychain-db` created via Security.framework FFI. Commands: `init`, `set`, `get`, `list`, `rm`, `gen`, `exec`, `migrate`, `harden`, `lock`, `usage` (`crates/lkr-cli/src/main.rs:24-141`). Key names are `provider:label` lowercase (`keymanager.rs:102-134`) — narrower than akm's `[A-Z_][A-Z0-9_]*`. Service name `com.llm-key-ring` (`crates/lkr-core/src/lib.rs:23`). Three pillars: Custom Keychain + Legacy ACL with cdhash binding, comprehensive TTY guard on `get`/`gen`, and `exec` as the recommended automation path.

## Keychain backend

**Dedicated keychain file**: `custom_keychain::create()` at `~/Library/Keychains/lkr.keychain-db` via `security-framework`'s `CreateOptions::new().password(password).create(path)` (`crates/lkr-core/src/custom_keychain.rs:70-90`). After creation, `KeychainSettings` sets lock-on-sleep + 300s auto-lock (`custom_keychain.rs:141-155`), then `ensure_not_in_search_list()` removes it from the global search list via raw FFI: `SecKeychainCopySearchList` → `CFArrayGetCount`/`CFArrayGetValueAtIndex` → build a filtered `CFArrayCreateMutable` → `SecKeychainSetSearchList` → re-fetch and verify absence (`custom_keychain.rs:163-244`). The unlock flow at `crates/lkr-cli/src/util.rs:52-80` retries the password 3 times via `rpassword`, then hands a `KeychainStore::new_v3(kc)` back to the CLI. `lkr lock` calls `SecKeychainLock` (`custom_keychain.rs:115-125`).

**cdhash ACL is a side-effect, not hand-built**. `acl::build_access()` (`crates/lkr-core/src/acl.rs:62-131`): validate the binary path exists and is a file → `CString` it → `SecTrustedApplicationCreateFromPath(path, &out)` → single-element `CFArrayCreateMutable` → `CFStringCreateWithBytes` for the description → `SecAccessCreate(desc, trusted_list, &out)` returns a `SecAccessRef`. macOS internally captures the binary's cdhash when ingesting the trusted-app ref — confirmed by `docs/design-v030.md:39-46` showing `requirement: cdhash H"..."`. Items are created with that `SecAccessRef` attached via legacy CSSM `SecKeychainItemCreateFromContent` (`keymanager.rs:221-229,535-558`) because it is "the only way to atomically create an item WITH an initial SecAccessRef" (`docs/design-v030.md:191-194`). Reads use `SecKeychainFindGenericPassword` scoped to the custom keychain handle (`keymanager.rs:231-240,626-637`) wrapped in a `disable_user_interaction()` RAII guard (`custom_keychain.rs:282-287`) so cdhash mismatch returns `-25308`/`-25293` instead of popping a dialog. The error path calls `acl::is_acl_blocked()` (`acl.rs:143-166`) — if `SecKeychainItemCopyAccess` also returns `-25308`, the error becomes `AclMismatch` with a "run `lkr harden`" hint.

**Why Custom Keychain not login**: spike findings in `docs/SECURITY.md:175-274` — login.keychain items get an `apple-tool:` partition ID that overrides the trusted-app list; Custom Keychains use the legacy CSSM format with no partition IDs, so `-T` is enforced. After `cargo install --force`, the binary's cdhash changes and `lkr harden` (`crates/lkr-cli/src/cmd/harden.rs:5-110`) re-reads each key interactively (`get_interactive` at `harden.rs:46-65`) and re-creates it with a fresh ACL (`set_interactive` at `harden.rs:69-83`).

## TTY guard

Implementation: `std::io::IsTerminal` on stdout evaluated once at `crates/lkr-cli/src/main.rs:146` and threaded down explicitly as `stdout_is_tty: bool`, which makes it unit-testable — tests inject `false` (`main.rs:341-429`). No env-var sniffing (`docs/SECURITY.md:116-117`).

For `get` (`crates/lkr-cli/src/cmd/get.rs:14-35`): in non-TTY only `--json` *without* `--show` (masked value only) or `--force-plain` (with stderr warning at `get.rs:37-39`) is allowed. Everything else — bare `get`, `--show`, `--plain`, `--json --show` — returns `Error::TtyGuard`, which `main.rs:224-227` maps to exit code 2 (distinct from generic exit 1). Clipboard copy is also skipped in non-TTY (`get.rs:52-56`) to defeat `lkr get key && pbpaste`.

For `gen` (`crates/lkr-cli/src/cmd/gen.rs:13-21`): blocked in non-TTY unless `--force`. For `exec` (`crates/lkr-cli/src/cmd/exec.rs`): always allowed — keys go straight into `child.env(env_var, &**value)` (`exec.rs:90-92`), so they never leave the process boundary. Non-TTY prints a 1-line warning for audit (`exec.rs:72-79`).

## Template renderer

`lkr gen` writes output with `0600` perms via `write_secure()` (`crates/lkr-core/src/template.rs:341-368`) using a `.lkr-gen-<pid>.tmp` + `fs::rename` atomic write. Format is auto-detected: `{{lkr:` triggers `generate_json`, otherwise `generate_env` (`template.rs:104-108,310-312`).

Two syntaxes:

1. **`.env.example` auto-resolution** (`template.rs:143-196`): line-by-line, comments and blanks pass through, `KEY=VALUE` lines look `KEY` up in a hard-coded 17-entry `ENV_VAR_MAP` (`template.rs:42-60`). Only *exact* env-var-name matches resolve — explicitly tested so `AWS_REGION` is left alone when `aws:*` exists (`template.rs:456-474`). With multiple runtime keys per provider, the alphabetically first wins via `BTreeMap` and the rest are surfaced as alternatives on stderr (`template.rs:200-215`, `cmd/gen.rs:99-110`).

2. **`{{lkr:provider:label}}` placeholders** (`template.rs:247-307`): scanned via `find("{{lkr:")` / `find("}}")`. Unclosed placeholders return `Error::Template`. JSON values are escaped via `escape_json_value()` — backslash, quote, control chars Unicode-escaped (`template.rs:316-333`). **Admin keys are rejected at render time** (`template.rs:271-278`).

`gen` also runs `git check-ignore` against the output path (`template.rs:119-130`) — if the output is not gitignored, it warns before writing (`cmd/gen.rs:67-74`).

## Things akm doesn't have (potential adoptions)

- **`exec` admin-key rejection** — `cmd_exec` refuses `KeyKind::Admin` even when explicitly named with `-k` (`crates/lkr-cli/src/cmd/exec.rs:43-54`, tested at `main.rs:433-515`). **Low effort / high value.**

- **TTY guard on `get`** — non-TTY raw output behind `--force-plain`, masked `--json` allowed, clipboard skipped, exit code 2 (`crates/lkr-cli/src/cmd/get.rs:14-56`, `main.rs:224-227`). **Low / high.** Directly addresses the AI-agent exfiltration threat akm names in its v0.1 docs.

- **Clipboard skip in non-TTY** (`get.rs:52-56`) — defeats the `pbpaste` bypass. **Low / medium.**

- **Hash-compare clipboard auto-clear** — `schedule_clipboard_clear` (`util.rs:16-46`) shells out for SHA-256 of current `pbpaste`, spawns a detached `sh` that re-hashes after N seconds and only clears if unchanged. Raw key never passed as a process arg. **Low / medium.**

- **`.gitignore` check on `gen` output** (`template.rs:119-130`, `cmd/gen.rs:67-74`) — exit 128 from `git check-ignore` means "not a repo", treated N/A. **Low / medium.**

- **Template renderer with two syntaxes** (`crates/lkr-core/src/template.rs:90-368`) — covers the "tool needs a config file" gap that `run --only` can't fill. Atomic write + gitignore warning + admin-key rejection bundled in. **Medium / medium.**

- **`KeyStatus::AclBlocked` first-class list status** (`keymanager.rs:61-94`, `cmd/list.rs:36-44`) — pattern reusable for any unreadable key (locked keychain, perm error). **Low / medium.**

- **`exec` auto-injects all runtime keys when `-k` is omitted** (`exec.rs:17-41`) — versus akm's `--only NAME` requirement. ACL-blocked keys listed in a warning rather than silently dropped. **Low / medium.**

- **3-layer error messages (WHAT/WHY/FIX)** (`main.rs:222-307`) — every variant has a "Fix: run X" line. Pairs well with akm's typed errors. **Low / medium.**

- **`disable_user_interaction()` RAII guard** around every keychain read (`custom_keychain.rs:282-287`, used `keymanager.rs:606-613,799-800`) — guarantees no surprise dialog mid-script. **Low / medium**, only if akm moves to security-framework directly.

- **Dedicated keychain (`lkr.keychain-db`) outside search list** — the *isolation* half of v0.3.0 (`custom_keychain.rs:163-244`). Defeats `security find-generic-password` from any tool that doesn't know the path. **Medium effort / medium value.** Costs: `init` flow with password, lock state, retries (`util.rs:52-80`), `migrate` (`cmd/migrate.rs`), `lock` (`cmd/lock.rs`). ~350 lines FFI + ~100 CLI plumbing.

- **cdhash-bound Legacy ACL** — the *authorization* half (`acl.rs:62-131`, `keymanager.rs:487-558`). `SecKeychainItemCreateFromContent` needs hand-rolled `SecKeychainAttributeList` structs with FOURCC tags (`keymanager.rs:248-259,510-521`), and ~half the bugs in CHANGELOG 0.3.0→0.3.4 are around the cdhash-mismatch error matrix (`CHANGELOG.md:8-30`). For an internal one-developer tool this is a lot of FFI to buy "another developer tool on the same machine can't read your keys" — which a malicious tool running as your uid trivially defeats by invoking `akm get` directly (acknowledged at `docs/design-v030.md:131-134`). **High effort / low-medium value for akm's threat model.**

## Things akm does better

- **No prompts ever.** akm reads from stdin or argv; lkr forces `rpassword` interactive entry on `set` (`crates/lkr-cli/src/cmd/set.rs:18-25`) and a 3-retry password loop every session (`util.rs:52-80`).
- **Login keychain, no `init` step.** lkr requires `lkr init` before first use (`main.rs:160-166`) with a permanent extra password to remember.
- **Provider-agnostic name scheme.** lkr is locked to `provider:label` lowercase (`keymanager.rs:102-134`) — `MY_SERVICE_TOKEN` does not validate.
- **Push to vendor secret stores (`vercel/gh/fly`).** lkr has no equivalent.
- **JSONL audit log.** lkr has no `started`/`ok` pair, no `run_id`, no mode-0600 trail.
- **`guard install/scan`, `agent-info --json`, `skill install`.** Pure agent ergonomics lkr lacks.
- **Redaction of known values in `run` stdout/stderr.** lkr's `exec` does nothing of the sort — once the child has the env var, anything it logs is on the child.
- **No tokio runtime in the hot path.** lkr pulls `tokio = full` (`Cargo.toml:18`) for `usage`, creating a runtime per invocation (`cmd/usage.rs:11-12`).

## Footguns / bugs / weak spots

- **`exec` re-fetches every key after `list`.** Auto-inject mode calls `store.list(false)` then `store.get(&entry.name)` per row to get the raw value (`crates/lkr-cli/src/cmd/exec.rs:22-32`) — N+1 keychain hits.
- **Long tail of cdhash bugs** (`CHANGELOG.md:8-30`): 0.3.4 alone fixes four — `harden` non-interactive read failed on first key after upgrade, `delete_v3`/`set_v3` blocked themselves with `disable_user_interaction`, `-25293` misdiagnosed as wrong password, `exists()` misreported `PasswordWrong`. 0.3.3 fixed a circular error where `exists()` → `get()` → "run lkr migrate" caused migrate to fail on every key.
- **ACL was fail-open in 0.3.0** (`CHANGELOG.md:61-63`): `build_access()` failure used to silently store without ACL. Fixed in 0.3.1 — but its existence is a tell.
- **Clipboard hash uses shell pipeline** (`util.rs:18-21`): `sh -c "pbpaste | shasum -a 256 | cut -d' ' -f1"`. Works on stock macOS but is a process-spawn dependency chain.
- **`/usr/bin/security` invariant documented but not enforced.** `docs/design-v030.md:204-206` says it must never be in the trusted-app list; `build_access` doesn't reject that path (`acl.rs:217-232` explicitly tests it accepts `/usr/bin/security`). Enforcement is left to callers.
- **`ENV_VAR_MAP` is hard-coded** (`template.rs:42-60`). Adding a provider needs a code change + release. Fallback for unknown providers is `PROVIDER_LABEL` not `PROVIDER_API_KEY` (`template.rs:68-77`).
- **Validation rejects underscores in names** (`keymanager.rs:102-134`). `my_service:dev` is invalid.
- **Repo unmaintained** (`README.md:3`) — zero upstream response for any port-related bug.

## Verdict

Three wins for akm v0.2.0, in order:

1. **TTY guard on `get`** — gate non-TTY raw output behind `--force-plain`, allow `--json` masked, skip the clipboard, exit code 2. Mirrors `crates/lkr-cli/src/cmd/get.rs:14-56` and `main.rs:224-227`. Low cost, directly addresses the AI-agent exfiltration threat akm already names.

2. **`gen` template renderer with gitignore check + atomic-write 0600** (`crates/lkr-core/src/template.rs:90-368`) — self-contained, covers the "tool needs a config file" gap, and is the most differentiated user-facing feature lkr ships.

3. **`exec`/`run` admin-key rejection + `KeyStatus::AclBlocked` surfacing** (`exec.rs:43-54`, `keymanager.rs:61-94`, `cmd/list.rs:36-44`) — clean policy primitive akm can lift without any keychain rewrite.

**Dedicated keychain DB + cdhash ACL is not worth it for v0.2.0.** Layer 1 (isolated keychain) is a real ~50% protection against casual snooping by other tools running as the same user; Layer 2 (cdhash ACL) is mostly theatre against a same-user attacker who can simply invoke `akm` directly — explicitly acknowledged at `docs/design-v030.md:131-134` and `docs/SECURITY.md:163-167`. For an internal multi-machine developer tool, ~500 lines of Security.framework FFI plus an ongoing tail of `-25293`/`-25308`/`harden` bugs (CHANGELOG.md:8-30) buys very little. Stay on login keychain for v0.2.0; revisit only if akm ships to external users with a real adversarial model.
