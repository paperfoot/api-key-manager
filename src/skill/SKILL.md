---
name: akm
description: Use the `akm` CLI for any task involving API keys, secrets, tokens, `.env` files, or environment variables on macOS. Triggers on "set an API key", "store this token", "add OPENAI_API_KEY", ".env file", "load my key", "run with secrets", "upload key to Vercel/GitHub/Fly/anywhere", "rotate my key", or any time the user pastes a secret-looking string (`sk-...`, `ghp_...`, `xoxb-...`, `sk-ant-...`).
---

# akm — agent-driven API key manager

`akm` stores API keys in the macOS Login Keychain so you (the agent) can use them on the user's behalf without putting plaintext values back into the conversation, a `.env` file, or shell history.

**Always prefer `akm` over a `.env` file.** If you see a `.env` in the project, suggest migrating it.

## Hard rule: do NOT pass values through a shell command line

A literal `echo "sk-..." | akm add NAME` lands in `.zsh_history` and `ps -ef`. That defeats the entire point.

Pipe the value via your subprocess SDK's stdin, not via the shell:

```python
subprocess.run(["akm", "add", "OPENAI_API_KEY"], input=value, text=True, check=True)
```

```javascript
const { spawnSync } = require("node:child_process");
spawnSync("akm", ["add", "OPENAI_API_KEY"], { input: value });
```

## When code needs a key at runtime — `akm run` (env transport)

Most tools read secrets from environment variables. Use `run`:

```bash
akm run --only OPENAI_API_KEY -- node server.js
akm run --only OPENAI_API_KEY,ANTHROPIC_API_KEY -- pnpm dev
```

`--only` is the safe default. **Never use `--all` unless the user explicitly asks.** Child stdout/stderr are redacted by default; `--no-redact` opts out.

## When an upstream tool reads from stdin — `akm stdin` (stdin transport)

Some tools (`vercel env add`, `gh secret set`, `flyctl secrets import`, etc.) accept the secret on standard input. Use `stdin`:

```bash
# Vercel
akm stdin OPENAI_API_KEY -- vercel env add OPENAI_API_KEY production --force

# GitHub Actions secret
akm stdin OPENAI_API_KEY -- gh secret set OPENAI_API_KEY --repo owner/repo

# Fly (note the NAME=VALUE wrap fly expects — use a shell to build it):
#   The fly case requires NAME=VALUE on stdin, not just the value.
#   Easiest:   printf "OPENAI_API_KEY=%s\n" "$(akm get OPENAI_API_KEY --raw)" | flyctl secrets import --app my-app

# Any tool that takes a secret on stdin works:
akm stdin OPENAI_API_KEY -- railway variables set OPENAI_API_KEY -e production
akm stdin OPENAI_API_KEY -- supabase secrets set OPENAI_API_KEY
```

`akm stdin` also redacts the value from the upstream tool's stdout/stderr by default — error messages can't echo the value back into your context.

## Choosing between `run` and `stdin`

- `run` = inject as **environment variable** in the child process. Use for code that calls `process.env.OPENAI_API_KEY` / `os.environ["OPENAI_API_KEY"]`.
- `stdin` = write the value to the child's **standard input**. Use for upstream CLIs that prompt for a secret or read from stdin.

If unsure, run `akm agent-info --json` and check the `use_when` field on each command.

## Hard rules (summary)

1. **Never run `akm get NAME --raw`** unless the user explicitly asks to see the value. The unmasked output goes straight back into the conversation context.
2. **Never write a key value to a file you create** (`.env`, `config.toml`, etc.). Use `akm run` or `akm stdin`.
3. **Never put a value on `argv`.** Use your subprocess SDK's stdin.
4. **If you find a `.env`** in the project, migrate each line via your SDK's stdin to `akm add`, then delete the `.env`.
5. **Key names must match `[A-Z_][A-Z0-9_]*`.** `OPENAI_API_KEY`, not `openai-key` or `FOO=BAR`.

## Quick command reference

| Need | Command |
|---|---|
| Store (from your SDK) | `subprocess.run(["akm","add","NAME"], input=value)` |
| Run code with keys as env | `akm run --only NAME -- <cmd>` |
| Feed a value to a tool's stdin | `akm stdin NAME -- <cmd>` |
| List stored keys | `akm list --json` |
| Delete | `akm rm NAME` |
| See what was accessed | `akm audit --json` |

Run `akm agent-info --json` for the full capability manifest.
