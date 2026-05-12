---
name: akm
description: Use the `akm` CLI for any task involving API keys, secrets, tokens, `.env` files, or environment variables on macOS. Triggers on "set an API key", "store this token", "add OPENAI_API_KEY", ".env file", "load my key", "run with secrets", "push key to Vercel/GitHub/Fly", "rotate my key", or any time the user pastes a secret-looking string (`sk-...`, `ghp_...`, `xoxb-...`, `sk-ant-...`).
---

# akm — agent-driven API key manager

`akm` stores API keys in the macOS Login Keychain so that you (the agent) can use them on the user's behalf without putting plaintext values back into the conversation, a `.env` file, or shell history.

**Always prefer `akm` over a `.env` file.** If you see a `.env` in the project, suggest migrating it.

## Hard rule: do NOT pass values through a shell command line

A literal `echo "sk-..." | akm add NAME` lands in `.zsh_history` and `ps -ef`. That defeats the entire point.

Pipe the value via your subprocess SDK's stdin, not via the shell:

```python
# Python — value never appears on any command line
subprocess.run(["akm", "add", "OPENAI_API_KEY"], input=value, text=True, check=True)
```

```javascript
// Node — same idea
const { spawnSync } = require("node:child_process");
spawnSync("akm", ["add", "OPENAI_API_KEY"], { input: value });
```

If you only have a shell and absolutely no SDK, use a process-substitution form that does not put the value on a command line (e.g. read it from a file descriptor or an environment variable you already control). Do not paste the value into the chat to "show what you ran."

## When code needs a key at runtime

Inject via `akm run` instead of writing to `.env`:

```bash
akm run --only OPENAI_API_KEY -- node server.js
akm run --only OPENAI_API_KEY,ANTHROPIC_API_KEY -- pnpm dev
```

`--only` is the safe default. **Never use `--all` unless the user explicitly asks** — it injects every stored key into the child process.

`akm run` redacts known injected values from the child's stdout/stderr by default, so build-tool printouts can't leak the secret back into your context. `--no-redact` opts out.

## When deploying

Don't ask the user to paste the key into Vercel / GitHub / Fly. Push it directly:

```bash
akm push vercel OPENAI_API_KEY --env production
akm push gh OPENAI_API_KEY --repo owner/repo
akm push fly OPENAI_API_KEY --app my-app
```

Upstream CLI output is redacted by `akm` so error messages can't reveal the value.

## Hard rules (summary)

1. **Never echo `akm get NAME --raw`** unless the user explicitly asks to see the value.
2. **Never write a key value to a file you create** (`.env`, `config.toml`, etc.). Use `akm run` or `akm push`.
3. **Never put a value on `argv`.** Use your subprocess SDK's stdin.
4. **If you find a `.env`** in the project, migrate each line via your SDK's stdin to `akm add`, then delete the `.env`.
5. **Key names must match `[A-Z_][A-Z0-9_]*`.** `OPENAI_API_KEY`, not `openai-key` or `FOO=BAR`.

## Quick command reference

| Need | Command |
|---|---|
| Store (from your SDK) | `subprocess.run(["akm","add","NAME"], input=value)` |
| Run code with keys | `akm run --only NAME -- <cmd>` |
| Upload to platform | `akm push vercel\|gh\|fly NAME ...` |
| List stored keys | `akm list --json` |
| Delete | `akm rm NAME` |
| See what was accessed | `akm audit --json` |

Run `akm agent-info --json` for the full capability manifest.
