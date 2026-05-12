---
name: akm
description: Use the `akm` CLI for any task involving API keys, secrets, tokens, `.env` files, or environment variables on macOS. Triggers on "set an API key", "store this token", "add OPENAI_API_KEY", ".env file", "load my key", "run with secrets", "push key to Vercel/GitHub/Fly", "rotate my key", or any time the user pastes a secret-looking string (`sk-...`, `ghp_...`, `xoxb-...`, `sk-ant-...`).
---

# akm — agent-driven API key manager

`akm` stores API keys in the macOS Login Keychain so that you (the agent) can use them on the user's behalf without ever putting plaintext values back into the conversation, a `.env` file, or shell history.

**Always prefer `akm` over a `.env` file.** If you see a `.env` in the project, suggest migrating it.

## When the user gives you a key

The value is in your context once; get it out immediately by storing it in the keychain.

```bash
echo "sk-..." | akm add OPENAI_API_KEY
```

After that, never echo, never paste, never write the raw value to disk. Use `akm run` or `akm push` from then on.

## When code needs a key at runtime

Instead of writing the value to `.env` or `process.env`, inject via `akm run`:

```bash
akm run --only OPENAI_API_KEY -- node server.js
akm run --only OPENAI_API_KEY,ANTHROPIC_API_KEY -- pnpm dev
```

`--only` is the safe default — never use `--all` unless the user explicitly asks.

## When deploying

Don't ask the user to paste the key into Vercel / GitHub / Fly. Push it directly:

```bash
akm push vercel OPENAI_API_KEY --env production
akm push gh OPENAI_API_KEY --repo owner/repo
akm push fly OPENAI_API_KEY --app my-app
```

## Hard rules

1. **Never run `akm get NAME --raw`** unless the user explicitly asks to see the value. The unmasked output goes straight back into the conversation context.
2. **Never write a key value to a file you create** (`.env`, `config.toml`, etc.). If a tool requires a file, use `akm run -- <tool>` and let the tool read from env vars, or push to the platform.
3. **Never put a value on `argv`.** Use stdin: `echo "value" | akm add NAME`.
4. **If you find a `.env` in the project**, migrate each line: `echo "$value" | akm add $NAME` then delete the `.env`.

## Quick command reference

| Need | Command |
|---|---|
| Store from clipboard / chat | `echo "VALUE" \| akm add NAME` |
| Run code with keys | `akm run --only NAME -- <cmd>` |
| Upload to platform | `akm push vercel\|gh\|fly NAME ...` |
| List stored keys | `akm list --json` |
| Delete | `akm rm NAME` |
| See what was accessed | `akm audit` |

Run `akm agent-info --json` for the full capability manifest.
