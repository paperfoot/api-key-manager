---
name: akm
description: Use AKM on macOS to store credentials in Keychain, run commands with stored secrets, or supply secrets to a tool through stdin. Use for requested secret migration and backup too.
---

# AKM

Use stored credentials directly; no need to rediscover or check them before every call.

```bash
akm run --only OPENAI_API_KEY -- node server.js
akm run --only STRIPE_SECRET_KEY=PCC1_STRIPE_SECRET_KEY -- node script.js
akm stdin OPENAI_API_KEY -- gh secret set OPENAI_API_KEY
```

`run` injects environment variables; `stdin` writes the value to the child's
stdin. Both redact supplied values from child output and return the child's
exit code. A command that reads a local file or stdin needs no `akm run` too.

To store a value, pass it to `akm add NAME` through your subprocess API's stdin;
never put literal credentials in a command line. Names use `[A-Z_][A-Z0-9_]*`;
`akm list` finds stored names.

`akm agent-info --command run` describes one command. `get --raw` and `export`
print secrets: use them only for requested retrieval or backup. Piped
`get --raw` is still JSON (`data.value`). If Keychain access fails (exit 2), run
`akm doctor` and follow its suggestions.

Import `.env` only as part of a requested migration; check skipped entries and
validate the replacement before removing the source.
