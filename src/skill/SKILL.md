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
akm stdin OPENAI_API_KEY --format env -- flyctl secrets import
```

`run` injects environment variables. `stdin` supplies the value on stdin. Both
redact supplied values from child output and preserve child exit codes. An
upstream command reading a local file or stdin does not need `akm run` too.

To store a value, pass it to `akm add NAME` through your subprocess API's stdin;
do not interpolate literal credentials into shell commands. Key names use
`[A-Z_][A-Z0-9_]*`. Use `akm list` when you need to find a stored name.

For unfamiliar options, use `akm agent-info --command run` (or the relevant
command); `akm <command> --help` is also available. `get --raw` and `export`
produce secrets: use them for requested retrieval/backup, not routine execution.
Piped `get --raw` returns JSON; `--raw` means unmasked, not bare text.

Keep existing project configuration working. Import `.env` only as part of a
requested migration; check skipped entries and validate the replacement before
removing the source. Do not turn unrelated coding work into a migration.
