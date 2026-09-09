---
description: Use ClaudePass Handles instead of Secret values. Use whenever a command needs an API key, token, password, or other Secret, or a prompt is about to include one.
---

## ClaudePass

This project keeps Secrets in a ClaudePass Vault; you only ever see a Handle, never a value.

- Never read `.env` or any other secret file directly.
- Run commands that need a Secret through `cpass run -- <command>`. It injects every Handle declared in `.claudepass.toml`; add one ad hoc with `--with <handle>[:VAR]`.
- When a command produces a new secret value, capture it instead of reading the output yourself: `cpass capture <handle> -- <command>` stores stdout as a Secret and prints only the Handle.
- Before relying on a Secret being available, run `cpass manifest check`; it exits non-zero and names any missing Handle.
