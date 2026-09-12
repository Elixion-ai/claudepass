# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability reporting: open
https://github.com/gumruyanzh/claudepass/security/advisories/new and describe how to reproduce the issue. Do not open a public issue for a security problem. We aim to acknowledge reports within a few days.

## What counts

A vulnerability is any way ClaudePass fails to hold the guarantees it claims: a Secret value reaching an Agent's Context through `cpass run`, `cpass capture`, the hooks or the MCP server; a Command Policy bypass; a Vault that opens without its key; a Redaction gap beyond the ones documented as best-effort.

For what those guarantees are, see [`docs/SECURITY.md`](../docs/SECURITY.md) (what each component does and touches) and [`docs/THREATS.md`](../docs/THREATS.md) (the threat model and the leak paths the design deliberately leaves open).
