# ClaudePass

A secret manager for AI coding agents. It lets an agent use a secret at the point of execution without the secret's value ever entering the agent's context.

## Language

**Secret**:
A sensitive value (API key, password, token, private key) that must never appear in an agent's context.
_Avoid_: Credential, password (as the general term), key

**Handle**:
An opaque name that refers to a Secret without revealing its value. The only form in which a Secret is visible to an Agent.
_Avoid_: Reference, placeholder, alias, secret name

**Agent**:
An AI coding session (Claude Code, Codex, or similar) whose context must be kept free of Secret values.
_Avoid_: Model, assistant, AI, session

**Broker**:
The local component that resolves a Handle into a Secret value at the moment a command runs, so the value reaches the destination process but not the Agent.
_Avoid_: Vault, daemon, agent (in the 1Password/SSH sense), proxy

**Context**:
Everything an Agent sees: prompts, tool results, and anything persisted from them (transcripts, logs, history).
_Avoid_: Conversation, chat, window

**Redaction**:
The Broker's replacement of a Secret value, in any recognisable encoding, with a marker in the output of a command before that output can reach an Agent.
_Avoid_: Scrubbing, masking, filtering

**Command Policy**:
The rules deciding whether a command an Agent wants to run may proceed: refusing commands that would reveal a Secret rather than use it, read Secrets from disk, or carry a raw Secret value. Applied both before a command runs and when the Broker injects.
_Avoid_: Allowlist, blocklist, guard, hook rules

**Vault**:
The encrypted local store, owned by ClaudePass, where Secrets live. The only source the Broker reads from.
_Avoid_: Store, keychain, database, backend

**Binding**:
How a Secret lands in a command's process: either as an environment variable holding the value, or as a temporary file whose path is placed in an environment variable and which is destroyed when the command exits. A Handle carries a default Binding; a command may override it.
_Avoid_: Mapping, alias, export, mount

**Manifest**:
A committed, per-project declaration of which Handles the project needs and their Bindings. Contains no Secret values and is safe to share.
_Avoid_: Config, env file, profile, .env

**Capture**:
Storing the output of a command directly into the Vault as a new Secret, so that a value born in a tool result never reaches an Agent.
_Avoid_: Pipe-in, save output, record

**Intercept**:
Catching a Secret value in a human's prompt before it reaches an Agent, moving it into the Vault, and erasing the prompt so the Agent only ever sees a Handle.
_Avoid_: Scan, filter, prompt guard

**Exposed**:
The state of a Secret whose value has entered an Agent's Context at least once. An Exposed Secret is treated as compromised and due for rotation.
_Avoid_: Leaked, compromised, dirty, seen

## Excluded icons

Generic security/hacker clichés this brand never uses, in any iconography, on any surface (Figma iconography-root's "Excluded Clichés" QA row and trademark-guardrails' "DON'T" row; see `site/brand/`'s Iconography section for the enforceable version of this list):

- Padlock
- Hoodie-Hacker Shield
- Matrix-Rain
- Sparkle / Starburst
- Soft Rounded Keyhole

The Vault + `[REDACTED]` bar is the mark of security here, never a padlock or shield glyph. A new SVG under `site/assets/` whose filename contains `lock`, `padlock`, `shield`, `hoodie`, `hacker`, `matrix`, `sparkle`, `starburst`, or `keyhole` should be treated as a guardrail violation on sight — flag it in review rather than merging it.
