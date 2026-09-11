# Threat model

This is the threat model ClaudePass is built to: what it defends, what it
deliberately does not attempt, and the leak paths that honestly remain
inside what it does attempt. `docs/SECURITY.md` is the companion reference
for exactly what each component does and touches; this page is about what
that design is and isn't defending against. Vocabulary follows
[`CONTEXT.md`](../CONTEXT.md).

## What this protects: Context confidentiality

The one property ClaudePass exists to hold is: **a Secret's raw value must
never enter an Agent's Context** — never sent to the model provider as part
of a prompt or tool result, never written into a transcript, session log,
or history file that a future Context could be built from.

The actors in that sentence, precisely:

- **The Agent** (Claude Code, Codex, or similar) is the thing being
  protected *from* seeing a value, not a thing assumed to be hostile. It is
  assumed to faithfully do what it's told, including running whatever
  command it's given — which is exactly why the value must never be *in*
  what it's told to begin with. Everything the Agent's Context does
  contain (prompts, tool results, transcripts) is assumed to eventually
  leave this machine, because that is what an Agent's Context is for.
- **The human at a real terminal** is trusted: they can type a master
  passphrase, read a Secret with `cpass add`'s hidden prompt, and pass
  `--unsafe-allow` to skip Command Policy for their own command. Every gate
  in ClaudePass that distinguishes "a human is here" from "an Agent is
  asking" exists to keep an Agent from doing these things, not to keep a
  human out of their own Vault.
- **The Vault, the Broker, and the two hooks** are the trusted computing
  base: code you did not write and cannot audit (ClaudePass is closed
  source, see [ADR-0006](adr/0006-closed-source-paid.md)), running as your
  own user, which this threat model assumes behaves as `docs/SECURITY.md`
  describes.

The mechanisms that hold this property, each mapped to the piece of it they
address:

- **Handles instead of values** ([ADR-0001](adr/0001-reference-and-inject.md)):
  an Agent composes commands using Handles; a value is never a token the
  model has to have seen to write the command.
- **Injection at the Broker, not in the Agent's tool call**: the value
  exists only inside the one child process `cpass run` spawns.
- **Redaction** ([ADR-0002](adr/0002-redaction-in-the-broker.md)): a value
  that a command echoes back is stripped from stdout/stderr before an
  Agent's tool result is built, for the encodings and conditions
  `docs/SECURITY.md` states.
- **Command Policy**: refuses, before it runs, a command whose only
  purpose is to defeat the two mechanisms above (dump the environment, cat
  a Secret-bearing file, print a bound variable).
- **Intercept**: catches a value a human typed into a prompt before the
  Agent's Context is ever built from that prompt.
- **Exposed tracking**: when a value does reach a Context anyway — a
  bypassed Intercept, a manual paste before the plugin was installed —
  ClaudePass records that fact rather than pretending it didn't happen, so
  rotation is a nagged, tracked action instead of a silent gap.

## Out of scope

These are not gaps in the mechanisms above; they are things ClaudePass does
not attempt at all, by deliberate design ([ADR-0005](adr/0005-manifest-portable-vault-bound.md)
and the PRD's own Out of Scope section).

- **Authorization.** Command Policy decides whether a *command* may run —
  it has no notion of *who* is asking. Anyone who can run `cpass` as the
  Vault's owning user can use every Handle in it; there is no per-Secret
  ACL, no "this Agent may only touch `stripe/test`," no distinction between
  one Agent session and another. If two Agents (or an Agent and a script)
  share a machine and a Vault, they share every Secret in it.
- **Cloud-hosted Agent sessions.** The Vault is a single local file that
  ClaudePass never syncs, uploads, or ships to a remote sandbox. A session
  running in someone else's cloud sandbox has no Broker to reach on this
  machine, so it simply has no Secrets available — this is a missing
  feature (a relay channel is deferred, per ADR-0005), not a defense
  against a compromised remote sandbox.
- **Sync across machines, teams and sharing, automatic rotation.** None of
  this exists yet, so none of it has a threat model.
- **Compromise of the account `cpass` runs as.** If an attacker already has
  arbitrary code execution as the same Unix user, they can read
  `CPASS_KEY` out of another process's environment, connect to the Broker's
  Unix socket while it's up, read the macOS Keychain item directly (see
  `docs/SECURITY.md`'s stated limitation there), or read the decrypted
  Vault straight out of a running `cpass` process's memory. ClaudePass
  keeps a Secret out of an *Agent's Context*; it is not a defense against a
  compromised account, a malicious human with a shell, or a co-resident
  process running as the same user.
- **Windows**, beyond "it builds": the Broker process isn't implemented
  there, so only `CPASS_KEY` unlock works, and this threat model's claims
  are not exercised on that platform.
- **Adapters to other secret stores, an HTTP rewriting proxy.** Both were
  considered and rejected as the foundation
  ([ADR-0001](adr/0001-reference-and-inject.md),
  [ADR-0003](adr/0003-own-vault-no-adapters.md)); there is nothing to
  threat-model in a design that doesn't exist.
- **Telemetry.** There isn't any — see `docs/SECURITY.md`'s no-telemetry
  statement. This document isn't defending against ClaudePass's own
  servers, because outside license issuance there are none it talks to.

## Known leak paths that remain

Even within what ClaudePass does attempt, these are the ways a Secret's
value can still end up somewhere it shouldn't, today:

1. **The streaming Redactor's chunk-timing gap.** A value the wrapped
   command writes in pieces shorter than 4 bytes with more than 100 ms
   between pieces evades the streaming matcher (identified closing CLA-21).
   Each fragment is short enough, and the gap wide enough, that it is
   flushed as ordinary output before the next fragment could complete a
   match. See `docs/SECURITY.md`'s Redaction section for the full,
   honest statement this is one instance of: **Redaction makes leaking
   hard and detectable, not impossible.**
2. **Encodings Redaction doesn't recognise.** Raw, base64 (both alphabets,
   three alignments), hex, percent-, and JSON-escaping are covered. A
   command that transforms a value some other way before printing it —
   its own bespoke encoding, compression, encryption, a Caesar/rot13-style
   shift, re-chunking with separators spliced mid-value — passes through
   unrecognised.
3. **Anything not written to the wrapped command's own stdout/stderr.**
   Redaction only ever sees the two pipes `cpass run`/`capture` own. A
   value the child writes to a file, a Unix socket, another process's
   stdin, or ships off to a log/metrics service of its own is invisible to
   it — closing that path is Command Policy's job (refusing the well-known
   ways a command tries to read a Secret back out for exactly this
   purpose), and Command Policy is necessarily a list of known patterns,
   not a sandbox.
4. **Two narrow, deliberate differences remain between the PreToolUse hook
   and the other two surfaces** (closed for the file-glob and raw-literal
   rules themselves by CLA-38 — see below). `cpass policy --hook` alone
   refuses `cpass add <handle> <value>` (an inline second positional
   argument defeats the terminal gate `cpass add`'s own hidden prompt
   enforces): there is no equivalent check in `cpass run` or the MCP
   server, since only the hook inspects a raw Bash command line before
   `cpass` has parsed anything, and `cpass add` is not a command either of
   them wraps. Separately, the hook's raw-literal scan (`internal/detect`)
   covers a command's entire text, including its program's own path,
   while the shared `Evaluate` (used by `cpass run`, the MCP server's
   `run_with_secrets`/`capture` tools, and the hook itself) deliberately
   excludes argv[0] from that scan: a real executable path — a build
   artifact under a randomly named temp directory, a versioned tool under
   a hashed store path — routinely reads as high-entropy to the same
   heuristic without being a Secret, and a Secret value is never itself
   the program being executed, so nothing is actually missed by excluding
   it. Before CLA-38, the secret-file-glob rule (`.env*`, `*.pem`,
   `id_rsa*`, `*.key`, `credentials*.json`, `.netrc`, `.npmrc`) and the
   raw-literal rule applied only to the hook: `cpass run -- cat .env` and
   an MCP `run_with_secrets` call with `command: ["cat", ".env"]` were
   **not** refused, even though the functionally identical Bash tool call
   inside Claude Code was — and `internal/policy`'s package doc comment
   overclaimed "the same evaluator serves `cpass run`, the ... hook, and
   the MCP server, so behaviour is identical everywhere." Both rules now
   live in the shared `Evaluate`, so all three surfaces refuse the same
   file reads and raw literals; the package doc comment states precisely
   the two differences left above.
5. **The `!!` Intercept bypass is a deliberate escape hatch, not a filter
   that got weaker.** It exists so a false positive never blocks real
   work; using it on an actual Secret sends that value into the Agent's
   Context on purpose. Marking it Exposed afterward is the intended
   remediation (rotate it), not a mechanism that stops the exposure from
   happening.
6. **Detection can miss or over-trigger.** `internal/detect`'s prefix list,
   PEM matcher, and entropy heuristic are exactly that — a heuristic. A
   real Secret shaped unlike anything on the prefix list and not
   high-entropy enough to clear the threshold is neither Intercepted nor
   caught by Command Policy's raw-literal check; conversely an ordinary
   high-entropy identifier can occasionally be flagged when it isn't one.
7. **The macOS Keychain item and the Broker's Unix socket have no access
   control beyond the ordinary OS user boundary** (detailed in
   `docs/SECURITY.md`). This is the "compromise of the account" scope
   above made concrete: it's the specific, practical way an already-unlocked
   Vault's key would reach a second process running as the same user.
8. **The human-terminal gate is `isatty()`, nothing stronger.** `cpass
   add`, `cpass capture`'s prompts, and `--unsafe-allow` all distinguish "a
   human is here" from "an Agent is asking" by whether stdin is a terminal.
   A full pty allocated by something other than an interactive shell would
   satisfy that check; a Unix process has no stronger signal available to
   it that a human, specifically, is on the other end.

## Intercept precision (v0.1.4)

The prompt Intercept hook and Command Policy block only on high-confidence Secrets: known provider-key prefixes (Stripe, GitHub, AWS, OpenAI, Anthropic, Google, Slack, ...) and PEM private-key blocks. They do NOT block on generic entropy, because ordinary agent traffic is full of high-entropy non-secrets (tool-call ids, UUIDs, git SHAs, base64 blobs, automated task notifications) and a false block stops the user's work. The honest trade: an unprefixed pasted secret is not auto-caught by Intercept; store it with `cpass add`, after which Redaction protects it. `detect.Scan` still offers the entropy heuristic for advisory, non-blocking uses.
