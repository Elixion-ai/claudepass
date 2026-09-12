# ClaudePass v1 — PRD

## Problem Statement

Developers working with AI coding agents (Claude Code, Codex, and similar) constantly need the agent to run commands that require secrets: deploy scripts, API calls, database migrations, cloud CLIs. Today the only way to give an agent a secret is to paste it into the conversation or leave it in a `.env` file the agent reads. Either way the value enters the agent's Context: it is sent to the model provider, written into transcript files, session logs, and history, and can be echoed back in any tool result. Every existing password manager is built for a human at a keyboard; none is built for an agent that must *use* a secret it is never allowed to *see*.

## Solution

ClaudePass is a secret manager for AI coding agents. A developer stores Secrets in a local encrypted Vault. The Agent only ever sees Handles, opaque names like `stripe/live`. When the Agent runs a command through `cpass run`, the Broker injects the real values into the child process, redacts them from everything that comes back, and refuses commands whose purpose is to reveal rather than use them. A committed Manifest declares which Handles a project needs so the Agent never guesses. Secrets born in tool output are Captured straight into the Vault; secrets pasted by mistake are Intercepted before the model sees them; anything that did reach Context is marked Exposed and nagged for rotation. It ships as one `cpass` binary plus a Claude Code plugin, a Codex snippet, and an MCP server. ClaudePass is free and open source under the MIT license (ADR-0011).

## User Stories

### Vault and Handles
1. As a developer, I want to initialise a Vault with one command, so that I have somewhere safe to put Secrets before my first Agent session.
2. As a developer, I want to add a Secret under a hierarchical Handle with hidden terminal input, so that the value never appears on screen or in shell history.
3. As a developer, I want to list Handles without values, so that I and my Agent can discover what exists without exposing anything.
4. As a developer, I want to rename, move, and delete Handles, so that my Vault stays organised as projects change.
5. As a developer, I want each Handle to carry a default Binding (an env var name, or a file), so that `cpass run` knows where the value should land without me repeating it.
6. As a developer, I want the Vault to be a single encrypted file I can back up, so that losing a laptop doesn't mean losing every Secret.
7. As a developer, I want the Vault format to refuse to open with the wrong key and to detect tampering, so that a corrupted or modified file fails loudly rather than silently.

### Unlocking
8. As a macOS developer, I want the Vault key held in the Keychain and unlocked with Touch ID or my login session, so that I never type a master password and no daemon runs.
9. As a Linux developer, I want to run `cpass unlock` once in my own terminal and have a Broker process hold the key with an idle timeout, so that Agent sessions work without a TTY.
10. As a developer, I want `cpass run` invoked from an Agent to fail fast with a clear "Vault is locked, run cpass unlock" message, so that the Agent can relay it to me instead of hanging.
11. As a developer, I want `cpass lock` to drop the key immediately, so that I can lock before stepping away.
12. As a CI pipeline, I want `cpass` to take its key from an environment variable, so that headless runs need no interactive unlock.

### Running commands
13. As an Agent, I want to run `cpass run --with stripe/live -- <command>` and have the Secret land in the command's environment under its default Binding, so that I can use it without reading it.
14. As an Agent, I want to override the Binding inline (`--with stripe/live:STRIPE_KEY`), so that tools with unusual env var names still work.
15. As an Agent, I want `cpass run -- <command>` with no `--with` to inject every Handle in the project's Manifest, so that I never have to enumerate Handles myself.
16. As an Agent, I want file Bindings to materialise as 0600 temp files whose path is exposed via an env var and which are destroyed when the command exits, so that `gcloud`, `ssh`, and `psql` work without a persistent secret on disk.
17. As an Agent, I want the exit code, signals, and stdin of the wrapped command passed through faithfully, so that `cpass run` is transparent for pipelines and interactive-ish tools.
18. As an Agent, I want long-running commands (dev servers, watchers) to stream output through `cpass run` with no buffering delay, so that Redaction doesn't make the tool unusable.

### Redaction
19. As a developer, I want every injected value replaced with `[REDACTED:<handle>]` in the wrapped command's stdout and stderr, so that a Secret echoed by a tool never reaches the Agent's Context.
20. As a developer, I want Redaction to cover base64, URL-encoded, and JSON-escaped forms of the value, so that the common transformations tools apply don't bypass it.
21. As a developer, I want Redaction to work across output chunk boundaries, so that a value split by a pipe buffer is still caught.
22. As a developer, I want Secrets shorter than a sane minimum to be refused at add time, so that Redaction never has to scrub trivially short strings from all output.
23. As a developer, I want every Redaction event logged locally with the Handle, command, and timestamp, so that I can see when an Agent tried, or a tool accidentally leaked.
24. As a developer, I want Redaction to also apply to values from file Bindings, so that `cat`-ing the temp file cannot leak the content.

### Command Policy
25. As a developer, I want `cpass run` to refuse commands that exist only to print their environment (`env`, `printenv`, `export -p`, `echo $VAR`, `set`), so that the trivial leak path is closed.
26. As a developer, I want `cpass run` to refuse reading the file-Binding temp directory (`cat`, `less`, `head`, `base64` on it), so that file Secrets can't be dumped.
27. As a developer, I want a Command Policy block to explain what was refused and why in one line, so that the Agent can choose a legitimate alternative.
28. As a developer, I want to be able to override Command Policy from my own terminal with an explicit flag, so that I am never locked out of my own Secrets.

### Manifest
29. As a developer, I want `cpass manifest init` to create a committable Manifest in the repo, so that the project declares what it needs without containing any values.
30. As a developer, I want `cpass manifest add <handle> [binding]` and `cpass manifest check`, so that I can maintain the Manifest and verify my Vault satisfies it.
31. As an Agent, I want `cpass manifest check` to name missing Handles by name only, so that I can ask the developer for exactly what's missing.
32. As a CI pipeline, I want `cpass run` in CI mode to resolve each Manifest Handle from the environment CI already provides instead of a Vault, so that the Manifest is the one contract everywhere.
33. As a developer, I want a Manifest to support per-Handle file Bindings, so that projects needing a credentials file declare it the same way.

### Ingestion
34. As a developer, I want `cpass import .env` to move every entry into the Vault, write or extend the Manifest, and shred the `.env`, so that no plaintext file remains next to the Manifest.
35. As a developer, I want `--keep` on import, so that I can opt out of shredding when I know better.
36. As an Agent, I want `cpass capture <handle> -- <command>` to store the command's stdout as a new Secret and print only the Handle, so that a key generated by a CLI never enters my Context.
37. As a developer, I want `cpass add` invoked without a TTY (i.e. by an Agent) to refuse with a message pointing at `cpass capture`, so that a value the Agent already knows is never stored as clean.
38. As a developer, I want `cpass add --exposed` to store a value I know has been seen, so that it's in the Vault but flagged for rotation.

### Intercept and Exposed
39. As a Claude Code user, I want a prompt containing a secret-shaped value to be blocked before the model sees it, the value stored in the Vault, and a message telling me the Handle to use instead, so that a careless paste costs nothing.
40. As a Claude Code user, I want Intercept to infer a Handle from known prefixes (`sk_live_` → `stripe/live`, `ghp_` → `github/token`, `AKIA` → `aws/access-key`) and fall back to `inbox/<timestamp>`, so that most pastes land somewhere sensible without me being asked.
41. As a Claude Code user, I want a bypass prefix (`!!`) that submits the prompt anyway, so that a false positive never blocks real work.
42. As a developer, I want `cpass exposed` to list every Exposed Secret with when and how it was exposed, so that I know what to rotate.
43. As a developer, I want `cpass run` to print a one-line rotation reminder when it injects an Exposed Secret, so that the nag is where I'll see it.
44. As a developer, I want `cpass rotate-done <handle>` to clear the Exposed flag after I've replaced the value, so that the nag stops.

### Agent integrations
45. As a Claude Code user, I want to install a ClaudePass plugin with one command that registers the Intercept hook, the Command Policy hook on Bash, and a skill teaching `cpass`, so that setup is a single step.
46. As a Claude Code user, I want the PreToolUse hook to block Bash commands that read `.env` or other secret files and commands containing a raw secret-shaped literal, so that "use `cpass run`" is enforced, not advised.
47. As a Claude Code user, I want the plugin's skill to teach the Agent `cpass run`, `cpass capture`, and the Manifest in the fewest words possible, so that it uses them correctly on the first try.
48. As a Codex user, I want `cpass integrate codex` to write an `AGENTS.md` section teaching the CLI, so that Codex sessions use Handles too.
49. As a user of any tool-first Agent, I want `cpass mcp` to expose `run_with_secrets`, `capture`, and `list_handles` over stdio MCP, so that agents without a shell still go through the Broker.
50. As a developer, I want the MCP server to apply the same Redaction and Command Policy as the CLI, so that there is one behaviour regardless of surface.

### Distribution
51. As a new user, I want to install `cpass` via Homebrew or a curl script with no account, license key, or payment, so that trying it costs nothing and stays that way.
52. As a contributor, I want the source on a public GitHub repository under the MIT license, so that I can read, audit, and fork it.
53. As a security-conscious user, I want a published document describing exactly what the hooks and Broker do and a no-telemetry guarantee, so that I can verify the claims myself against the source rather than trust them on faith.

### Quality
54. As the owner, I want an end-to-end test suite that drives the `cpass` binary against a fixture Vault and asserts on child environment, stdout, stderr, and exit code, so that every guarantee is tested at the boundary the Agent actually uses.
55. As the owner, I want a dedicated leak test suite that tries every known reveal path and asserts nothing reaches stdout, so that Redaction and Command Policy regressions are caught.
56. As the owner, I want CI to build and test on macOS and Linux and produce release binaries, so that every commit is shippable.

## Implementation Decisions

- **Language and shape.** Go, one static binary `cpass`, cross-compiled for macOS (arm64, amd64) and Linux (amd64, arm64). Windows builds but is untested. See ADR-0007.
- **Vault.** One file at a well-known path under the user's config directory. Contents: a JSON document of entries (Handle, value, default Binding kind and name, Exposed flag with history, timestamps) encrypted with XChaCha20-Poly1305 under a random data key; the data key is wrapped by the unlock key. Tamper detection comes from the AEAD tag. Minimum Secret length enforced at add time. See ADR-0003.
- **Unlock model.** macOS: the wrapping key lives in the Keychain, access-controlled to the `cpass` binary, with Touch ID where available; each `cpass` invocation reads it directly, no daemon. Linux and CI: a Broker process listening on a user-only Unix socket holds the key after `cpass unlock`, idles out after a configurable timeout (default 4h); `CPASS_KEY` env var bypasses it for CI. The Broker interface is a single "resolve Handles → values" call so the transport can change later. See ADR-0004.
- **`cpass run`.** Parses `--with handle[:BINDING]` repeats and the Manifest, resolves values, builds the child environment, materialises file Bindings into a per-invocation 0700 temp dir, spawns the command with stdin passed through and stdout/stderr piped through the Redactor, forwards signals, shreds the temp dir on exit, returns the child's exit code.
- **Redactor.** A streaming matcher over stdout and stderr holding a sliding window at least as long as the longest encoded value, replacing exact matches of each value and its base64, URL-encoded, and JSON-escaped forms with `[REDACTED:<handle>]`. Flushes on newline and on a short idle timer so interactive tools stay responsive. Logs events to a local append-only file. See ADR-0002.
- **Command Policy.** A rule set evaluated against the command's argv before spawning: refuse known reveal-only programs, refuse any argv referencing the temp-dir path with a reader, refuse shell strings whose only content is variable expansion. Rules are the same in the CLI, the PreToolUse hook, and the MCP server. A human-only `--unsafe-allow` flag (refused without a TTY) overrides.
- **Manifest.** A TOML file named `.claudepass.toml` at the repo root listing Handles with optional Binding overrides and kind (env or file). `cpass run` reads it from the nearest ancestor directory. In CI mode (`CPASS_CI=1` or detected CI env) each Handle resolves from the environment variable named by its Binding.
- **Ingestion.** `import` parses dotenv syntax, adds each entry, appends to the Manifest, and overwrites-then-unlinks the source unless `--keep`. `capture` reads the child's stdout fully, stores it, and prints the Handle; the child's stderr is redacted like `run`. `add` requires a TTY unless `--exposed` or invoked internally by capture/intercept.
- **Intercept.** A `cpass intercept` subcommand reads Claude Code's UserPromptSubmit JSON on stdin, scans with prefix patterns plus an entropy check on tokens ≥ 20 chars, stores hits with inferred or `inbox/` Handles (marked Exposed only if the bypass was used or detection ran after the fact), and exits 2 with a stderr message naming the Handle. `!!` prefix passes through.
- **Claude Code plugin.** A plugin directory with hooks (UserPromptSubmit → `cpass intercept`; PreToolUse matcher Bash → `cpass policy --hook`) and a skill file. Installable via the plugin marketplace mechanism or `cpass integrate claude`.
- **Codex.** `cpass integrate codex` writes or updates a delimited section in `AGENTS.md`.
- **MCP server.** `cpass mcp` speaks MCP over stdio with three tools; it calls the same internal run/capture functions as the CLI.
- **Distribution.** Public GitHub repo under the MIT license, GoReleaser producing signed binaries, Homebrew formula in the owner's existing tap, and a curl installer. See ADR-0011.

## Testing Decisions

- **The seam is the binary.** Almost every test drives the built `cpass` executable as a subprocess with `CPASS_HOME` pointed at a fixture directory and `CPASS_KEY` set, then asserts on the child's observed environment (via a helper program that prints its env to a file, never to stdout), on stdout/stderr text, and on exit code. This is the exact boundary an Agent uses, so tests test the guarantees, not the internals.
- **Leak tests are their own suite.** Each known reveal path (env dump, echo, cat of temp file, base64 pipeline, error message echo, chunk-split output, JSON error body) is one test asserting the value is absent from everything the Agent would see.
- **Unit tests only for pure cores.** The Redactor's streaming matcher, the Command Policy rule evaluator, and the Intercept detector get table-driven unit tests because their inputs are easy to enumerate and their bugs are subtle.
- **Hook tests feed real Claude Code JSON.** Fixtures captured from actual hook invocations, asserting exit codes and stderr content.
- **No prior art in the repo.** Go's standard `testing` package with `os/exec`; no framework.

## Out of Scope

Sync across machines, teams and sharing, automatic rotation, per-Secret authorization policies, Windows support beyond "it builds", cloud-hosted Agent sessions and the relay they would need, adapters to 1Password/Bitwarden/pass/keychains as Secret sources, an HTTP rewriting proxy, and any telemetry. See ADR-0005 and CONTEXT.md.

## Further Notes

- Vocabulary in `CONTEXT.md` is canonical: Secret, Handle, Agent, Broker, Context, Redaction, Command Policy, Vault, Binding, Manifest, Capture, Intercept, Exposed.
- Redaction is best-effort by design; the honest public framing is "we make leaking hard and detectable, not impossible."
- The name ClaudePass is settled and not to be re-raised.
- 1Password publishes an `agent-hooks` repository for AI agents; assume competition and move quickly.
