# Security

ClaudePass is closed source (see [ADR-0006](adr/0006-closed-source-paid.md)),
so trust in it has to come from documentation rather than from reading the
code yourself. This page says exactly what each component does and touches
— the Vault's format and cipher, where the unlock key lives on each
platform, what the two Claude Code hooks read and block, what `cpass run`
does to a child process and its output, what Redaction can and cannot
guarantee, the redaction log, the license check, and a no-telemetry
guarantee. `docs/THREATS.md` covers the threat model and the leak paths
this design deliberately leaves open; this page is the "what actually
happens" reference underneath it. Vocabulary follows
[`CONTEXT.md`](../CONTEXT.md).

## The Vault

- **Location**: `$CPASS_HOME/vault.cpv`. `CPASS_HOME` defaults to
  `os.UserConfigDir()/claudepass` — `~/Library/Application Support/claudepass`
  on macOS, `$XDG_CONFIG_HOME/claudepass` (usually `~/.config/claudepass`) on
  Linux — and can be overridden with the `CPASS_HOME` environment variable.
  The file is written with mode `0600` inside a `0700` directory, atomically
  (written to `vault.cpv.tmp`, then renamed).
- **Format**: a JSON envelope (`internal/vault/vault.go`) holding a format
  version, a random 32-byte data key wrapped by the unlock key, and the
  entry list encrypted under that data key. Both layers use
  **XChaCha20-Poly1305** (an AEAD cipher: `golang.org/x/crypto/chacha20poly1305`),
  each with its own random nonce. The outer wrap's associated data binds in
  the format version and both nonces, so the envelope cannot be
  reassembled from parts of two different Vaults.
- **Wrong key vs. tampering are distinct failures**: a key that cannot
  unwrap the data key reports `vault: wrong key`; ciphertext, nonces, or
  JSON structure that fails to decode or fails its AEAD authentication tag
  reports `vault: integrity check failed (file is tampered or corrupt)`.
  Both fail loudly — the Vault never opens partially or silently drops
  entries.
- **Entries**: each holds a Handle, the Secret value, its default Binding
  (kind `env` or `file`, and a variable name), an Exposed flag with a
  history of `{at, reason}` exposures, and created/updated timestamps.
  Nothing is stored outside this encrypted envelope; there is no plaintext
  sidecar or cache.
- **Minimum Secret length**: 8 characters (`vault.MinSecretLength`),
  enforced wherever a value is stored (`add`, `capture`, `import`,
  `intercept`) — so Redaction is never asked to scrub a string so short it
  would also match large stretches of ordinary output.

## Where the unlock key lives, per platform

`cpass` resolves the unlock key in this order, every time it needs the
Vault (`broker.UnlockKey`):

1. **`CPASS_KEY`** (base64 of 32 raw bytes), if set. This is the only
   supported way to run `cpass` fully unattended (CI, containers) and
   bypasses everything below entirely.
2. **macOS, by default**: a Keychain item. `cpass init` creates a
   generic-password item (service `cpass`, or `$CPASS_KEYCHAIN_SERVICE`;
   account = the Vault's absolute path, so multiple Vaults never collide)
   holding the key, base64-encoded. Every read and write goes through the
   `security` command-line tool as a subprocess — `cpass` links no Security
   framework and no cgo. **Stated plainly**: because it's created this way,
   the item carries no access-control list requiring Touch ID or a
   password, unlike a fully hardened Keychain item; any process running as
   the same macOS user that knows the service and account name can read it
   directly with `security find-generic-password -w`. This is a known,
   current limitation of the v1 unlock model (a cgo-based, ACL'd item is
   follow-up work), not a hidden one.
3. **Linux, CI, or macOS with `CPASS_UNLOCK=socket`**: a Broker process.
   `cpass unlock` prompts for a master passphrase on a real terminal,
   derives the key with **scrypt** (`N=2^15, r=8, p=1`, a random 16-byte
   salt persisted at `$CPASS_HOME/broker.salt` with mode `0600`, so the same
   passphrase always re-derives the same key), and hands that key to a
   detached `cpass broker-serve` process over a pipe — never a command-line
   argument, so it never appears in `ps`. That process listens on a
   user-only Unix domain socket (mode `0600`) at `$XDG_RUNTIME_DIR/cpass.sock`
   if `XDG_RUNTIME_DIR` is set, else `$CPASS_HOME/cpass.sock`; holds the key
   in memory only (never written to disk); answers a `RESOLVE` request with
   the key; and exits — dropping the key — after an idle timeout (default
   4h, `cpass unlock --timeout`) or on `cpass lock`. Anything able to
   connect to that socket, i.e. any process running as the same user
   (ordinary Unix socket permissions are the only gate), can retrieve the
   key while the Broker is up.
4. Windows is untested beyond building; the Broker process is not
   implemented there yet (`broker.StartBroker` returns an explicit "not
   supported" error), so only `CPASS_KEY` works.

## What the Intercept hook reads and where it writes

`cpass intercept` is registered as Claude Code's `UserPromptSubmit` hook by
`cpass integrate claude` (written into
`<skills-dir>/claudepass/hooks/hooks.json`, default skills dir
`~/.claude/skills`).

- **Reads**: the hook's JSON payload on stdin — only the `prompt` field is
  used; every other field Claude Code sends (`session_id`,
  `transcript_path`, `cwd`, …) is ignored. Nothing else on disk or the
  network is read to make its decision; detection (`internal/detect`) runs
  in memory against the prompt text only.
- **Writes**: on a match, it opens the Vault and stores each matched value
  as a new Secret — inferring a Handle from a known key-prefix
  (`sk_live_` → `stripe/live`, `ghp_` → `github/token`, `AKIA` →
  `aws/access-key`, and similarly for Anthropic, OpenAI, Slack, Google, and
  PEM private keys), or `inbox/<UTC timestamp>` when it can only tell that a
  value looks Secret-shaped — then saves the Vault file. That file
  (`$CPASS_HOME/vault.cpv`) is the only thing this command writes.
  - Without the `!!` bypass, it exits `2` with a one-line stderr message
    naming the stored Handle(s); Claude Code's `UserPromptSubmit` protocol
    treats exit `2` as "block the submission and show this to the human,"
    so the prompt — and the raw value inside it — never reaches the model.
  - With the `!!` bypass, it still stores the match(es), but flagged
    Exposed (reason `bypass`) rather than clean, and always exits `0` so the
    prompt goes through: a bypassed value is about to enter the Agent's
    Context, so per `CONTEXT.md`'s definition it is Exposed on arrival, not
    silently stored as if it never had been.

## What the PreToolUse hook blocks

`cpass policy --hook` is registered as Claude Code's `PreToolUse` hook,
matcher `Bash`, alongside Intercept. It reads
`{"tool_name": "...", "tool_input": {"command": "..."}}` from stdin (a
non-Bash `tool_name` or an empty command is a silent pass-through) and, for
everything else, evaluates `policy.EvaluateHook` against the raw command
string. It refuses (exit `2`, one stderr line naming the rule and a
suggested alternative) a command that, at any nesting depth (pipelines,
`$(...)`, backticks, or a `shell -c '...'` inside it, up to 8 levels):

- would read a Secret-bearing file directly — matched by basename against
  `.env*`, `*.pem`, `id_rsa*`, `*.key`, `credentials*.json`, `.netrc`,
  `.npmrc` — via a reader program (`cat`, `less`, `more`, `head`, `tail`,
  `base64`, `xxd`, `od`, `strings`, `hexdump`, `bat`, `tee`, `cp`, `nl`,
  `tac`, `rev`, `sort`, `uniq`, `cut`, `awk`, `sed`, `grep`, `jq`, `yq`,
  `dd`, `install`, `rsync`, `scp`) or a shell `source`/`.` builtin;
- carries a raw Secret-shaped literal anywhere in the command text (the
  same entropy/prefix detector Intercept uses);
- gives `cpass add` a second positional argument — an inline value, which
  would defeat the terminal gate `cpass add` enforces on itself; or
- is an environment dump with no Secret yet bound to check against —
  `printenv`, a bare `env`, `export`/`declare`/`typeset` with no arguments
  or with `-p`, `set` with no arguments, `compgen -v`, reading
  `/proc/*/environ`, or a shell/`set -x` trace flag — unless the command is
  itself a `cpass run` invocation, since that one re-applies the equivalent
  checks at execution time against its real Bound variables (see below).

This hook never opens the Vault and makes no network call; it is a pure,
static judgment over the command text (`internal/policy`).

**Scope note**: this hook's file-glob and raw-literal checks
(`EvaluateHook`) are stricter than the evaluator `cpass run` and the MCP
server use directly (`Evaluate`, see below) — see `docs/THREATS.md` for
exactly what that gap means in practice.

## What `cpass run` does to the child and its output

1. Resolves every requested Handle — explicit `--with handle[:VAR]`
   repeats, or every entry in the nearest ancestor `.claudepass.toml`
   Manifest when `--with` is omitted — to a value via the Broker.
2. Unless `--unsafe-allow` is given (refused outright without a terminal —
   an Agent invoking `cpass run` itself can never set it), evaluates
   `policy.Evaluate` against the command's argv: it refuses the
   environment-dump patterns above and any argument that literally names
   the path of this invocation's own file-Binding temp directory (see
   next point) passed to a reader program.
3. Builds the child's environment: `os.Environ()` plus one variable per
   env-bound Handle, set to its value. A file-bound Handle instead gets a
   fresh Secret file, mode `0600`, inside a per-invocation directory, mode
   `0700`, at `$CPASS_HOME/run/<16-hex-char id>/` — the variable holds that
   file's *path*, never the value. That directory also carries a `.pid`
   file naming the `cpass` process that created it, so a directory
   orphaned by a `cpass` process that was itself killed gets swept and
   shredded by the next `cpass run` invocation, not left behind.
4. Spawns the command with `stdin` passed through unmodified, `stdout` and
   `stderr` piped through the Redactor (unless the caller is `cpass
   capture`, which bypasses redaction on stdout only — see below), and
   `SIGINT`/`SIGTERM`/`SIGHUP` forwarded to the child so interactive
   Ctrl-C behaves normally.
5. On every exit path — the child exits normally, is killed by a signal,
   or `cpass` itself is killed before it can clean up (swept on the next
   run instead) — every file in the per-invocation temp directory is
   overwritten with zeros, `fsync`'d, unlinked, and the directory removed:
   shredded, not just deleted.
6. Returns the child's real exit code, or `128 + signal number` if a
   signal killed it — `cpass run` is exit-code-transparent.
7. If an injected Secret is Exposed, prints one reminder line per run to
   stderr (`cpass: <handle> is Exposed since <date>, rotate it`); after the
   child exits, prints one summary line per Handle actually redacted from
   its output (`cpass: redacted <handle> from output (<n>×); the Agent must
   use the value, not print it`). Both are stderr notices for the human,
   never anything that blocks or changes the child's own output.

`cpass capture <handle> -- <command>` and the MCP server's
`run_with_secrets` and `capture` tools call this exact same function
(`internal/run.Run`), so this behaviour — Redaction, Command Policy, file
Bindings, signal forwarding, shredding — is identical regardless of surface.
`capture` sets `RawStdout`: the child's stdout bypasses the Redactor
entirely, because it is about to be stored as the new Secret itself and
redacting it would corrupt the captured value; its stderr is still
redacted like an ordinary `run`.

## What Redaction can and cannot guarantee

Honest statement, per [ADR-0002](adr/0002-redaction-in-the-broker.md):
**Redaction is best-effort by design. It makes leaking a Secret through a
wrapped command's own stdout/stderr hard and detectable — it does not make
it impossible.**

What it does cover, for every value injected into the current `cpass
run`/`capture` invocation: the raw value; base64 in both the standard and
URL-safe alphabets, at all three byte-alignments a value can start on
inside a longer base64 stream (so a value embedded anywhere inside, say,
`echo "token=$X" | base64` is still caught); hex; percent-encoding
(`url.QueryEscape` and `url.PathEscape` forms); and JSON string-escaping.
Matching is streaming, over a sliding window at least as long as the
longest such encoded form, so a match split across two separate writes
(e.g. by a pipe buffer, or a command that flushes mid-value) is still
caught; a partial match still pending is released as ordinary output after
a short (100 ms, for a partial under 4 bytes) or longer (1.5 s) idle period,
so interactive tools stay responsive rather than hanging on a byte that
turns out not to complete a match.

**Documented limitation** (identified closing CLA-21, streaming Redaction):
a value the wrapped command writes in chunks shorter than 4 bytes with more
than 100 ms between chunks evades the streaming matcher — each fragment is
short enough, and the gap wide enough, that the idle timer flushes it as
ordinary output before the next fragment arrives to complete the match. A
command has to go out of its way to write that slowly and that
fragmented for this to matter in practice; it is recorded here because
"we tested every leak path we could think of" is a different claim from
"impossible," and the leak-test suite in `internal/e2e/leak_test.go`
deliberately does not claim to cover this case.

What it structurally cannot cover, regardless of tuning:

- **Only the wrapped command's own stdout/stderr.** A value the child
  writes anywhere else it can reach — a file, a socket, a pipe to another
  process, its own log output to a service — never passes through the
  Redactor at all. Command Policy's job is to refuse the well-known ways a
  command tries to do exactly that (reading a file-Binding temp path, an
  environment dump); Redaction's job starts only once bytes reach the pipe
  `cpass run` itself owns.
- **Only the encodings listed above.** A value the child transforms some
  other way before printing it — its own bespoke encoding, compression,
  encryption, reversal, re-chunking with separators inserted mid-value — is
  not recognised and passes through unredacted.

## The redaction log

Every redaction event is appended, one line per event, to
`$CPASS_HOME/redactions.log` (created on first use if it doesn't exist,
mode `0600`, append-only, never rotated or truncated by `cpass` itself):

```
<RFC3339 UTC timestamp> handle=<handle> encoding=<raw|base64|base64url|hex|percent|json> stream=<stdout|stderr> cmd=<argv[0] basename>
```

The Secret's value itself is never written to this file, in any form or
encoding — only that a redaction happened, for which Handle, in which
encoding, on which stream, for which command's basename.

## The license check is offline

A license token is `base64url(JSON{sub, plan, exp, iat, jti})` + `.` +
`base64url(Ed25519 signature)`. The Ed25519 public key that verifies it
ships baked into the `cpass` binary (`internal/license/publickey.go`);
`cpass license activate <token>` verifies the signature **entirely
locally** and, only if it verifies, writes the token verbatim to
`$CPASS_HOME/license` (mode `0600`) — it never sends the token, or anything
derived from it, anywhere. `cpass license status`, `cpass license
deactivate`, and every command that gates a new Secret on the free-plan
limit read that same local file and do the arithmetic (plan, expiry) in
the `cpass` process itself. Issuing a token in the first place —
`services/license/`, a separate small Go service behind Stripe Checkout —
is a different binary this CLI never talks to; `cpass` only ever verifies,
never issues or phones home to check.

## No telemetry

**The only network call the `cpass` binary ever makes, in any command, at
any point, is none.** `cmd/cpass`, `internal/cli`, `internal/vault`,
`internal/broker`, `internal/run`, `internal/redact`, `internal/policy`,
`internal/manifest`, `internal/detect`, `internal/dotenv`, `internal/mcp`,
`internal/integrate`, and `internal/license` import no `net/http` and open
no outbound network connection anywhere — the only networking primitive in
the whole binary is `internal/broker`'s own Unix domain socket to the local
Broker process (loopback-only, machine-local, never a network address).
Two things outside the `cpass` binary itself do touch the network, and
neither is telemetry: `install.sh` fetches a release archive and its
`checksums.txt` over HTTPS from `claudepass.com` (verifying the archive's
sha256 before installing it) to install `cpass` in the first place, and
`services/license/` is the separate hosted service that issues license
tokens after a Stripe Checkout — the `cpass` binary you run afterwards
never talks to it (see above).

## Every `CPASS_*` environment variable

| Variable | Read by | Purpose |
|---|---|---|
| `CPASS_HOME` | `broker.Home` | Overrides the ClaudePass home directory (default `os.UserConfigDir()/claudepass`); everything below is relative to it. |
| `CPASS_KEY` | `broker.UnlockKey` | Base64 of a 32-byte unlock key; the first key source tried, ahead of the Keychain and the Broker socket. The supported way to run unattended (CI). |
| `CPASS_UNLOCK` | `broker.UseKeychain` | Set to `socket` to force the Linux/CI Broker-process unlock path even on macOS. |
| `CPASS_KEYCHAIN_SERVICE` | `broker.KeychainService` | Overrides the macOS Keychain service name (production always uses `cpass`; tests point this at a throwaway name so they never touch a real login Keychain). |
| `CPASS_CI` | `broker.CIMode` | `1` forces CI mode (Handles resolve from the environment CI already provides, not the Vault); `0` forces it off. |
| `CI` | `broker.CIMode` | Not a `CPASS_*` variable, but consulted alongside `CPASS_CI`: `CI=true` with no Vault file present at the resolved path also triggers CI mode. |
| `CPASS_TEST_STDIN` | `cli.testStdin` | **Test-only** — compiled in only by binaries built with `-tags e2e`. Lets a non-terminal stdin satisfy `cpass add`/`cpass capture`'s terminal gate, so the e2e suite can drive prompts without a real TTY. A release binary has no way to read this variable at all. |
| `CPASS_TEST_TTY` | `cli.testTTY` | **Test-only**, same `-tags e2e` gate as above. Forces `humanPresent()` true, for exercising `--unsafe-allow` and similar human-only paths from a test harness. |
| `CPASS_TEST_LICENSE_PUBKEY` | `license.trustedPublicKey` | **Test-only**, same `-tags e2e` gate. Base64 of a throwaway 32-byte Ed25519 public key, so tests can mint and verify their own license tokens without the real signing key (which is not in this repository) or the real trusted key. |
| `CPASS_VERSION` | `install.sh` only | Not read by the compiled `cpass` binary. `latest` (default) or an explicit release tag (e.g. `v0.1.2`) for the installer to fetch from `claudepass.com/dl/<version>/`. |
| `CPASS_INSTALL_DIR` | `install.sh` only | Not read by the compiled `cpass` binary. Where the installer places the downloaded `cpass` binary. |
| `CPASS_BASE_URL` | `install.sh` only | Not read by the compiled `cpass` binary. Overrides the download origin the installer fetches the release archive and `checksums.txt` from (default `https://claudepass.com`) — for a mirror or a test fixture server. |

## Every path `cpass` touches on disk

All paths below are relative to `$CPASS_HOME` unless stated otherwise.

| Path | What it is | Mode |
|---|---|---|
| `$CPASS_HOME/vault.cpv` | The Vault: the encrypted envelope described above. | `0600` (dir `0700`) |
| `$CPASS_HOME/vault.cpv.tmp` | Transient — the Vault's atomic-write staging file; renamed over `vault.cpv` on save, never left behind on success. | `0600` |
| `$CPASS_HOME/broker.salt` | The scrypt salt for deriving the unlock key from a passphrase (Linux/CI unlock path only). | `0600` |
| `$CPASS_HOME/cpass.sock` (or `$XDG_RUNTIME_DIR/cpass.sock` if set) | The Broker process's Unix domain socket (Linux/CI unlock path only). | `0600` |
| `$CPASS_HOME/redactions.log` | The append-only redaction event log described above. | `0600` |
| `$CPASS_HOME/run/<16-hex-char id>/` | One per-invocation temp directory for `cpass run`'s file Bindings; holds a `.pid` file and one file per file-bound Secret, all shredded on exit. | `0700` (files `0600`) |
| `$CPASS_HOME/license` | The activated license token, stored verbatim after local signature verification. | `0600` |
| `.claudepass.toml` (repo root, found by walking up from the current directory) | The Manifest: which Handles this project needs and their Bindings. Contains no values; meant to be committed. | `0644` |
| `<skills-dir>/claudepass/` (default `~/.claude/skills/claudepass`, overridable with `cpass integrate claude --path`) | The installed Claude Code plugin: `.claude-plugin/plugin.json`, `hooks/hooks.json`, `skills/claudepass/SKILL.md`. | `0644` (dirs `0755`) |
| `AGENTS.md` (repo root, or `cpass integrate codex --path`) | A delimited, idempotent section `cpass integrate codex` writes teaching Codex the CLI. Everything outside the `<!-- cpass:begin/end -->` markers is preserved untouched. | `0644` |
