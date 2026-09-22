# Security

ClaudePass is free and open source under the MIT license (see
[ADR-0011](adr/0011-free-and-open-source.md)) — you can read the code
yourself, and this page still says exactly what each component does and
touches so you don't have to. This page covers the Vault's format and
cipher, where the unlock key lives on each platform, the Global Manifest and
how it reaches a project, what the two Claude Code hooks read and block,
what `cpass run` does to a child process and its output, what Redaction can
and cannot guarantee, the redaction log, and a no-telemetry guarantee.
`docs/THREATS.md` covers the threat model and the
leak paths this design deliberately leaves open; this page is the "what
actually happens" reference underneath it. Vocabulary follows
[`CONTEXT.md`](../CONTEXT.md).

## Reporting a vulnerability

This page documents what ClaudePass does and touches, not how to report a
security issue — see [`.github/SECURITY.md`](../.github/SECURITY.md) for
that.

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

## The Global Manifest

- **Location**: `$CPASS_HOME/global.toml` (`internal/manifest/global.go`) —
  the same TOML subset a project Manifest uses (a `[secrets]` list, an
  optional `[options]` section) and, like a project Manifest, holding no
  Secret values. The file is written `0644`; `SaveGlobal` creates
  `$CPASS_HOME` itself (`0700`) if it doesn't exist yet, the same as the
  Vault's own directory.
- **What writes and removes it**: `cpass add <handle> -g` (once the Secret
  is safely stored), `cpass global <handle>` (promotes a Handle already in
  the Vault without retyping its value), and `cpass manifest add <handle>
  -g` all declare one Handle into it. `cpass local <handle>` removes a
  declaration; the Secret itself, in the Vault, is untouched.
- **Reachability** (`manifest.globalReaches`): a Global Handle reaches a
  directory only when both hold — a project Manifest is found from that
  directory by the ordinary ancestor walk (`manifest.Find`), and no
  directory between the command's directory and that Manifest's own
  directory carries its own `.git`. Both ends of that walk are resolved with
  `filepath.EvalSymlinks` first: the walk itself is lexical while the `.git`
  check is a syscall the kernel resolves through links, and a link at the
  project root pointing into a nested repository would otherwise have a
  lexical parent of the project root itself — stepping over the very
  directory holding the boundary. A path that cannot be resolved (a dangling
  link, a directory renamed mid-run) withholds Global Handles rather than
  guessing. A directory with no Manifest anywhere above it gets no Global
  Handles at all. A nested repository cloned inside
  an onboarded project — a dependency under `vendor/`, a scratch checkout
  under `tmp/` — gets none either, because crossing its own `.git` withholds
  them: an install script that repository runs cannot reach the machine's
  ambient Secrets. The outer project's own explicitly declared Handles still
  reach such a directory, exactly as a committed Manifest has always meant;
  this gate does not change that. See `docs/THREATS.md` for the one gap this
  check does not close.
- **Opting out**: the durable opt-out is a property of the project's own
  committed Manifest, not a machine-local setting — `cpass manifest global
  off` (or `cpass manifest init --no-global` at creation) writes
  `[options]` / `global = false`, and every `cpass run` or
  `run_with_secrets` call against that project skips the Global Manifest
  from then on, whoever runs it. `cpass run --no-global`, and the MCP
  `run_with_secrets` tool's `no_global` argument, do the same for one
  invocation without touching the file.
- **Precedence**, most specific wins: the Global Manifest is the base layer;
  a project Manifest entry for the same Handle replaces it outright, Binding
  and all (`manifest.Refs`); `--with handle[:VAR]` (repeatable on `cpass
  run`) then overrides by Handle on top of that; and the MCP
  `run_with_secrets` tool's explicit `handles` argument, whenever it's
  given at all — even an empty list — replaces the entire source outright,
  so a Global Handle can never sneak into an explicit list the caller wrote.
- **Resolution: skip, not fail, for a Global Handle.** A Handle that reached
  the run through the Global Manifest and cannot be resolved — removed from
  the Vault since it was declared, or, in CI mode, its Binding's variable
  not set in the environment — is skipped rather than failing the run, with
  a stderr notice: ``cpass: <handle> is declared in your Global Manifest but
  <reason>; skipping it — run `cpass local <handle>` to stop declaring it``.
  A Handle a project declared itself, or one named in the MCP
  `run_with_secrets` tool's `handles` list, still hard-fails exactly as it
  always has: a drifted machine-wide declaration must not take every
  project down at once, but a project's own committed contract is still a
  contract. `cpass run --with handle[:VAR]` counts as naming it: `cmdRun`
  clears the Ref's Global origin when it merges the override, so a Handle
  asked for by name hard-fails when it cannot be resolved even if it was
  also reaching the run ambiently. Nothing a human or an Agent typed out is
  ever silently skipped.
- **An unreadable Global Manifest costs only its own Handles.** A
  `global.toml` that will not parse — a half-written file, a hand edit that
  went wrong — does not fail the run: `manifest.Refs` skips the Global layer,
  reports ``cpass: your Global Manifest is unreadable (<err>); skipping
  Global Handles for this run — run `cpass manifest check -g` once it is
  fixed`` on stderr, and the project's own declared Handles resolve
  normally. A project's *own* Manifest failing to parse is still fatal, for
  the same reason as above. A plain `cpass ls`, and the MCP `list_handles`
  tool without `global: true`, never read the file at all, so neither can be
  broken by it; `cpass ls -l` and `cpass ls --global` do read it, and report
  the failure.
- **Collisions**: two Handles bound to the same environment variable are
  refused — `cpass: handle collision: <a> and <b> both bind <VAR>`, exit `1`
  on `cpass run` — only when at least one of them reached the run through
  the Global Manifest. The MCP `run_with_secrets` tool refuses the same
  collision as an `isError: true` tool result whose text is the bare
  `handle collision: <a> and <b> both bind <VAR>` — MCP tool-level errors
  are returned as-is, with no `cpass: ` prefix and no process exit code (MCP
  has no exit code to give). Two Handles a project declares itself into the
  same variable keep today's silent last-write-wins, so no existing project
  starts failing on a version bump it never opted into.
- **The opt-out's round-trip guarantee, and its one real limit.** `Load` and
  `Save` (`internal/manifest/manifest.go`) keep, verbatim, any `[options]`
  key this binary doesn't itself parse and any whole section that is
  neither `[options]` nor `[secrets]`, so a committed `[options]` /
  `global = false` survives a later `cpass manifest add` or `cpass global`
  run by any binary at or above this version. **The disclosed exception**: a
  `cpass` binary built before this feature existed has no notion that
  `[options]` exists at all, and its own `Save` regenerates the whole file
  from only what it parsed — so running that older binary against a
  Manifest that already opted out, and having it write the file again,
  silently drops the opt-out on that Save.

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
   current limitation of the default unlock model, not a hidden one — an
   opt-in that removes it exists (`--touch-id`, a special build only,
   never the default) and is documented in full below.
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

## Opting into Touch ID / user-presence Keychain protection (CLA-23)

Everything in point 2 above is what `cpass` does by **default**, in every
release binary, unaffected by anything on this page: no reader change, no
new dependency, no new prompt. This section documents a separate, opt-in
capability — a real user has to ask for it twice (once at build time, once
per Vault) before anything about their Keychain item changes.

**What it needs, and why it doesn't ship by default.** Requiring Touch ID
or the device passcode to read a Keychain item is a Security-framework
capability (`SecAccessControlCreateWithFlags` with
`kSecAccessControlUserPresence`, applied via `SecItemAdd`) that the
`security` command-line tool has no flag for — reaching it needs cgo, which
links the Security framework directly. ADR-0007 and CLAUDE.md commit
`cpass` to building as a single, portable, `CGO_ENABLED=0` binary for every
release and every CI run, and that does not change: this capability lives
entirely behind a `touchid` Go build tag (`internal/broker/touchid_darwin.go`,
guarded `//go:build darwin && touchid && cgo`) that is never part of an
ordinary `go build ./cmd/cpass` — only `go build -tags touchid ./cmd/cpass`
compiles it in, and only on darwin with cgo enabled. Every other build
configuration — which is every release, and every `go test`/`go vet`/CI
invocation this repository runs — compiles `touchid_stub.go` instead: a
few lines with no cgo and no Security-framework dependency at all, so
nothing about the default build's dependency graph, binary size, or
startup cost changes. `broker.TouchIDAvailable()` reports which one is
compiled in.

**Turning it on.** Two commands opt in, both refusing with a clear
explanation rather than doing something unexpected when Touch ID support
isn't actually available:

- `cpass init --touch-id` — for a brand-new Vault. If this binary has
  Touch ID support compiled in, the Keychain item it creates carries the
  access control from the first paragraph above, and `cpass init` says so.
  If it doesn't (the common case: an ordinary release binary, or a local
  `go build` without `-tags touchid`), it still creates a fully working
  Vault — falling back to the plain, no-ACL item from point 2, exactly as
  if `--touch-id` had not been given — while printing a clear warning that
  Touch ID was requested but unavailable and how to get it. A Vault must
  always be creatable from a single portable binary; a missing optional
  hardening feature must never be the reason `cpass init` fails outright.
- `cpass keychain upgrade --touch-id` — for a Vault that already exists.
  It reads the current key (through the same `broker.UnlockKey()` every
  other command uses, whatever this Vault's unlock source currently is)
  and re-stores it under this Vault's existing Keychain identity, this
  time with the access control. Unlike `init`, it refuses outright
  (exit code 1, nothing changed) rather than falling back when Touch ID
  support is unavailable — there is no new Vault to bring into existence
  here to justify a silent downgrade, only an existing Keychain item to
  leave alone or deliberately upgrade.

Either way, the item this creates is read back by exactly the same,
unchanged `security`-CLI-based reader every `cpass` invocation already
uses (`broker.UnlockKey` → `keychainGet`, keychain_darwin.go) — the code
path this page has always described. **Nothing about that reader
changes.** It is the Keychain itself, not `cpass`, that then prompts for
Touch ID or the device passcode the next time anything reads that item —
`cpass ls`, `cpass run`, the next `cpass keychain upgrade`, or literally
`security find-generic-password -w` typed by hand — because the access
control is a property the OS enforces on the item for any reader, not
logic `cpass` applies itself.

**The one real deployment requirement this surfaces: code signing.**
macOS only enforces `kSecAccessControlUserPresence` on an item stored in
the modern Data Protection Keychain (the default `SecItemAdd` target on
every supported macOS version) — not on the legacy, file-based keychain,
which was confirmed, non-interactively, to accept a `SecAccessControl`
attribute on an item without ever enforcing it (see
`internal/broker/touchid_darwin_test.go`'s package doc comment for exactly
how). Creating an *access-controlled* item in the Data Protection
Keychain, in turn, requires the calling binary to be code-signed with a
`keychain-access-groups` entitlement matching a real, Apple-issued Team
ID; a plain, unsigned, or ad hoc-signed binary — which is what a local
`go build -tags touchid ./cmd/cpass` produces — gets refused outright by
the OS (`SecItemAdd` returns `errSecMissingEntitlement`, OSStatus
`-34018`), and `cpass` surfaces that as a specific, actionable error
naming the requirement rather than a bare OSStatus number. **This is not
an additional requirement `cpass` invents** — a real release binary
already needs a Developer ID signature (and, for un-sandboxed
distribution, notarization) to avoid a Gatekeeper warning on first launch;
adding a `keychain-access-groups` entitlement to that existing signing
step is the only extra piece. A minimal entitlements file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array>
        <string>$(AppIdentifierPrefix)com.claudepass.cpass</string>
    </array>
</dict>
</plist>
```

```sh
go build -tags touchid -o cpass ./cmd/cpass
codesign --force --options runtime \
  --sign "Developer ID Application: <Org> (<TEAMID>)" \
  --entitlements entitlements.plist \
  cpass
```

Until a binary is signed this way, `--touch-id` on either command above
behaves exactly as if this binary had no Touch ID support compiled in at
all (`cpass init --touch-id` falls back with a warning; `cpass keychain
upgrade --touch-id` refuses) — the signing requirement fails closed to the
existing, unhardened-but-working behaviour, never open to an item that
looks protected but silently isn't.

**What was verified for CLA-23, and what could not be, here.** This was
built and checked on a Mac with the full Xcode toolchain installed
(`xcode-select -p` resolves), so the `touchid`-tagged code was compiled
and exercised, not just written:

- `go build -tags touchid ./...` succeeds. `go vet -tags touchid
  ./internal/broker/...` does **not** come back clean: it flags one line,
  `internal/broker/touchid_darwin.go:47:53: possible misuse of
  unsafe.Pointer`, on `cfPtr`'s `unsafe.Pointer(uintptr(x))` conversion.
  That finding is a false positive for this exact pattern, not a bug —
  see `cfPtr`'s own doc comment in `touchid_darwin.go` for the full
  argument, in short: cgo represents every Objective-C-bridged CF opaque
  type this file touches (`CFTypeRef`, `CFStringRef`, `CFDictionaryRef`,
  `SecAccessControlRef`, and friends) as a plain `uintptr` rather than a
  Go pointer type, deliberately, so the garbage collector never mistakes
  a Core Foundation object address for a Go heap pointer; bridging one
  back to `unsafe.Pointer` to hand it to `CFDictionaryCreate` is the
  intended, necessary way to call these APIs from cgo, not arithmetic on
  a Go-managed allocation — the distinction `go vet`'s unsafeptr
  heuristic cannot make, so it fires on sight regardless. This finding
  does not gate anything: the project's actual quality bar (`go vet -tags
  e2e ./...`, `golangci-lint run`) never runs against the `touchid` tag —
  `.golangci.yml` pins `build-tags` to `e2e` only — so it never reaches
  CI or a release build; it is called out here, correctly, rather than
  claimed as a clean pass that does not occur.
- `internal/broker/touchid_darwin_test.go` (`go test -tags touchid
  ./internal/broker/ -run TestTouchIDUserPresence -v`) mechanically proves
  the access-control mechanism itself — see that file's doc comment —
  entirely non-interactively, using `kSecUseAuthenticationUISkip` to prove
  enforcement without ever displaying the real prompt.
- What it could not prove, on this machine, and why: `go test`'s own
  output binary is unsigned, so even `SecItemAdd` of the access-controlled
  item is refused by the OS before Touch ID ever enters the picture (see
  the code-signing paragraph above) — the test detects exactly that
  condition and skips with an explanation rather than failing or
  papering over it. Signing a build the way the paragraph above describes
  requires an Apple Developer Program Team ID and certificate, which this
  environment does not have and which only a human on the ClaudePass team
  can provide. Completing the check from there — confirming the real
  Touch ID / password prompt actually appears on `cpass ls` after `cpass
  init --touch-id`, and that Cancel leaves the Vault locked — additionally
  needs a human physically present at that signed build's keyboard, for
  the same reason no automated test in this repository is allowed to
  trigger that prompt (see the constraint carried forward from CLA-8).
- One specific link in the chain was confirmed only by inference, not
  direct measurement, for the same reason: that `security find-generic-password`
  (`keychain_darwin.go`'s unchanged reader) correctly locates and decodes
  an access-controlled item in the Data Protection Keychain specifically.
  What was measured directly is that it does so for a **plain** item
  stored there, and that it locates an **access-controlled** item stored
  in the legacy keychain (metadata only, no `-w`, so no prompt) — creating
  an access-controlled item in the Data Protection Keychain itself needs
  the signed binary this environment cannot produce. `security` is an
  Apple-signed system binary already entitled for ordinary keychain
  access, and Apple's own documentation describes it operating against
  the Data Protection Keychain by default on current macOS, so this is
  expected to hold — the same signed-build manual check above closes this
  gap too, and is the way to confirm it directly.

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
`$(...)`, backticks, a `shell -c '...'` inside it, a shell's own
script-by-path or heredoc body, up to 8 levels — see `docs/THREATS.md`
for exactly what a shell invocation's argument shape does and does not
make statically inspectable, and why an unresolvable shape refuses
rather than runs unchecked):

- would read a Secret-bearing file directly — matched by basename against
  `.env*`, `*.pem`, `id_rsa*`, `*.key`, `credentials*.json`, `.netrc`,
  `.npmrc`, except a conventionally non-secret counterpart of one
  (`*.pub`, `.env.example`, `.env.sample`, `.env.template`, `.env.dist` —
  CLA-65: neither a public key nor a template dotenv was ever meant to be
  Vaulted, so refusing one is a dead end, not a protection) — via a
  reader program (`cat`, `less`, `more`, `head`, `tail`, `base64`, `xxd`,
  `od`, `strings`, `hexdump`, `bat`, `tee`, `cp`, `nl`, `tac`, `rev`,
  `sort`, `uniq`, `cut`, `awk`, `sed`, `grep`, `jq`, `yq`, `dd`,
  `install`, `rsync`, `scp`) or a shell `source`/`.` builtin;
- references a live file-Binding's run-directory path by literal path —
  the same `$CPASS_HOME/run` root `cpass run` itself protects (CLA-63);
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

The shell-string tokenizer behind all of this (`internal/policy/split.go`,
shared by `EvaluateHook` and `Evaluate` alike, so every fix here applies to
both) also recognizes: shell reserved words (`if`/`then`/`elif`/`else`/
`fi`/`while`/`until`/`do`/`done`/`for`/`in`/`case`/`esac`/`select`) as
starting a fresh command, exactly like `;`/`&&`/`||` already do, rather
than becoming a bogus program literally named `if`/`then`/etc. — so `if
cat .env; then true; fi` still has `cat .env` checked as the real command
it is (2026-09-22 audit round 2); ANSI-C (`$'...'`) and locale (`$"..."`)
quoting, so `cat $'.env'` still names `.env`; and single-level,
non-nested brace expansion (`{a,b,c}`, `{n..m}`, `{a..z}`), so `cat
.{env,bashrc}` presents `.env` and `.bashrc` as separately checkable
words. See `docs/THREATS.md`'s "Known leak paths" item 11 for the
narrower edges this round's own fixes leave disclosed (a command
substitution or array expansion naming the program dynamically, a nested
or repeated brace span, a reader's file argument arriving over a pipe
rather than as literal text).

**Scope note**: the secret-file-glob and raw-literal checks above are the
same rule in `EvaluateHook` and the evaluator `cpass run` and the MCP
server use directly (`Evaluate`, see below) — CLA-38 folded them into the
shared evaluator. Two narrow differences remain: only the hook judges
`cpass add`'s own inline-value usage, since only it inspects a raw Bash
command line before `cpass` has parsed anything and neither `cpass run`
nor the MCP server has a `cpass add` invocation to wrap; and the hook's
raw-literal scan covers a command's entire text, including its own
program path, while `Evaluate` deliberately excludes argv[0] from that
scan (see the next section) since a real executable path routinely reads
as high-entropy without being a Secret. See `docs/THREATS.md` for the full
detail.

## What `cpass run` does to the child and its output

1. Resolves every requested Handle to a value via the Broker: explicit
   `--with handle[:VAR]` repeats when given, or else the Global Manifest's
   Handles layered under the nearest ancestor `.claudepass.toml` Manifest's
   own declarations when `--with` is omitted — see the Global Manifest
   section above for the reachability rule, the two opt-outs, and the
   skip-vs-fail and collision rules that govern this step.
2. Unless `--unsafe-allow` is given (refused outright without a terminal —
   an Agent invoking `cpass run` itself can never set it), evaluates
   `policy.Evaluate` against the command's argv: it refuses the
   environment-dump patterns above; any argument that literally names the
   path of this invocation's own file-Binding temp directory (see next
   point) passed to a reader program — including a relative argument
   resolved against the directory the command actually runs in (this
   process's own `os.Getwd()` for `cpass run`, or a caller-given `cwd` for
   the MCP server — see below — since its own working directory never
   follows the Agent's), or against a literal `cd DIR` seen earlier in the
   same shell string (2026-09-22 audit round 2); any argument naming a
   Secret-bearing file by the same basename glob the PreToolUse hook
   matches (`.env*`, `*.pem`, `id_rsa*`, `*.key`, `credentials*.json`,
   `.netrc`, `.npmrc`, with the same non-secret-counterpart exclusions —
   see above), passed to the same reader programs — anywhere in the
   command, not only as the program actually invoked, so a reader behind
   a wrapper this package doesn't enumerate (`find . -exec cat .env \;`)
   is still caught the same way the hook's own per-word scan already
   catches it (2026-09-22 audit round 2 closed this `Evaluate`/
   `EvaluateHook` parity gap) — or a shell `source`/`.` builtin; a bound
   or tainted variable given to a reader with no matching file operand —
   a here-string (`cat <<< $STRIPE_LIVE`) is the live shape, since a
   reader given no real file argument is functionally "cat used as echo"
   (2026-09-22 audit round 2); a whole variable reference naming the
   command itself (`x='cat .env'; $x`) when that variable was earlier
   assigned a plain string literal in the same shell string, resolved and
   re-evaluated the same way `eval`'s argument already is (2026-09-22
   audit round 2 — a command substitution or array expansion naming the
   program dynamically is not resolved this way, since that needs the
   substitution's actual runtime output; see `docs/THREATS.md` item 11);
   and a raw Secret-shaped literal (the same detector Intercept and the
   hook use) anywhere in the command's arguments — but not in argv[0], the
   program itself, since a Secret value is never the thing being executed
   and a real executable path can otherwise read as high-entropy without
   being one.
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

**Always pass `cwd` to the MCP `run_with_secrets` tool.** The MCP server is
one long-lived process for the whole session; its own working directory
never follows the Agent's, and that directory is exactly what
`manifest.Refs` searches from to find a Manifest — and, through it, any
Global Manifest Handles — at all. Called with no `cwd`, the tool still runs
the command, against whatever Manifest (if any) sits above wherever the
server process happened to start, and adds one warning to the result: "cpass:
no cwd given, so the Manifest was located from this MCP server's own working
directory, not yours; pass cwd to be sure which project's Handles (and
Global Handles) are injected." The same `cwd` is also what Command Policy
resolves a relative reader argument against (`policy.Input.Cwd`, above) —
without it, that resolution falls back to the server's own working
directory too, which can equally be the wrong one for a relative-path
protected-directory check.

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

## No telemetry

**The only network call the `cpass` binary ever makes, in any command, at
any point, is none.** `cmd/cpass`, `internal/cli`, `internal/vault`,
`internal/broker`, `internal/run`, `internal/redact`, `internal/policy`,
`internal/manifest`, `internal/detect`, `internal/dotenv`, `internal/mcp`,
and `internal/integrate` import no `net/http` and open no outbound network
connection anywhere — the only networking primitive in the whole binary is
`internal/broker`'s own Unix domain socket to the local Broker process
(loopback-only, machine-local, never a network address). One thing outside
the `cpass` binary itself does touch the network, and it isn't telemetry
either: `install.sh` fetches a release archive and its `checksums.txt` over
HTTPS from `claudepass.com` (verifying the archive's sha256 before
installing it) to install `cpass` in the first place.

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
| `.claudepass.toml` (repo root, found by walking up from the current directory) | The Manifest: which Handles this project needs and their Bindings. Contains no values; meant to be committed. | `0644` |
| `$CPASS_HOME/global.toml` | The Global Manifest: the same TOML subset as a project Manifest (`.claudepass.toml`), declaring the Handles this machine gets in every project it reaches. Contains no values. | `0644` (dir `0700`, created like the Vault's own directory if missing) |
| `<skills-dir>/claudepass/` (default `~/.claude/skills/claudepass`, overridable with `cpass integrate claude --path`) | The installed Claude Code plugin: `.claude-plugin/plugin.json`, `hooks/hooks.json`, `skills/claudepass/SKILL.md`. | `0644` (dirs `0755`) |
| `AGENTS.md` (repo root, or `cpass integrate codex --path`) | A delimited, idempotent section `cpass integrate codex` writes teaching Codex the CLI. Everything outside the `<!-- cpass:begin/end -->` markers is preserved untouched. | `0644` |

## Intercept precision (v0.1.4)

The prompt Intercept hook and Command Policy block only on high-confidence Secrets: known provider-key prefixes (Stripe, GitHub, AWS, OpenAI, Anthropic, Google, Slack, ...) and PEM private-key blocks. They do NOT block on generic entropy, because ordinary agent traffic is full of high-entropy non-secrets (tool-call ids, UUIDs, git SHAs, base64 blobs, automated task notifications) and a false block stops the user's work. The honest trade: an unprefixed pasted secret is not auto-caught by Intercept; store it with `cpass add`, after which Redaction protects it. `detect.Scan` still offers the entropy heuristic for advisory, non-blocking uses.
