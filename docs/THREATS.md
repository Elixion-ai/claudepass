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
  base: running as your own user, and — because ClaudePass is free and
  open source (see [ADR-0011](adr/0011-free-and-open-source.md)) — code
  you can read and audit yourself rather than take on faith, which this
  threat model assumes behaves as `docs/SECURITY.md` describes.

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
- **The Global Manifest's reachability gate**: an unreviewed nested tree — a
  dependency cloned into `vendor/`, a scratch checkout under `tmp/` — cannot
  silently receive the machine's ambient Global Handles just because `cpass
  run` would otherwise inject them by default; crossing that tree's own
  `.git` on the way up withholds them (see `docs/SECURITY.md`'s Global
  Manifest section).
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
  share a machine and a Vault, they share every Secret in it. The Global
  Manifest's reachability rule (see
  [ADR-0012](adr/0012-global-manifest-reachability.md)) does not change any
  of this: it is a directory boundary on one ambient convenience layer, not
  an authorization system. Every Handle a project's own Manifest declares,
  and every Handle a command explicitly asks for (`--with`, the MCP
  `handles` list), is still available to anyone who can run `cpass` as the
  Vault's owning user, exactly as this bullet already states.
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
  servers, because there are none it talks to.

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
   three alignments), base32 (standard alphabet, padded and unpadded, five
   alignments), hex (both lower- and upper-case), percent-, and
   JSON-escaping are covered — see `docs/SECURITY.md`'s Redaction section
   for the exact list. A command that transforms a value some other way
   before printing it — its own bespoke encoding, compression, encryption,
   a Caesar/rot13-style shift, re-chunking with separators spliced
   mid-value — passes through unrecognised.
3. **Anything not written to the wrapped command's own stdout/stderr.**
   Redaction only ever sees the two pipes `cpass run`/`capture` own. A
   value the child writes to a file, a Unix socket, another process's
   stdin, or ships off to a log/metrics service of its own is invisible to
   it — closing that path is Command Policy's job (refusing the well-known
   ways a command tries to read a Secret back out for exactly this
   purpose), and Command Policy is necessarily a list of known patterns,
   not a sandbox.
4. **A value split across stdout and stderr.** stdout and stderr each get
   their own `redact.Writer`, with independent automaton state
   (`internal/run.Run` — see `docs/SECURITY.md`'s Redaction section); a
   value whose bytes are split across the two streams — half printed to
   one, half to the other — is never matched on either stream, because
   neither Writer's sliding window ever sees the whole value; both halves
   print unredacted. A real fix means sharing match state across both
   streams' concurrently written bytes, which trades this gap for a new
   one of its own — buffering one stream while waiting to see whether the
   other completes a match risks over-redaction and race conditions
   between the two streams' writers — so this is recorded here as a
   disclosed limitation rather than attempted in this pass.
5. **Three narrow, deliberate differences remain between the PreToolUse
   hook and the other two surfaces** (closed for the file-glob and
   raw-literal rules themselves by CLA-38 — see below). `cpass policy
   --hook` alone refuses `cpass add <handle> <value>` (an inline second
   positional argument defeats the terminal gate `cpass add`'s own
   hidden prompt enforces): there is no equivalent check in `cpass run`
   or the MCP server, since only the hook inspects a raw Bash command
   line before `cpass` has parsed anything, and `cpass add` is not a
   command either of them wraps. Separately, the hook's raw-literal scan
   (`internal/detect`) covers a command's entire text, including its
   program's own path, while the shared `Evaluate` (used by `cpass run`,
   the MCP server's `run_with_secrets`/`capture` tools, and the hook
   itself) deliberately excludes argv[0] from that scan: a real
   executable path — a build artifact under a randomly named temp
   directory, a versioned tool under a hashed store path — routinely
   reads as high-entropy to the same heuristic without being a Secret,
   and a Secret value is never itself the program being executed, so
   nothing is actually missed by excluding it. A third difference,
   narrower still and added by CLA-102: `cpass policy --hook` alone
   allows `printenv NAME` when every `NAME` given is on a small, fixed
   allowlist of well-known, non-secret variables (`PATH`, `HOME`, `LANG`,
   `GOPATH`, ... — see `docs/SECURITY.md`'s full list). This exists
   because the hook has no Bound-variable knowledge at all — unlike
   `cpass run` and the MCP server, which run with real Bound Secret
   values already sitting in the same process environment as `PATH`/
   `HOME` — so it would otherwise refuse even an utterly ordinary
   `printenv PATH` lookup; those two other surfaces deliberately keep the
   stricter, allowlist-free refusal, since assuming a name is safe there
   just because it looks like an ordinary one is a different, higher-cost
   bet once real Secret values are actually present. A fourth, sibling
   difference, added by CLA-103: `cpass policy --hook` alone also allows
   `set -x`/`set -o xtrace`/a combined short-flag group containing `x`
   (`-euxo pipefail`) — the same "the hook has no Bound-variable
   knowledge at all" reasoning applies just as directly to tracing as it
   does to `printenv`: nothing is ever Bound yet at hook-check time, so
   there is no Secret value for a trace line to echo in the first place,
   only the Agent's own already-visible commands and its own process
   environment. `cpass run` and the MCP server again deliberately keep
   the stricter, allowlist-free refusal, since real execution DOES have
   real Bound Secret values sitting in the same process a traced
   script's own `+ echo $STRIPE_LIVE`-style line would echo. A bare
   `set` with no arguments is a different rule entirely (it prints every
   variable unconditionally, which has nothing to do with tracing) and
   is unaffected — it stays refused on all three surfaces. Before CLA-38, the
   secret-file-glob rule (`.env*`, `*.pem`, `id_rsa*`, `*.key`,
   `credentials*.json`, `.netrc`, `.npmrc`) and the raw-literal rule
   applied only to the hook: `cpass run -- cat .env` and an MCP
   `run_with_secrets` call with `command: ["cat", ".env"]` were **not**
   refused, even though the functionally identical Bash tool call inside
   Claude Code was — and `internal/policy`'s package doc comment
   overclaimed "the same evaluator serves `cpass run`, the ... hook, and
   the MCP server, so behaviour is identical everywhere." Both rules now
   live in the shared `Evaluate`, so all three surfaces refuse the same
   file reads and raw literals; the package doc comment states precisely
   the three differences left above.
6. **The `!!` Intercept bypass is a deliberate escape hatch, not a filter
   that got weaker.** It exists so a false positive never blocks real
   work; using it on an actual Secret sends that value into the Agent's
   Context on purpose. Marking it Exposed afterward is the intended
   remediation (rotate it), not a mechanism that stops the exposure from
   happening.
7. **Detection can miss or over-trigger.** `internal/detect`'s prefix list,
   PEM matcher, and entropy heuristic are exactly that — a heuristic. A
   real Secret shaped unlike anything on the prefix list and not
   high-entropy enough to clear the threshold is neither Intercepted nor
   caught by Command Policy's raw-literal check; conversely an ordinary
   high-entropy identifier can occasionally be flagged when it isn't one.
8. **The macOS Keychain item and the Broker's Unix socket have no access
   control beyond the ordinary OS user boundary** (detailed in
   `docs/SECURITY.md`). This is the "compromise of the account" scope
   above made concrete: it's the specific, practical way an already-unlocked
   Vault's key would reach a second process running as the same user.
9. **The human-terminal gate is `isatty()`, nothing stronger.** `cpass
   add`, `cpass capture`'s prompts, and `--unsafe-allow` all distinguish "a
   human is here" from "an Agent is asking" by whether stdin is a terminal.
   A full pty allocated by something other than an interactive shell would
   satisfy that check; a Unix process has no stronger signal available to
   it that a human, specifically, is on the other end.
10. **The Global Manifest's nested-repository gate keys off a directory
    having its own `.git`, nothing more.** `manifest.globalReaches` (see
    `docs/SECURITY.md`'s Global Manifest section, and
    [ADR-0012](adr/0012-global-manifest-reachability.md)) treats crossing a
    `.git` on the way up to a project's Manifest as the boundary of an
    unreviewed nested tree. A tree that carries no `.git` at all — an
    extracted tarball, a directory copied rather than cloned — is
    indistinguishable from an ordinary subdirectory of the onboarded
    project, and so still receives Global Handles. This is the same kind of
    honest, disclosed limitation as 1-9 above, not a defect the gate was
    supposed to close and missed: it is, precisely, a `.git`-presence check,
    stated here as exactly that and nothing stronger.
11. **The stale run-dir sweep's time-based fallback is a bound, not a
    guarantee, in either direction.** `sweepStale` (`internal/run/files.go`)
    decides whether to shred an old `cpass run` file-Binding directory using
    `syscall.Kill(pid, 0)` against the `.pid` it recorded; if the `cpass`
    process that owned it was `SIGKILL`ed and the OS later recycles that pid
    for an unrelated process before the next sweep, PID liveness alone would
    read "alive" forever and never catch it, leaving a plaintext Secret file
    on disk indefinitely. `staleRunDirMaxAge` (three times
    `broker.DefaultIdleTimeout`, currently 12h) closes that gap by shredding
    any run dir older than the bound regardless of what its `.pid` says —
    but the bound cuts both ways: a directory that *is* a genuine PID reuse
    can still sit on disk, plaintext Secret file and all, for up to that
    long before the fallback catches it, not immediately; and a single
    `cpass run` invocation that legitimately wraps one command for longer
    than the bound (an unattended dev server or watcher left running past
    12h straight, the exact long-running case PRD story #18's
    no-buffering-delay guarantee exists for) would have its own,
    still-in-use file-Binding directory shredded out from under it. Neither
    side of this trade has a sharper fix without either trusting a reused
    pid forever (today's bug) or tracking process identity more precisely
    than a bare pid, which no supported platform here gives `cpass` a
    portable way to do.
12. **The broad-root warning (`manifest.BroadRoot`) only recognises the
    filesystem root and the caller's own home directory, nothing wider.**
    A Manifest planted at either turns every Global Handle this machine
    ever declares into an ambient default for every subdirectory beneath
    it — `cpass manifest init` warns loudly at the moment such a Manifest
    is created, and `manifest.Refs` warns again, on stderr, the first time
    that Manifest actually hands a directory a Global Handle, in case it
    ended up broad some other way (hand-copied, git-cloned straight into
    `$HOME`). Neither warning blocks anything: declaring and consuming
    Global Handles from a broad root both keep working, on purpose, since
    ClaudePass has no way to know whether that is actually what someone
    wants. Not covered: a merely-large ancestor short of the two exact
    cases above (`/Users`, `/home`, a mounted volume root), and a
    symlinked or bind-mounted path to either that `filepath.EvalSymlinks`
    cannot resolve. The same honest shape as 10 above — a named, narrow
    check, stated as exactly that.
13. **A shell invocation's argument shape decides whether Command Policy
    can statically inspect what it runs, and the default for anything it
    cannot is refuse, not allow** (`shellCommandString`, CLA-62). What it
    inspects, precisely:
    - `<shell> -c STRING`, with any combination of `-e -u -x -l -i -n -v
      -p -s -a -b -f -h -k -m -t`, `-o`/`-O`/`+o`/`+O <arg>`, or
      `--noprofile --norc --login --posix` before it — the STRING is
      evaluated exactly like the shell string this package already parses
      everywhere else, up to a nesting depth of 8 (`maxDepth`) — past
      which this package now refuses rather than silently allowing an
      unevaluated command through (2026-09-23 audit; previously it
      returned nil past this depth, a real gap between this claim and
      what actually happened, since nothing that deep is genuinely
      evaluated at all — it is refused instead, which is what keeps this
      a non-issue for the property that matters: no command can evade
      every rule above by nesting deep enough). This holds for
      every ordering a real shell accepts, combined short-flag groups
      included: `-co`, `-oc`, `+co`, and `+oc` all consume exactly one
      word for `o`/`O` (wherever it falls in the group) and defer `c`'s
      own word until the entire run of option tokens ends — matching a
      real shell's own getopt-style parsing, live-verified against
      `/bin/bash` — not "the word immediately after wherever the letter
      `c` happens to sit," which is what `shellCommandString`'s combined-
      group branch actually did before a review fix (CLA-62): `-co
      pipefail 'cat .env'` checked the harmless word `pipefail` as if it
      were the `-c` string, so the real command, `cat .env`, was never
      evaluated at all — a silent, full bypass reachable with either
      letter order, either sign. See
      `TestShellInvocationCombinedOptionOrdering` (and its hook/e2e
      counterparts) for the exact shapes now covered.
    - `<shell> script-path [args...]` (script-by-path) — when script-path
      names a readable regular file no larger than 1 MiB, its own content
      is read and statically evaluated the same way, so `cpass run --
      bash script.sh` keeps working for a legitimate script. This is why
      `#comment` lines (including a shebang) are recognised and skipped:
      without that, a script's own `#!/bin/sh` line would misparse as a
      bare invocation of `sh` and refuse the whole script.
    - **Write-then-run (CLA-103): when script-path is not (yet) a
      readable file on disk, a heredoc-to-file write recorded earlier in
      the SAME wrapped command is tried before falling back to refuse.**
      A single Bash tool call, or a single `cpass run -- bash -c '...'`
      invocation, routinely both writes a script and immediately runs it
      (`cat > script.sh <<'EOF' ... EOF; bash script.sh`) — and this
      whole check runs *before* either the write or the run has actually
      executed, so `os.Stat` genuinely finds nothing there yet, even
      though the invocation is completely ordinary. `cat > PATH
      <<DELIM`, `cat <<DELIM > PATH` (splitCommands always appends the
      heredoc word last regardless of which came first on the line, so
      both spellings tokenize identically), `cat >> PATH <<DELIM`
      (append — prepending whatever this SAME shell string already
      wrote to that identical path, checked before falling back to a
      real, best-effort on-disk read, so an earlier write's own content
      is never silently dropped from what gets checked), and `tee [-a]
      PATH <<DELIM` are the four exact shapes recognised
      (`heredocToFileWrite`, `internal/policy/policy.go`) — a real read
      argument alongside the redirect, more than one candidate target
      word, or any other program or flag is not this shape and falls
      through to the ordinary refusal unchanged. The identical literal
      path (resolved through the same plain-string-variable tracking a
      script path already gets, `G=script.sh; bash $G`) must name the
      SAME word later in the SAME command — a `cd` anywhere between the
      write and the run invalidates every pending write-then-run
      candidate entirely, a deliberately blanket/conservative safety
      valve rather than reasoning precisely about which entries a
      particular `cd` would or wouldn't affect. This recognizes `cd`
      reached through a `command`/`builtin` prefix (`command cd
      ...`/`builtin cd ...`) exactly like a bare `cd` (`skipCommandPrefix`,
      `internal/policy/hook.go`) — a review round of this same ticket
      caught the first pass comparing only the bare word, which let
      `command cd`/`builtin cd` silently leave a stale write-then-run
      entry pointing at a directory the command never actually ran in,
      resolving a later same-named script-by-path invocation to the
      wrong (tracked, benign) body instead of the real, differently-owned
      file actually sitting at the new directory — a genuine bypass of
      this whole safety valve, not merely a missed refusal. Recorded paths
      are normalized (`t.sh`, `./t.sh` and `x/../t.sh` are one entry),
      so a rewrite spelled differently cannot slip past a recorded
      benign body, and a body this command writes takes priority over
      an older copy already on disk, since the write runs first. A script whose written
      body itself reads a Secret file is still refused exactly as if
      that content had come from a real file on disk, since the
      resolved content re-enters the same recursive evaluation every
      other script-by-path/heredoc body already goes through.
    - **A LATER write to the identical literal path, through any shape
      other than the four `heredocToFileWrite` shapes above, invalidates
      the tracked entry (CLA-103 round-2 review — a genuine regression
      vs. main, not merely a missed refusal).** The `cd` safety valve just
      above only ever invalidated on a `cd`; nothing invalidated a tracked
      entry when a LATER command in the SAME shell string wrote to the
      identical path some other way. Live-reproduced: `cat > t.sh <<'EOF'
      ... EOF; echo 'echo REAL_EXECUTION_RAN_UNCHECKED_SCRIPT' > t.sh;
      bash t.sh` was allowed and the second, never-inspected write's real
      content genuinely ran — proof only real, unvetted execution could
      produce. `invalidateOverwrittenWrites` (`internal/policy/policy.go`,
      shared by `ev.simple` and `hookWalk`) now resolves every `>`/`>>`
      output-redirection target word in a simple command — tagged
      generically by `splitCommands` on ANY program via
      `word.outRedirTarget`, not only inside `heredocToFileWrite`'s own
      narrow cat/tee-with-heredoc match — and deletes that specific
      tracked entry unless it is exactly the path `heredocToFileWrite`
      itself just recorded new content for from this same command. Beyond redirects, the rule is closed rather than a list of writers
      (review round 3 found a new writer shape every round: `curl -o`,
      `dd of=`, `sed -i`, an archive extraction that never names the
      script): between the write and the run, a command keeps the
      recorded body only if it is a pure assignment, a
      `contentPreserving` program (`chmod`, `echo`, `ls`, `mkdir`,
      `test`, ...), or the shell invocation that runs a recorded path
      itself; any other program clears every recorded write, and so
      does a redirect whose target is not a plain literal (`>
      $(...)`, a glob). This is the ADR-0013 calibration, not a gap
      chased shape by shape: an on-disk script already had the same
      overwrite-before-run exposure across two calls (write it in one,
      `curl -o x.sh ... && bash x.sh` in the next), so write-then-run in
      one call adds no capability, and a path computed at run time
      stays in item 16's residual class. Either way the later script-by-path
      read then fails closed on the ordinary "invocation shape can't be
      checked statically" refusal — this does not, and cannot, inspect
      the later write's own real content, since by construction that
      content was never tracked in a shape this package recognises.
    - A heredoc (`<<[-]DELIM ... DELIM`) attached to a shell — `sh
      <<'EOF'` or `bash <<EOF`, quoted delimiter or not — has its body
      evaluated as the script it is, since the target shell runs it as
      commands either way, **but only when the invocation has no `-c
      STRING` or script-path argument of its own.** When it does, that's
      what a real shell actually executes — the heredoc is just stdin
      data for the invocation, and the -c/script content is what's
      checked, exactly like the no-heredoc case above; the heredoc
      fallback exists only for the genuinely bare `sh <<EOF` shape,
      where the shell would otherwise read its script from stdin
      interactively. (CLA-62's initial heredoc support checked the heredoc
      first and evaluated it instead of a real -c/script-path argument
      alongside it — a silent bypass fixed in review: see the
      `TestShellInvocationHeredoc`/`TestEvaluateHookShellInvocationShapes`
      "alongside a benign heredoc" cases.)
    - A heredoc attached to **anything else** — `cat <<EOF`, `python3 -
      <<EOF`, `wc -l <<EOF` — is **not** simply left alone as inert data,
      and an earlier version of this page was wrong to say so (CLA-61
      review). Whether its body is inert depends on its delimiter, exactly
      as it does for a real shell: a **quoted** delimiter (`<<'EOF'` or
      `<<"EOF"`) is genuinely inert — the body reaches the program's stdin
      byte-for-byte, never expanded, so `cat <<'EOF'` followed by
      `$(cat .env)` prints that literal seven-character-plus text and
      never touches `.env`. An **unquoted** delimiter's body, though, is
      expanded by the real shell — command substitutions, backticks, and
      parameter (variable) expansions — exactly like a double-quoted
      string, *before* it is ever handed to the reading program's stdin:
      `cat <<EOF` followed by `$(cat .env)` already ran `cat .env` and
      already handed its output to the outer `cat`'s stdin before that
      outer `cat` ever started, and a bound variable reference in such a
      body (`cat <<EOF` / `$STRIPE_LIVE` / `EOF`) resolves to the Secret's
      real value there exactly as `echo $STRIPE_LIVE` would, since a
      reading program given no file operand generally does nothing but
      echo its stdin back out. Command Policy evaluates both halves of
      this for an unquoted delimiter — command/backtick substitutions
      (populated as the word's own `subs`, walked by the same "command
      substitutions are commands too" step every other word's `subs`
      already goes through) and a bound/tainted parameter reference
      (`ev.simple`'s own heredoc-reveal check) — regardless of which
      program the heredoc is attached to, not only a shell. See
      `TestShellInvocationHeredocUnquotedExpansionAnyProgram`,
      `TestSplitCommandsUnquotedHeredocSubs`, and their hook/e2e
      counterparts for the exact shapes now covered, quoted and unquoted
      side by side.
    - What it does **not** inspect, and so refuses rather than guesses at:
      an unrecognised option; `-o`/`-c` with no value following it; a
      script path that is not a readable regular file under 1 MiB (an
      executable run directly by path, a missing file, a directory, a
      symlink to something else, an oversized file); a bare shell
      invocation with nothing statically visible (`sh` alone, `sh -s`,
      or one reading real, non-heredoc piped stdin); and a here-string's
      own `$(...)`/backtick command substitutions once it becomes an
      ordinary checkable word (CLA-61) are evaluated, but its surrounding
      plain text is not scanned for reader programs — it is inline data,
      not a script. None of this is a leak path: every one of these
      shapes is a refusal, not a silent allow.
14. **Three narrower shapes closed this round leave their own, smaller
    disclosed edges** (2026-09-22 audit, stream `policy`, round 2):
    - **A dynamic command name is only resolved back to a real program
      when it is a whole variable reference (`$x`/`${x}`) to a plain
      string literal already assigned in the same shell string** —
      `x='cat .env'; $x` really does execute `cat .env` and is refused the
      same way. A command substitution naming the program (`` `echo
      cat` .env ``, `$(echo cat) .env`) or an array expansion
      (`arr=(cat); ${arr[@]} .env`) needs that substitution's actual
      *runtime output*, which isn't knowable by any static read of the
      command text, so neither is resolved and both still run unchecked
      by this rule specifically (Redaction still catches a value the
      resulting command then echoes back, the same defense-in-depth
      backstop every other gap on this page already relies on). A shell
      function defined and then called (`f(){ cat "$1"; }; f .env`) is
      the same family and is likewise not inlined at its call site.
    - **Brace expansion ({a,b,c}, {n..m}, {a..z}) is single-level and
      non-nested, and only the first `{..}` span in a given word is
      expanded.** A nested span (`{a,{b,c}}`) or a second span later in
      the same word is left as intact literal text rather than being
      truncated — still checked as the one word it already was, just not
      multiplied into the several words a real shell would produce from
      it — matching this package's existing, deliberate rule of refusing
      or under-checking rather than guessing at a shape it cannot fully
      model.
    - **A reader's file argument must appear as literal text in the
      command itself.** `echo .env | xargs cat` — the filename arriving
      over a pipe from another program's own stdout, never sitting in the
      command's text as an argument `cat`/`xargs` is invoked with — is
      invisible to a purely text-based reader: there is no `.env` word
      anywhere in the command line for `matchesSecretFile` to match
      against. This is the same limitation item 3 above already states
      for Redaction's own stdout/stderr-only view, one level up the
      pipeline.

15. **Four narrower shapes closed this round leave their own, smaller
    disclosed edges** (2026-09-22 audit, stream `policy`, round 3):
    - **The `$IFS`/`${IFS}` word-splitting fix treats every unquoted
      reference as a word-splitting boundary unconditionally, without
      modeling IFS's actual runtime value.** This is deliberately the
      conservative direction: whatever IFS was ever reassigned to
      earlier in the same shell string, an unquoted `$IFS`/`${IFS}`
      reference is always treated as if it splits into nothing but
      whitespace, so this can only ever split a word into MORE, smaller
      pieces to check, never fewer. What it does not attempt: a custom,
      non-default `IFS` value relied on through something OTHER than a
      direct `$IFS`/`${IFS}` reference — reassigning `IFS` to a
      punctuation character and then depending on that character's
      field-splitting effect on some OTHER expansion's result. A real
      shell's word-splitting only ever applies to the result of an
      expansion (`$var`, a command substitution, an arithmetic
      expansion) in the first place, never to literal text typed
      directly in the command line, so this narrower shape needs an
      actual expansion vector this package doesn't otherwise resolve to
      a filename (see item 14's dynamic-command-name entry above) — not
      a new gap this fix opens, only one it doesn't happen to also
      close.
    - **The `read`/`mapfile`/`readarray`/`exec`-fd-alias fix's
      descriptor tracking is scoped to one shell string, and records a
      bind regardless of which command it was attached to, not only
      `exec`.** A real shell scopes a plain `cmd N< target` redirection
      (one not on `exec`) to that one command's own execution only; this
      package deliberately does not model that precision, recording the
      bind for any command carrying one, since doing so can only make a
      LATER `<&N` resolve to a path that really was bound to that number
      at some point in the same shell string, never to something
      invented — over-conservative in the safe direction, matching this
      package's existing "refuse/resolve rather than guess" default, not
      a leak.
    - **The `Evaluate` shell-behind-unenumerated-wrapper fix mirrors
      `EvaluateHook`'s own hookWalk exactly, including hookWalk's
      pre-existing lack of a printer exemption for a shell name.**
      Unlike the equivalent reader-name fallback (which exempts
      `echo`/`printf`'s own data arguments), a shell name appearing as a
      mere argument to `echo` — `echo bash -c 'cat .env'`, where `bash`
      is never actually invoked — is still resolved and evaluated as if
      it were, the same way it already was for hookWalk before this
      round. This is an existing, shipped over-refusal this fix
      intentionally left alone, since changing it would itself be a
      fresh `Evaluate`/`EvaluateHook` divergence in the other direction;
      it is disclosed here rather than silently inherited.
    - **The glob-expansion fix is scoped to a shell-string argument to a
      reader/source builtin directly (`ev.simple`), not to one hidden
      behind a wrapper program the per-word fallback resolves (`find .
      -exec cat .en? \;`), and does not replicate a real shell's own
      "hide dotfiles from a pattern with no literal leading dot" rule.**
      The first gap means a glob-shaped filename passed to an
      unenumerated wrapper's own argument list is not currently
      glob-resolved by this package, even though a real shell DOES
      expand it before the wrapper ever starts — the same class item
      11's own wrapper-coverage entry describes, one level removed. The
      second means Go's `filepath.Glob`, unlike a real shell, has no
      notion of hiding a leading dot from a bare `*`/`?` pattern with no
      literal leading dot of its own, so this check can occasionally
      refuse a glob shape (e.g. a bare `*env`) that a real shell would
      not actually expand to a dotfile at all — over-refusal, not
      under-refusal, and so not a leak either way. Also direct argv with
      no shell involved at all (`cpass run -- cat .en?`) is never
      glob-checked, correctly: Go's `os/exec` performs no globbing of
      its own, so the reading program receives the glob pattern's
      literal text and simply fails to find a file by that name — there
      is nothing to leak in that shape to begin with.

16. **Command Policy is a static guardrail, not a decision procedure for
    arbitrary shell (see [ADR-0013](adr/0013-command-policy-is-a-static-guardrail.md))
    — a command can compute what it does at run time in ways no amount of
    precise syntax modeling reaches, and this is the standing, disclosed
    residual class every item above is an instance of, not a defect any
    one of them was supposed to close.** Concretely:
    - **An interpreter's own `-c`/`-e` string is not shell syntax and this
      package does not read it as one.** `python3 -c "open('.env').read()"`,
      `node -e "require('fs').readFileSync('.env')"`, `ruby -e
      "File.read('.env')"` — none of these are `shells`-map members (only
      `sh`/`bash`/`zsh`/`dash`/`ksh`/`fish` are), so their own `-c`/`-e`
      argument is checked only as ordinary argv text (the raw-literal and
      glob/filename rules still apply to it), never parsed as the
      language it's actually written in. A language-specific parser for
      every interpreter an Agent might reach for is not a "cheap, precise
      addition" — it is a second copy of this package per language, which
      is not what a static guardrail can be.
    - **A dynamically constructed string handed to `eval` isn't
      resolved, per item 14's own dynamic-command-name entry — one level
      up, at `eval` itself.** `eval "$(printf '%s' Y2F0IC5lbnY= | base64
      -d)"` decodes and runs `cat .env`, but the text `eval`'s own
      argument statically shows is a `base64 -d` pipeline's output, not
      the command that output happens to spell; this package evaluates
      what a command's own text literally says, not what any program it
      invokes might later produce.
    - **A program that opens a file itself, through an argument shape
      this package has no reason to model as file-like, is invisible to
      the secretFileGlobs checks.** `mytool --config .env` is checked
      only if `mytool` is a name in `readers`/`sourceBuiltins`/`shells` —
      an ordinary CLI tool with its own `--config`/`--input`/`--source`
      flag pointing at a Secret-bearing file is not, and has no reason to
      be: enumerating every third-party tool's own file-taking flag is
      the same unbounded task as the interpreter case above, just per
      tool instead of per language.
    - **An unenumerated wrapper this package's own per-word fallback
      doesn't reach still exists.** `readerWordRefusal`/`hookWalk`'s
      per-word scans catch a reader or shell name appearing at ANY
      position in a flat argv or word list (`find . -exec cat .env \;`,
      `xargs cat .env`, `cpass run -- cat .env`, `docker exec c cat
      .env`, `nsenter ... sh -c '...'`), except for the small, specific
      set of multi-level CLI subcommands that merely share a reader's
      name without behaving like one (`coincidentalReaderSubcommands`,
      `internal/policy/policy.go` — see CLA-101's own entry below), which
      covers the common, genuinely reachable shapes — but a wrapper that
      renames its child process, execs through a compiled helper binary
      with no readable argv text naming the real command, or otherwise
      obscures what it's about to run from the text of the command line
      itself is outside what any text-based scan can see, by
      construction.

    The enforced boundary for this whole residual class is not Command
    Policy — it is Redaction (a value these programs print still gets
    stripped from `cpass run`'s own stdout/stderr, per item 3's stated
    scope) and `cpass import` removing the plaintext Secret file from disk
    once its values are in the Vault (so there is decreasingly often a
    `.env`/`id_rsa`/etc. left on disk for one of these to open in the
    first place). A newly found shape in this class is not a broken
    Command Policy guarantee; it is confirmation of the boundary ADR-0013
    already states. A shape that genuinely IS syntax this package could
    model precisely — a new heredoc form, a redirection this page doesn't
    yet cover — is a different kind of finding, judged the way items 1–12
    above already are: a regression (something this package used to catch
    and now doesn't) is a bug, and a shape it never modeled is a cheap,
    precise addition when the fix is narrow, or a disclosed edge here when
    it isn't.

    This round (2026-09-23 audit) also leaves its own narrower disclosed
    edges: the case-statement pattern-arm fix models `case`/`in`/`;;`/`esac`
    precisely but not bash's `;&`/`;;&` fallthrough operators, which this
    package's tokenizer still treats as plain `;`-separated command
    boundaries — a case arm using either form parses as more separate
    commands than a real shell would run together, which can only ever
    mean MORE separately-checked text, never less, the same conservative
    direction every other under-modeled shape in this document already
    takes.

    **CLA-101 (2026-09-23 audit follow-up)** fixed that same round's own
    disclosed `readerWordRefusal` coincidental-subcommand-match
    over-refusal: a multi-level CLI's own subcommand that merely shares a
    name with a reader utility and does not itself read a local file
    (`aws logs tail ...`, `kubectl cp pod:/x .env` — AWS's `tail`
    streams remote CloudWatch logs, and this `kubectl cp` invocation
    WRITES a local file) is not treated as a reader invocation. CLA-101's
    first version of this fix required a genuine trigger word (a wrapper,
    one of find's own exec-style flags, a bare `xargs`, or `--`)
    immediately before ANY reader-name word — closing the aws/kubectl
    false positive, but, as CLA-101's own follow-up review found (round
    2), also silently dropping detection for every OTHER wrapper program
    this package doesn't happen to enumerate (`docker exec`, `chroot`,
    `strace`, `setsid`, `unshare`, `stdbuf`, and any other passthrough
    shim) — a substantial, undisclosed reduction of this fallback's whole
    reason to exist, not a narrower version of the disclosed trade-off
    below. **CLA-101's review fix (round 2)** replaced that trigger-word
    gate with a small, specific denylist instead
    (`coincidentalReaderSubcommands`/`isCoincidentalReaderSubcommand`,
    `internal/policy/policy.go`): a reader name is caught at ANY word
    position again, exactly as before CLA-101, except for the exact,
    contiguous `{CLI, subcommand path}` pairs on that list (`aws logs
    tail`, `aws s3 cp`, `kubectl cp`, `docker cp`) — restoring detection for every unenumerated-wrapper shape
    without reopening the aws/kubectl false positive. As a side effect,
    this also restores catching a multi-level CLI subcommand that
    genuinely DOES read a local file the way a real reader would (`git
    grep PATTERN .env`), which CLA-101's first version had disclosed
    losing as an unavoidable cost of the trigger-word approach — it isn't
    unavoidable with a denylist instead, and refusing a command that
    really would read the file is correct, not a new false positive. The
    denylist's own `cp` entries stay direction-blind (`kubectl cp
    LOCAL pod:PATH` genuinely reads LOCAL off disk on upload,
    `kubectl cp pod:PATH LOCAL` only writes LOCAL on download, and this
    exemption skips every argument's secretFileGlobs check either way,
    the same edge CLA-101's own trigger-word version already had for
    this shape) — telling those two argument shapes apart precisely
    enough to re-check only the genuinely local one would mean modeling
    each CLI's own copy-argument syntax, the same unbounded per-tool task
    this item already declines generally. Redaction and `cpass import`
    remain the enforced boundary for both disclosed edges.

    **CLA-102 (2026-09-23 audit follow-up)** is not a residual-class item
    on its own — it is the hook-only `printenv` allowlist documented in
    item 5 above — but is noted here too since it is the same kind of
    "narrow the check, disclose what narrowing costs" trade-off: a
    `printenv` call naming only well-known, non-secret variables no
    longer refuses at the hook layer, and the fixed, small allowlist
    (`docs/SECURITY.md`) is itself the disclosed boundary — a name not on
    it stays refused exactly as before, by design, not by omission.

    **CLA-103 (owner report, 2026-09-23)** fixed the false-positive class
    the hook's own `set` rules had been silently accumulating: the
    owner's own Claude Code transcripts on this machine showed the hook
    blocking 40 distinct real commands across 89 transcripts by
    misreading Python's `set(...)` (and other languages'/tools'
    unrelated uses of the bare word "set") as the shell `set` builtin,
    refusing `set -x`/a combined short-flag group containing `x`
    unconditionally even though nothing is ever Bound at the hook layer
    to trace-reveal, and refusing a script written and run in the same
    Bash tool call because the file genuinely wasn't on disk yet at
    check time. The Python/other-language misreading turned out to
    already be fixed by CLA-99/CLA-100/CLA-101's own tokenizer and
    per-word-scan work — an interpreter's own `-c`/`-e` string and a
    heredoc fed to a non-`shells`-map program were already opaque data,
    not re-parsed as shell commands (see item 16's own interpreter-
    string entry above) — so this ticket's own code changes are the
    other two: the hook-only `set -x` allowlist (item 5's fourth
    difference, above) and the write-then-run resolution (item 13's own
    sub-bullet, above). Like CLA-102, both are "narrow the check,
    disclose what narrowing costs" trade-offs, not residual-class items
    on their own: the trace allowlist's own fixed scope (tracing only,
    never a bare `set`, hook-only) and the write-then-run resolution's
    own fixed scope (four exact heredoc-to-file shapes, invalidated by
    any intervening `cd`, matched only by an exactly identical literal
    path) are each the disclosed boundary, not an omission.

## Intercept precision (v0.1.4)

The prompt Intercept hook and Command Policy block only on high-confidence Secrets: known provider-key prefixes (Stripe, GitHub, AWS, OpenAI, Anthropic, Google, Slack, ...) and PEM private-key blocks. They do NOT block on generic entropy, because ordinary agent traffic is full of high-entropy non-secrets (tool-call ids, UUIDs, git SHAs, base64 blobs, automated task notifications) and a false block stops the user's work. The honest trade: an unprefixed pasted secret is not auto-caught by Intercept; store it with `cpass add`, after which Redaction protects it. `detect.Scan` still offers the entropy heuristic for advisory, non-blocking uses.
