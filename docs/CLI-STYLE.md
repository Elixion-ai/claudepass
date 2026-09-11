# ClaudePass CLI output & terminal-demo style guide (CLA-28)

The `cpass` CLI is the primary product surface. Its output follows one rule:
an Agent reads it, so it must be legible, quiet, and never leak a Secret.

## Voice
- Lowercase, terse, one line where one line will do. The program name prefixes
  every diagnostic: `cpass: <message>`.
- Say the Handle, never the value. Success prints the Handle; failure names the
  Handle and what to do.

## Message grammar
| Situation | Shape | Example |
|---|---|---|
| Stored a Secret (`cpass add`) | `stored <handle> (<binding kind> <binding name>)` | `stored stripe/live (env STRIPE_LIVE)` |
| Secret caught in a prompt (`cpass intercept`) | `cpass: stored <kind> as <handle>[, <kind> as <handle>…]; resubmit using the Handle, or prefix with !! to send anyway` | `cpass: stored Stripe live key as stripe/live; resubmit using the Handle, or prefix with !! to send anyway` |
| Refusal (Command Policy) | `cpass: refused: <what> — <do instead>` | ``cpass: refused: cat would read .env, a Secret-bearing file — use `cpass run` (or the Manifest) instead of reading the file directly`` |
| Redaction marker (in child output) | `[REDACTED:<handle>]` | `STRIPE_SECRET_KEY=[REDACTED:stripe/live]` |
| Redaction notice | `cpass: redacted <handle> from output (<n>×)` | |
| Exposed reminder | `cpass: <handle> is Exposed since <date>, rotate it` | |
| Locked Vault | `cpass: vault is locked, run cpass unlock` | |

`cpass add`'s success line is a confirmation, not a diagnostic — like
`init`/`rm`/`mv`'s own success lines, it skips the `cpass: ` prefix. It
colours its Handle ember and its Binding detail dim grey (see Colour below)
but does not use the `<kind> as <handle>` grammar: `add` never detects a
Secret's kind (that only happens during Intercept), so its own row and
Intercept's are deliberately different shapes for different situations.

## Exit codes
`0` ok · `1` error · `2` usage / hook-block · `3` refused — a Command Policy
block, or `CheckFreeLimit` (`internal/cli/licensecmds.go`) refusing a new
Secret past the free plan's limit. Both are refusals in the general sense;
only the Command-Policy path uses the `cpass: refused: <what> — <do instead>`
grammar (`CheckFreeLimit`'s message is its own plain sentence, matched
character-for-character by `internal/e2e/license_test.go`'s `freeLimitMsg`).
These exit codes are contract; do not repurpose `0`/`1`/`2`/`3` for anything
outside what is already listed here.

## Colour (ANSI, TTY only)
Implemented in `internal/cli/ansi.go` (that file's own doc comment
cross-links back here — the two must never diverge). Colour is decided once
per destination stream when the CLI's `env` is built: stderr's mode governs
every coloured diagnostic (`refuse`, `stored`, `exposed`, `locked` in
`internal/cli/cli.go`) and stdout's own mode governs `add`'s success line
(see Message grammar above); `notice` is the plain fallback for a
diagnostic with no fixed brand role of its own and never applies colour,
regardless of the stream's mode. Each stream's own mode also governs the
`[REDACTED:<handle>]` marker written to it, so a redirected stdout with a
TTY stderr (or vice versa) colours only the stream that is actually a
terminal.

Detection order (`detectColorMode` in `ansi.go`), checked in this sequence:
1. `NO_COLOR` set to any non-empty value → no colour, unconditionally.
2. The destination is not a TTY (piped, redirected to a file, captured by a
   test) → no colour.
3. `TERM=dumb` → no colour.
4. `COLORTERM` is `truecolor` or `24bit` → 24-bit escapes.
5. Otherwise → the 256-colour fallback escapes below.

Palette maps to the brand (escape codes exactly as `ansi.go` emits them):
- ember — the Handle, success. 256: `\x1b[38;5;208m`. Truecolor (`#ff8a1f`): `\x1b[38;2;255;138;31m`.
- cyan — hints, the `cpass run` shield. 256: `\x1b[38;5;45m`. Truecolor (`#4de8ff`): `\x1b[38;2;77;232;255m`.
- red — refusals, the `[REDACTED]` marker, Exposed. 256: `\x1b[38;5;203m`. Truecolor (`#ff4d4d`): `\x1b[38;2;255;77;77m`.
- dim grey — secondary detail (`text-muted`). 256: `\x1b[38;5;245m`. Truecolor (`#b3a89b`): `\x1b[38;2;179;168;155m`.

Every colour segment ends with a plain reset, `\x1b[0m`. With colour off,
output is byte-for-byte identical to a build with no colour support at
all — this is what every `internal/e2e` assertion on cpass's stdout/stderr
relies on, since those tests always capture through a pipe.

## Terminal demos (asciinema / GIF)
- 80×24, one idea per demo, ~2s pauses. Never type a real Secret on camera —
  use `cpass add` off-screen and a fake `sk_live_…` for the Intercept demo.
- Show the mechanism, not the value: the winning shot is `cpass run -- env`
  printing `STRIPE_SECRET_KEY=[REDACTED:stripe/live]`.
- Amber prompt, `#0e0a06` background, Press Start 2P for any title card.
