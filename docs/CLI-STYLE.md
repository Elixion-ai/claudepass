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
| Stored a Secret | `cpass: stored <kind> as <handle>; …` | `cpass: stored Stripe live key as stripe/live` |
| Refusal (Command Policy) | `cpass: refused: <what> — <do instead>` | `cpass: refused: cat would read .env, a Secret-bearing file — use ` + "`cpass run`" |
| Redaction marker (in child output) | `[REDACTED:<handle>]` | `STRIPE_SECRET_KEY=[REDACTED:stripe/live]` |
| Redaction notice | `cpass: redacted <handle> from output (<n>×)` | |
| Exposed reminder | `cpass: <handle> is Exposed since <date>, rotate it` | |
| Locked Vault | `cpass: vault is locked, run cpass unlock` | |

## Exit codes
`0` ok · `1` error · `2` usage / hook-block · `3` refused (Command Policy).
These are contract; do not repurpose them.

## Colour (ANSI, TTY only)
Colour is applied only when stdout is a TTY (never when piped or captured, so
logs stay clean). Palette maps to the brand:
- ember (208 / `#ff8a1f`) — the Handle, success.
- cyan (45 / `#4de8ff`) — hints, the `cpass run` shield.
- red (203 / `#ff4d4d`) — refusals, the `[REDACTED]` marker, Exposed.
- dim grey — secondary detail.
Truecolor when `COLORTERM` supports it, else the 256-colour fallbacks above,
else no colour. Respect `NO_COLOR`.

## Terminal demos (asciinema / GIF)
- 80×24, one idea per demo, ~2s pauses. Never type a real Secret on camera —
  use `cpass add` off-screen and a fake `sk_live_…` for the Intercept demo.
- Show the mechanism, not the value: the winning shot is `cpass run -- env`
  printing `STRIPE_SECRET_KEY=[REDACTED:stripe/live]`.
- Amber prompt, `#0e0a06` background, Press Start 2P for any title card.
