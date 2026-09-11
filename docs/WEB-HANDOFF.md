# Web implementation hand-off spec (CLA-36)

The marketing/app site is shipped and live at https://claudepass.com. This
spec is the contract between the Figma Brand Book and the site so the two
stay in sync.

## Stack (as shipped, and the recommendation to keep)
- **Static HTML + one CSS file** (`site/retro.css`), no framework, no build
  step, self-hosted Press Start 2P. Served by **Caddy** on the DigitalOcean
  host with automatic TLS; app routes reverse-proxy to the Go license service.
- Recommendation: **stay static.** The site is content + one canvas game +
  three form POSTs. A framework would add a build step and a runtime for no
  gain. Revisit only if an authenticated dashboard is added.

## Token export (Figma → code)
The Figma library (file `tamehh67b8zUgteY6xVQv5`) is the source of truth for
design tokens, across eight variable collections: Primitives, Color,
Spacing, Radius, Elevation, Motion, Typography, and Type Scale. `retro.css`
carries all eight, in two layers:

- **Primitives** (`--bg-void`, `--ember`, `--light-theme-amber`, `--cream`,
  `--sand`, …) are the only place a raw hex/rgb literal is allowed to live,
  defined once in `:root`.
- **Semantic Color tokens** (`--color-bg-canvas`, `--color-bg-surface`,
  `--color-border`, `--color-text-primary`, `--color-accent`,
  `--color-danger`, …) are the exact Figma WEB code syntax names, each
  defined as `var(--<primitive>)` — never a literal — so a primitive is
  the single source of truth for its value. `:root` carries the Color
  collection's **Dark** mode. Its **Light** mode is a second definition of
  the same names, scoped to `.inner-page main` (not `.inner-page` itself,
  so the sticky header/footer on inner pages keep the Dark values exactly
  like today — only the long-form content area switches).

`radius-none` is the default everywhere; `radius-pill` is the one
deliberate exception, on Handle Pill and Badge, plus (documented here
since it is easy to miss) the Terminal Window's three traffic-light
dots (`.terminal-dot`) — Figma's Install Terminal Block draws them as
circles, not squares.

Spacing, Radius, Elevation, Motion, Typography and Type Scale have one mode
each and live only in `:root` (`--space-1..8`, `--radius-none/sm/md/lg/pill`,
`--bevel-width`/`--focus-ring-width`/`--focus-ring-offset`,
`--duration-instant/fast/base/slow/loop` + `--ease-out-arcade` /
`--ease-in-out-loop`, `--font-family-display/body/mono` +
`--font-weight-regular/bold`, `--text-xs..4xl`). A handful of overlay/glow
tokens (`--bevel-hi-overlay`, `--bevel-lo-overlay`, `--glow-accent`,
`--crt-scanline`, `--overlay-scrim`, `--overlay-scrim-hover`) are **not**
from Figma — they exist only so a translucent wash over an existing fill
has one named source instead of a fresh literal, and are marked as such in
`site/tokens.json`.

**`site/tokens.json`** is a committed, trimmed export of all eight
collections (name, type, per-mode values, WEB code syntax), derived from
the design handoff's `figma-tokens.json`. **`internal/site/tokens_test.go`**
(package `claudepass/internal/site`, runs with the rest of `go test ./...`,
no build tag) parses `retro.css`'s `:root` and `.inner-page main` blocks,
resolves each token's `var()` alias chain the way a browser would, and
fails if a resolved value drifts from `tokens.json`, or if any color
literal turns up in `retro.css` outside those two blocks. That test is the
parity contract: when a token changes in Figma, update `site/tokens.json`
and the matching `--token` in `retro.css` in the same commit, or the test
fails.

Two values are deliberately **shipped-value-wins** over what an older
Figma/handoff export said, both recorded with a comment at their
definition and in `site/tokens.json`: `--focus-ring-width` is `3px` (Figma
said `2`, then was updated to match `3`), and `--font-family-display` /
`--font-family-body` / `--font-family-mono` carry the site's fuller,
practical font stacks (with fallback fonts Figma's plain family-name
string doesn't include).

## Component mapping (Figma component → CSS class)
One row per Figma component, with every variant/state it has in code and where it's shown. Everything in this table that has no other product surface (Paywall Banner, License Checkout Fields, Elevation swatches, the Dark/Light footer pairing, Handle Pill's copied state, Badge/Exposed) is rendered at **`/brand`** — see the Route map below.

| Figma component | Variants/states | Site class | Where shown |
|---|---|---|---|
| Button | Primary / Secondary / Danger-outline / Danger-filled / Disabled / focus-visible | `.btn.btn-primary` / `.btn-secondary` / `.btn-danger-outline` (outline) / `.btn-danger` (filled); disabled via `.btn[disabled]` or `.btn.is-disabled` (40% opacity, no hover lift, `pointer-events:none`); focus via the shared `:focus-visible` outline (`--focus-ring`), not a 4th variant | Every page's CTAs; all four + disabled + focus-ring on `/brand` |
| Handle Pill | Default / Copied | `.handle-pill`; copied via `.handle-pill.is-copied` (border/text shift to `--color-accent`) | Default: landing hero lede, docs vocabulary, security page, game HUD. Copied: `/brand` only — no live page wires a copy affordance onto a pill itself yet |
| Code Chip | inline (dark), inline (light) | `.content code` (light `.inner-page`), `code:not(pre code)` (dark pages) | Every inner page's inline `<code>`; both dark/light appearances on `/brand` |
| Panel / Cabinet | default, hover lift | `.cab-panel` | Landing "How it works", pricing cards, account page, `/brand` |
| Badge | Free / Pro / Exposed | `.badge.badge-free` / `.badge-pro` / `.badge-exposed` | Free/Pro: both pricing cards next to the plan `<h3>`. Exposed: `/brand` only — no live page shows an Exposed badge today. Free and Pro are both the outline treatment (steel/ember `border` + matching text on `--color-bg-surface`) per the winning atom-v2 badge spec — Pro is not a filled ember pill |
| Input | Default / Focus / Error | `.input` / `form.checkout-form input[type=email]`, error via `.is-error` or `[aria-invalid="true"]` + adjacent `.field-error` | Default/Focus: `/pricing`, `/account` email fields. Error: same fields, set client-side in `site/js/site.js` (HTML5 constraint validation on submit — required check on `/account`, format-if-present on `/pricing`; there is no server round-trip that re-renders these static pages, so the browser-side check is the only path that can ever reach this state). All three side by side on `/brand` |
| Redaction Token (chip) | Idle / Kill / Breach | `.redacted.redacted--idle` / `--kill` / `--breach` | Idle: `/brand` only. Kill/Breach: landing page's `<noscript>` fallback, the security page's Redaction section, and the `.redacted--breach` marker on `/404` (`[REDACTED: /this-page]`) and `/500` (`[REDACTED: /license-service]`) |
| Terminal Window | titlebar + body, with/without copy buttons | `.terminal-titlebar` (3 dots + label) + `.terminal` (with a `.terminal-line` per command); a titlebar-less inline variant is plain `<pre>`, picking up its look from the generic `.inner-page .content pre` rule with no class of its own | Landing `#install`, `/install`, `/docs` quickstart, `/account` (bare `<pre>`, no titlebar), license-service `license_ready.html`; a full titlebar+body+copy-button instance on `/brand` |
| Term list (definition list) | single | `dl.term` (`.inner-page .content dl.term dt` / `dd`) — a separate component from Code Chip and Terminal Window, despite the shared "term" name | `/docs` vocabulary section, license-service `license_ready.html` (plan/account/expiry rows), `/brand` reference |
| Command-Policy-Block Alert / Toast | Alert (dismissible card) / Toast (compact strip) | `.cp-alert` (with `.cp-alert-head`, `.cp-alert-label`, `.cp-alert-dismiss`, `.cp-alert-message`) / `.cp-toast` (with `.cp-toast-badge`) | Alert: `/security`. Toast: `/brand` only — no live page has a transient-notification surface yet. Both reuse the real refusal string verbatim (see the Command Policy row of the Accessibility/canon note below, and `internal/policy`). Both are dark composites: every colour is a raw dark primitive (`--panel-bg`/`--alert-red`/`--signal-cyan`/`--text-hi`/`--bg-void`), never a `--color-*` semantic token, so they read the same on a light `.inner-page` as on a dark one — Alert keeps dc-66:94's red border card, Toast keeps composites-root-v1 26:25's cyan border + square "CP" glyph badge, no mixing the two treatments |
| Security Trust Panel | single (Vault + Command Policy glyphs) | `.trust-panel` (`.trust-panel-icons` + `.trust-panel-glyph` × 2, `.trust-panel-copy`) | Landing `#security`, `/security` |
| Install spinner | full-width (progress), inline (checkout button) | `.spinner` / `.spinner.spinner-inline` | Full-width: `/install`. Inline: the checkout button's "TAKING YOU TO SECURE CHECKOUT…" submitting state (`site/js/site.js`). Both, live/looping, on `/brand` |
| Nav Header | single (no GITHUB link, no header CTA — see the ADR below) | `.arcade-header` (`.brand`, `.arcade-nav`, `.header-tools`, `.icon-btn`) | Every page's sticky header; a static (non-interactive, unduplicated-id) reference copy on `/brand` |
| Footer | Dark (shipped) / Light (documented only, W22) | `.arcade-footer` (shipped, every page) / `.footer-light-demo` (`/brand`-only CSS, not used on any real page) | Dark: every page's footer. Light: `/brand` only, side by side with Dark, per the W22 decision below |
| Pricing Card | Free / Pro | `.plan` / `.plan.pro` | `/pricing`, landing `#pricing`; copy is the canon-worked-examples text (see the W19 decision below), not dc-25:42's |
| Paywall / Upgrade Banner | single | `.paywall-banner` (`.paywall-copy`) | `/brand` only — see the W18 decision below |
| License Checkout Fields | single, spec-only | `.checkout-mock` (`.field`, `.field-label`, `.field-mock`, `.fine-print`) | `/brand` only, labeled "reference only" — see the W20 decision below |
| [REDACTED] Bar | game canvas | game canvas (`site/game/game.js`); DOM equivalent is the Redaction Token chip above | Landing page canvas |
| Elevation (Bevel raised/inset, Elevation 1–3) | 5 swatches | `.bevel-raised` / `.bevel-inset` / `.elevation-1` / `.elevation-2` / `.elevation-3` | `/brand` only — no live page needed a labeled elevation reference before this |
| Iconography | 7 Tier-0 icons + 2 game sprites | `<img>`/inline `<svg>` from `site/assets/icons/*.svg` | Used inline across `/docs`, `/security`, `/install` headings; the full named gallery is on `/brand` |

### Decisions on record (this hand-off is where they're findable)
- **W19 — Pricing Card copy**: `canon-worked-examples` (14:19, "pulled from the live site") is the source of truth for the Pricing Card's feature-list copy, not the `dc-25:42` component spec — the latter's ✓/· feature list and 4-item list don't match anything shipped and were flagged to design as stale. `site/pricing/index.html`'s copy is unchanged by this reconciliation. The one thing worth adopting from dc-25:42 going forward is its Badge sub-component (already shipped, see the Badge row above) and its ✓/· bullet-glyph treatment as an option for design to consider — not its specific feature strings.
- **W22 — Nav GITHUB/CTA and Footer Dark/Light**: recorded in `docs/adr/0010-nav-footer-no-github-dark-footer.md`. Short version: no `GITHUB` link, no header CTA (closed-source product, redundant with page-level CTAs); the footer stays Dark on every page including `.inner-page` ones, intentionally — the Light variant is documented at `/brand` only.
- **W20 — License Checkout Fields**: the Figma component's inline EMAIL + CARD NUMBER form does not become a live field. The real checkout (`site/pricing/index.html`'s `form.checkout-form`, `services/license/internal/server/checkout.go`) posts only an optional email and redirects to Stripe-hosted Checkout; ClaudePass never collects or renders a card-number field, per Stripe's PCI model. The component's card field maps to Stripe Checkout's own hosted UI, not a ClaudePass-rendered form — do not "fix" this by wiring up a real card input later. Shown at `/brand` as a labeled `.checkout-mock`, not a `<form>`.
- **W18 — Paywall/Upgrade Banner**: "3 of 3 Secrets used" is local CLI state (`cpass vault`) never transmitted to the website — there is no logged-in web dashboard today, so this Tier-2 composite has no real web surface to live on. Built at `/brand` only, labeled as awaiting a real product surface. Flag to product/design: the real trigger for this message likely belongs in `cpass list`/`cpass add` terminal output (it already exists there — `internal/cli/licensecmds.go`'s `freeLimitMessage`, e.g. `cpass: free plan holds 3 Secrets; upgrade at https://claudepass.com/pricing ($9.99/month)`) rather than as a web banner nothing currently shows.
- **W26 — Excluded-clichés icon guardrail**: the five banned generic-security icons (Padlock, Hoodie-Hacker Shield, Matrix-Rain, Sparkle/Starburst, Soft Rounded Keyhole) are listed in `CONTEXT.md`'s "Excluded icons" section and enforced by `internal/site/guardrail_test.go` (`TestNoExcludedIconFilenames`), which fails `go test ./...` the moment a new SVG lands under `site/assets/` with a suspicious filename (`lock`, `padlock`, `shield`, `hoodie`, `hacker`, `matrix`, `sparkle`, `starburst`, `keyhole`).

## Text styles (Figma style → CSS class)
| Figma style | Site class |
|---|---|
| Display/Wordmark-Hero | `.t-display-wordmark-hero` |
| Display/Wordmark-Nav | `.t-display-wordmark-nav` |
| Display/H1 | `.t-display-h1` |
| Display/H2 | `.t-display-h2` |
| Display/Button | `.t-display-button` |
| Display/HUD-Label | `.t-display-hud-label` |
| Display/HUD-Score | `.t-display-hud-score` |
| Label | `.t-label` |
| Body/Regular | `.t-body` |
| Body/Small | `.t-body-small` |
| Code/Inline | `.t-code-inline` |
| Code/Mono-Small | `.t-code-mono-small` |

## Icons and the brand-mark glyph
Seven Tier-0 icons (`iconography-root.md`) are self-hosted SVGs under
`site/assets/icons/`: `icon-redaction-bar`, `icon-handle-tag`,
`icon-broker-seam`, `icon-manifest-check`, `icon-command-refusal-bar`,
`icon-exposed-flag`, `icon-terminal-glyph`. Single-colour icons use
`fill="currentColor"` and are inlined (not `<img>`) wherever they need to
pick up a specific ink color; the rest keep their literal multi-colour
fills. `player-tank.svg` and `intruder-tank-env.svg` mirror `game.js`'s
`PAL` hex constants exactly.

The header/footer brand-glyph, every page's `<link rel=icon>` favicon, and
`site/assets/icon.html`'s generated app icon (`icon.png`,
`favicon-512.png`) are all one shape now — canon-wordmark-type's
Door/Dial/Handle vault glyph — scaled from the same 16-unit proportions
(Door = full square radius-none, Dial = a circle 37.5% of the Door's
width centered in it, Handle = a thin vertical bar right-of-center).

## Route map
| Path | File / handler | Issue |
|---|---|---|
| `/` | `site/index.html` (Vault Defense game) | CLA-29 |
| `/pricing` | `site/pricing/` (POST → `/checkout`) | CLA-29/32 |
| `/install` | `site/install/` | CLA-31 |
| `/docs` | `site/docs/` | CLA-31 |
| `/account` | `site/account/` (POST → `/reissue`) | CLA-33 |
| `/brand` | `site/brand/` — living style guide, not linked from the nav | CLA-27 |
| `/security` `/privacy` `/terms` | `site/*/` | CLA-34 |
| `/404.html` | Caddy `handle_errors` (404) | CLA-34 |
| `/500.html` | Caddy `handle_errors` (5xx from Caddy itself, e.g. a dead upstream) | CLA-34 |
| `/checkout` `/license` `/reissue` `/webhook` `/healthz` | Go license service | CLA-32/33 |
| `/checkout/canceled` | `site/checkout/canceled/` — static, deliberately NOT in `deploy/Caddyfile`'s `@licenseService` matcher; Stripe Checkout's `CancelURL` (set in `services/license/internal/stripeapi/stripeapi.go`) sends cancelled buyers here | CLA-32/33 |
| `/dl/*` `/install.sh` `/assets/*` | static (releases, installer, brand assets) | CLA-31/35 |

## Accessibility & SEO contract
- Every text pairing meets WCAG AA (see the Brand Book "06 — Accessibility"
  page; all pairings pass in both modes). Contrast is not to be reduced.
- Every page carries the verbatim non-affiliation disclaimer and the
  `og:image` / `twitter:image` social card (`/assets/og.png`).

## Transactional email (reissue)
The one email ClaudePass sends (`services/license/internal/mailer/mailer.go`,
`ReissueEmail`) was checked against the CONTEXT.md vocabulary on 2026-09-11:
it speaks only of a *license*, a *subscription* and the literal
`cpass license activate <token>` command — the token is never called a Secret
or a Handle, nothing in the copy contradicts the glossary, and the footer
carries the disclaimer verbatim. Its inline colours are the named constants
in that file, mirrored by hand from `site/tokens.json` (light-bg, light-fg,
light-theme-amber, bg-void, ember, sand); when a token changes, update both.
The plain-text part is first-class; the HTML part is a restrained alternative
with no images and no marketing content.
