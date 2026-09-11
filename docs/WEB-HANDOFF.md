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
design tokens. Export path: the `Primitives` and `Color` (Dark/Light) variable
collections map 1:1 to the CSS custom properties already in `:root` of
`site/retro.css`. When a token changes in Figma, update the matching
`--token` in `retro.css`; names are identical (ember, panel-bg, color-accent…).

## Component mapping (Figma component → CSS class)
| Figma component | Site class |
|---|---|
| Button (Primary/Secondary/Danger) | `.btn.btn-primary` / `.btn-secondary` / `.btn-danger-outline` |
| Handle Pill | `.handle-pill` (game HUD + docs) |
| Code Chip | `.content code`, `.term` |
| Panel / Cabinet | `.cab-panel` |
| Badge (Free/Pro/Exposed) | `.plan-accent`, pricing card headers |
| Nav Header | `.arcade-header` |
| Footer (Dark/Light) | `.arcade-footer`, `.inner-page` footer |
| Pricing Card | `.plan` / `.plan.pro` |
| [REDACTED] Bar | game canvas (`site/game/game.js`) |

## Route map
| Path | File / handler | Issue |
|---|---|---|
| `/` | `site/index.html` (Vault Defense game) | CLA-29 |
| `/pricing` | `site/pricing/` (POST → `/checkout`) | CLA-29/32 |
| `/install` | `site/install/` | CLA-31 |
| `/docs` | `site/docs/` | CLA-31 |
| `/account` | `site/account/` (POST → `/reissue`) | CLA-33 |
| `/security` `/privacy` `/terms` | `site/*/` | CLA-34 |
| `/404.html` | Caddy `handle_errors` | CLA-34 |
| `/checkout` `/license` `/reissue` `/webhook` `/healthz` | Go license service | CLA-32/33 |
| `/dl/*` `/install.sh` `/assets/*` | static (releases, installer, brand assets) | CLA-31/35 |

## Accessibility & SEO contract
- Every text pairing meets WCAG AA (see the Brand Book "06 — Accessibility"
  page; all pairings pass in both modes). Contrast is not to be reduced.
- Every page carries the verbatim non-affiliation disclaimer and the
  `og:image` / `twitter:image` social card (`/assets/og.png`).
