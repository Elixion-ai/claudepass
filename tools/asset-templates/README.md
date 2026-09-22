# Asset templates

Build-time screenshot targets for the static PNGs committed under
`site/assets/`: `og.html` renders `og.png` (the `og:image`/`twitter:image`
social card), `icon.html` renders `icon.png` and `favicon-512.png` (the
app icon), and `readme-header.html` renders `readme-header.png` (the
README banner). Each file sets its own fixed `html`/`body` pixel size —
screenshot the rendered page at exactly that size and save the result
over the matching file in `site/assets/`.

These live here, outside `site/`, on purpose (CLA-92): they are not
pages — nothing links to them, and unlike every real page they lean on
an inline `<style>` block and an inline `style=` attribute rather than
`retro.css`, so keeping them under `site/` would either need the
production CSP's `style-src` to keep granting `'unsafe-inline'` for
their sake alone, or leave them silently broken if that ever changed.
Being outside the served root, `deploy.sh`'s rsync of `site/` never
publishes them, and the tightened `style-src` in `deploy/Caddyfile` has
nothing under it left that needs `'unsafe-inline'`.

Open a template directly in a browser to regenerate its PNG. `og.html`
and `readme-header.html` load the pixel font via a relative
`../../site/fonts/...` `@font-face` URL, so open those two from their
own location on disk (not copied elsewhere) or via a local static
server rooted at the repo root.
