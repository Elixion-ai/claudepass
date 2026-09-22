# Deploying claudepass.com

The production host is reached only as `ssh claudepass` (an alias
configured in `~/.ssh/config` on the deploying machine). One Caddy
instance terminates TLS for `claudepass.com` and serves the static site.

## Layout on the server

| Path | What it is |
|---|---|
| `/etc/caddy/Caddyfile` | This directory's [`Caddyfile`](Caddyfile), installed verbatim. |
| `/srv/claudepass/site/` | The static site (this repo's [`site/`](../site)), rsynced with `--delete` — except `site/dl/`, which `deploy.sh` never touches. |
| `/srv/claudepass/site/install.sh` | This repo's [`install.sh`](../install.sh), rsynced verbatim by `deploy.sh` as its own step (the file lives at the repo root, not under `site/`, so `internal/e2e/install_test.go` can exercise it directly — this is the only step that publishes it, so skipping a deploy means `curl .../install.sh` 404s even though the file is right there in git). |
| `/srv/claudepass/site/dl/` | The public release mirror `install.sh` and the Homebrew formula (`softorize/tap`) download `cpass_<os>_<arch>.tar.gz` and `checksums.txt` from, at `/dl/<version>/...` and `/dl/latest/...`. Populated by the release pipeline (GoReleaser's output, copied here), **not** by `deploy.sh` — the release stage owns this directory. |

`/dl/*` is static files with directory listing off; everything else is
the static site with `site/404.html` and `site/500.html` as the custom
error pages.

## Deploying

```bash
./deploy/deploy.sh
```

Run from the repository root, on the machine with the `claudepass` SSH
alias. It:

1. Rsyncs `site/` to `/srv/claudepass/site/` with `--delete`, excluding
   `dl/` — so a stale local `site/` never removes published release
   binaries, and this script never needs to know what's actually in `dl/`.
2. Rsyncs `install.sh` (repo root) to `/srv/claudepass/site/install.sh` —
   its own step, since the canonical file lives outside `site/`.
3. Uploads `deploy/Caddyfile` to a temp path and runs
   `caddy validate --config ... --adapter caddyfile` on the server,
   aborting with a clear message (and leaving the live config untouched)
   if validation fails — a bad Caddyfile can never take the site down.
4. Installs the validated Caddyfile to `/etc/caddy/Caddyfile` and
   `systemctl reload caddy` (falling back to `restart` if reload fails).

Safe to re-run at any time; it makes no change `git diff`-visible to this
repo.

## Publishing a release to `/dl/`

Not part of `deploy.sh` (which only ships the static site) — copy
GoReleaser's `dist/` output for a tagged release to
`/srv/claudepass/site/dl/v<version>/` (matching
`cpass_<os>_<arch>.tar.gz` and `checksums.txt`) and refresh
`/srv/claudepass/site/dl/latest/` to match, e.g.:

```bash
ssh claudepass 'mkdir -p /srv/claudepass/site/dl/v0.1.2'
rsync -az dist/cpass_*.tar.gz dist/checksums.txt claudepass:/srv/claudepass/site/dl/v0.1.2/
ssh claudepass 'rm -rf /srv/claudepass/site/dl/latest && cp -r /srv/claudepass/site/dl/v0.1.2 /srv/claudepass/site/dl/latest'
```

This is what `install.sh`'s `https://claudepass.com/dl/latest/...` and the
Homebrew formula's `https://claudepass.com/dl/v<version>/...` URLs read
from.

`checksums.txt` published here must stay byte-identical to the one
GoReleaser already uploaded to the GitHub Release for the same tag —
`install.sh` cross-checks the two and refuses to install on a mismatch
(CLA-79, `docs/SECURITY.md` "Verifying a release"). Copying `dist/`
straight from GoReleaser's own output, as the snippet above does, keeps
that true automatically; hand-editing anything under `/dl/` after the fact
would not.

### Bumping the Homebrew tap (manual, outside this repo)

`.goreleaser.yaml` has no `brews:` integration, so `brew install
softorize/tap/cpass` (README.md) is **not** kept current by anything in
this repo or its CI — it is a separate, manual step in a separate
repository, [`Softorize/homebrew-tap`](https://github.com/Softorize/homebrew-tap)
(`Formula/cpass.rb`), kept current by hand through v0.2.1. After
completing the `/dl/` publish above for a new tag, in a checkout of that
other repo, edit `Formula/cpass.rb` to match the new release's
`checksums.txt`:

1. Bump the `version "..."` string to the new tag's version (no leading
   `v`).
2. Replace each of the four `sha256 "..."` values (one per
   `on_macos`/`on_linux` × `on_arm`/`on_intel` block) with that
   architecture's entry from `checksums.txt` — the formula's own header
   comment says as much, but nothing enforces it stays true.
3. Commit and push directly to `Softorize/homebrew-tap`; there is no PR
   review or CI gate on that repo today, so a mistake here is live the
   moment it's pushed. `brew install --build-from-source` or a `brew test
   cpass` against the bumped formula is the only check before that.

The next release-cutter following only *this* repo's own docs would
otherwise never learn this step exists, and `brew install`/`brew upgrade`
would keep serving the previous version indefinitely with no error at all
— silent, not loud, unlike every other verification gap CLA-79 closed.
