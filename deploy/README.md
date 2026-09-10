# Deploying claudepass.com

The production host is a single DigitalOcean droplet (Ubuntu 24.04, 2
vCPU, 2 GB RAM), reachable only as `ssh claudepass` (a key-only, root
alias configured in `~/.ssh/config` on the deploying machine). One Caddy
instance terminates TLS for `claudepass.com` and either serves the static
site directly or reverse-proxies to the license service running locally
on `127.0.0.1:8080`.

## Layout on the server

| Path | What it is |
|---|---|
| `/etc/caddy/Caddyfile` | This directory's [`Caddyfile`](Caddyfile), installed verbatim. |
| `/etc/systemd/system/license.service` | This directory's [`license.service`](license.service), installed verbatim. |
| `/etc/claudepass/license.env` | The license service's secrets (`LICENSE_SIGNING_KEY`, `LICENSE_STRIPE_SECRET_KEY`, etc. — see `services/license/README.md`'s environment variable table). **Never written by `deploy.sh`** — provisioned separately, see below. |
| `/srv/claudepass/bin/license-service` | The `services/license` binary, built for `linux/amd64`. |
| `/srv/claudepass/site/` | The static site (this repo's [`site/`](../site)), rsynced with `--delete` — except `site/dl/`, which `deploy.sh` never touches. |
| `/srv/claudepass/site/install.sh` | This repo's [`install.sh`](../install.sh), rsynced verbatim by `deploy.sh` as its own step (the file lives at the repo root, not under `site/`, so `internal/e2e/install_test.go` can exercise it directly — this is the only step that publishes it, so skipping a deploy means `curl .../install.sh` 404s even though the file is right there in git). |
| `/srv/claudepass/site/dl/` | The public release mirror `install.sh` and the Homebrew formula (`softorize/tap`) download `cpass_<os>_<arch>.tar.gz` and `checksums.txt` from, at `/dl/<version>/...` and `/dl/latest/...`. Populated by the release pipeline (GoReleaser's output, copied here), **not** by `deploy.sh` — the release stage owns this directory. |
| `/srv/claudepass/data/` | The license service's SQLite file (`LICENSE_DB_PATH`), owned by the `license` system user. The only path `license.service`'s `ProtectSystem=strict` sandbox is allowed to write to (`ReadWritePaths`). |

The Caddyfile routes exactly five paths — `/checkout`, `/license`,
`/reissue`, `/webhook`, `/healthz` — to the license service; `/dl/*` is
static files with directory listing off; everything else is the static
site with `site/404.html` as the custom error page.

## Deploying

```bash
./deploy/deploy.sh
```

Run from the repository root, on the machine with the `claudepass` SSH
alias. It:

1. Cross-compiles `services/license` for `linux/amd64` (`CGO_ENABLED=0`,
   matching `modernc.org/sqlite`'s pure-Go driver — no cgo toolchain
   needed on either end).
2. Ensures the `license` system account and the `/srv/claudepass/{bin,site,data}`
   directories exist (idempotent — a no-op after the first run).
3. Uploads the binary under a temp name and renames it into place, so a
   partial transfer never leaves a half-written binary where systemd
   could find it.
4. Rsyncs `site/` to `/srv/claudepass/site/` with `--delete`, excluding
   `dl/` — so a stale local `site/` never removes published release
   binaries, and this script never needs to know what's actually in `dl/`.
5. Rsyncs `install.sh` (repo root) to `/srv/claudepass/site/install.sh` —
   its own step, since the canonical file lives outside `site/`.
6. Installs `deploy/Caddyfile` and `deploy/license.service`, then
   `systemctl daemon-reload`, restarts `license.service`, and reloads (or,
   if that fails, restarts) `caddy`.

Safe to re-run at any time; it makes no change `git diff`-visible to this
repo and never touches `/etc/claudepass/license.env`.

## Provisioning secrets (not part of `deploy.sh`)

`/etc/claudepass/license.env` holds the license service's live secrets —
`LICENSE_SIGNING_KEY` (the Ed25519 signing key matching
`internal/license/publickey.go`) and `LICENSE_STRIPE_SECRET_KEY` (the live
Stripe secret key), both ClaudePass Vault Handles on the machine doing the
deploy. They reach the server over SSH's `SendEnv`/`AcceptEnv` — never
typed, echoed, or logged — which requires the remote `sshd_config` to
`AcceptEnv LICENSE_*` (part of one-time droplet provisioning, done once,
separately from both this script and every deploy).

From the repo root, with a real Vault holding these Handles:

```bash
go build -o bin/cpass ./cmd/cpass
./bin/cpass run \
  --with stripe/live:LICENSE_STRIPE_SECRET_KEY \
  --with license/signing-key:LICENSE_SIGNING_KEY \
  -- ssh -o SendEnv=LICENSE_STRIPE_SECRET_KEY -o SendEnv=LICENSE_SIGNING_KEY claudepass \
  'umask 077; mkdir -p /etc/claudepass; { printf "LICENSE_STRIPE_SECRET_KEY=%s\n" "$LICENSE_STRIPE_SECRET_KEY"; printf "LICENSE_SIGNING_KEY=%s\n" "$LICENSE_SIGNING_KEY"; } > /etc/claudepass/license.env'
```

The remaining `LICENSE_*` variables `services/license/README.md` lists
(`LICENSE_STRIPE_PRICE_ID`, `LICENSE_STRIPE_WEBHOOK_SECRET`,
`LICENSE_BASE_URL=https://claudepass.com`, `LICENSE_DB_PATH=/srv/claudepass/data/license.db`,
and the `LICENSE_SMTP_*` reissue-email settings) aren't secret-Handle
material in the same sense but belong in the same file; append them the
same way or edit `/etc/claudepass/license.env` directly over `ssh
claudepass`. After any change to this file, restart the service:
`ssh claudepass systemctl restart license.service`.

## Publishing a release to `/dl/`

Not part of `deploy.sh` (which only ships the license service and the
site) — copy GoReleaser's `dist/` output for a tagged release to
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
