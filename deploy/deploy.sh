#!/usr/bin/env bash
# ClaudePass deploy script — run from a Mac with the `claudepass` SSH alias
# configured (see deploy/README.md).
#
# Rsyncs the static site, install.sh (repo root, not part of site/ — see
# below), and the Caddyfile onto the production host, validates the
# Caddyfile on the server before installing it, then reloads (or, if that
# fails, restarts) caddy. Safe to re-run: every step is idempotent.
#
# install.sh lives at the repo root, not under site/, so that
# internal/e2e/install_test.go can exercise the exact file a user's
# `curl .../install.sh | sh` runs without a build step in between. This
# script is what publishes that single source of truth to
# https://claudepass.com/install.sh — it is not reachable any other way,
# so skipping this step silently 404s the documented one-liner.
#
# It does NOT touch /srv/claudepass/site/dl/ — that's the public release
# mirror install.sh and the Homebrew formula download from, populated by
# the release pipeline, not by this script.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

host="claudepass"
remote_base="/srv/claudepass"

echo "==> ensuring remote directories exist"
ssh "$host" '
    set -euo pipefail
    mkdir -p /srv/claudepass/site
'

echo "==> syncing the static site (never touches site/dl/ on the server)"
rsync -az --delete --exclude 'dl/' --exclude 'dl' site/ "$host:$remote_base/site/"

echo "==> syncing install.sh (repo root is the single source of truth — internal/e2e/install_test.go exercises it there; this is the only thing that publishes it to the site)"
rsync -az install.sh "$host:$remote_base/site/install.sh"

echo "==> syncing Caddyfile"
rsync -az deploy/Caddyfile "$host:/tmp/claudepass-Caddyfile"

echo "==> validating Caddyfile on the server before installing it"
if ! ssh "$host" 'caddy validate --config /tmp/claudepass-Caddyfile --adapter caddyfile'; then
    echo "==> ABORTING: the new Caddyfile failed validation on the server — the live config was left untouched" >&2
    ssh "$host" 'rm -f /tmp/claudepass-Caddyfile' || true
    exit 1
fi

echo "==> installing config and reloading caddy"
ssh "$host" '
    set -uo pipefail
    install -o root -g root -m 0644 /tmp/claudepass-Caddyfile /etc/caddy/Caddyfile
    rm -f /tmp/claudepass-Caddyfile

    if ! systemctl reload caddy 2>/dev/null && ! systemctl restart caddy; then
        echo "==> WARNING: caddy failed to reload and restart" >&2
        exit 1
    fi
'

echo "==> done. Check: ssh $host systemctl status caddy --no-pager"
