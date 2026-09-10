#!/usr/bin/env bash
# ClaudePass deploy script — run from a Mac with the `claudepass` SSH alias
# configured (key-only, logs in as root; see deploy/README.md).
#
# Builds the license service for linux/amd64, and rsyncs it plus the
# static site, the Caddyfile, and the license.service systemd unit onto
# the production droplet, then installs the config and restarts both
# services. Safe to re-run: every step is idempotent, and this script
# never reads, writes, or even looks at /etc/claudepass/license.env — the
# real Stripe/signing-key secrets are provisioned separately (see
# deploy/README.md) so a deploy can never accidentally clobber them.
#
# It does NOT touch /srv/claudepass/site/dl/ — that's the public release
# mirror install.sh and the Homebrew formula download from, populated by
# the release pipeline, not by this script.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

host="claudepass"
remote_base="/srv/claudepass"
build_dir="dist/deploy"

echo "==> building license-service for linux/amd64"
mkdir -p "$build_dir/bin"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$build_dir/bin/license-service" ./services/license

echo "==> ensuring remote directories and the 'license' service account exist"
# Idempotent, and none of this touches /etc/claudepass/license.env.
ssh "$host" '
	set -euo pipefail
	id -u license >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin license
	mkdir -p /srv/claudepass/bin /srv/claudepass/site /srv/claudepass/data
	chown -R license:license /srv/claudepass/data
'

echo "==> syncing the license-service binary"
# Upload under a temp name and rename into place so a partial transfer
# never leaves a half-written binary where systemd would find it.
rsync -az --checksum "$build_dir/bin/license-service" "$host:$remote_base/bin/license-service.new"
ssh "$host" "chmod 0755 $remote_base/bin/license-service.new && mv $remote_base/bin/license-service.new $remote_base/bin/license-service"

echo "==> syncing the static site (never touches site/dl/ on the server)"
rsync -az --delete --exclude 'dl/' --exclude 'dl' site/ "$host:$remote_base/site/"

echo "==> syncing Caddyfile and the license.service unit"
rsync -az deploy/Caddyfile "$host:/tmp/claudepass-Caddyfile"
rsync -az deploy/license.service "$host:/tmp/claudepass-license.service"

echo "==> installing config and restarting services"
ssh "$host" '
	set -euo pipefail
	install -o root -g root -m 0644 /tmp/claudepass-Caddyfile /etc/caddy/Caddyfile
	install -o root -g root -m 0644 /tmp/claudepass-license.service /etc/systemd/system/license.service
	rm -f /tmp/claudepass-Caddyfile /tmp/claudepass-license.service
	systemctl daemon-reload
	systemctl enable license.service >/dev/null
	systemctl restart license.service
	systemctl reload caddy 2>/dev/null || systemctl restart caddy
'

echo "==> done. Check: ssh $host systemctl status license.service caddy --no-pager"
