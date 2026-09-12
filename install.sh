#!/bin/sh
# ClaudePass installer.
#
#   curl -fsSL https://claudepass.com/install.sh | sh
#
# Downloads a prebuilt cpass release archive and its checksums.txt from
# claudepass.com's own release mirror (served from /dl/, see
# deploy/Caddyfile and deploy/README.md — the archives themselves are
# GoReleaser's output, CLA-16), verifies the archive's sha256 against
# checksums.txt, and installs the cpass binary. No GitHub credentials are
# needed: cpass downloads prebuilt archives from claudepass.com's own /dl/
# release mirror, not from GitHub directly.
#
# Env vars (all optional):
#   CPASS_VERSION       "latest" or an explicit tag, e.g. v0.1.2 (default latest)
#   CPASS_INSTALL_DIR   where to put the binary (default: see pick_install_dir)
#   CPASS_BASE_URL      override the download origin entirely — for a
#                       mirror, or for testing against a local fixture
#                       server. When set, the asset and checksums.txt are
#                       fetched from "$CPASS_BASE_URL/dl/<version>/..." with
#                       no authentication.
#
# CI / tests: `CPASS_INSTALL_DIR=$(mktemp -d) sh install.sh` installs into a
# temp prefix instead of touching the real system paths.

set -eu

version="${CPASS_VERSION:-latest}"
base_url="${CPASS_BASE_URL:-https://claudepass.com}"

err() {
    printf 'cpass-install: %s\n' "$1" >&2
    exit 1
}

detect_os() {
    case "$(uname -s)" in
        Darwin) echo darwin ;;
        Linux) echo linux ;;
        *) err "unsupported OS: $(uname -s) (cpass ships darwin and linux only)" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        arm64 | aarch64) echo arm64 ;;
        x86_64 | amd64) echo amd64 ;;
        *) err "unsupported architecture: $(uname -m) (cpass ships amd64 and arm64 only)" ;;
    esac
}

pick_install_dir() {
    if [ -n "${CPASS_INSTALL_DIR:-}" ]; then
        echo "$CPASS_INSTALL_DIR"
        return
    fi
    if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
        echo /usr/local/bin
        return
    fi
    echo "$HOME/.local/bin"
}

have() { command -v "$1" >/dev/null 2>&1; }

# sha256_of FILE — prints the lowercase hex sha256 of FILE, using whichever
# of sha256sum (Linux) or shasum (macOS) is present; both ship without
# extra installs on every platform cpass targets.
sha256_of() {
    if have sha256sum; then
        sha256sum "$1" | awk '{print $1}'
    elif have shasum; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        err "neither sha256sum nor shasum found; cannot verify the download"
    fi
}

# verify_checksum FILE ASSET CHECKSUMS_FILE — looks up ASSET's expected
# sha256 in a GoReleaser-style checksums.txt ("<hex>  <filename>" per
# line, filename optionally prefixed with "*" for binary mode) and fails
# loudly on a missing entry or a mismatch, rather than installing an
# unverified binary.
verify_checksum() {
    file="$1" asset="$2" checksums="$3"
    want="$(awk -v a="$asset" '{ f = $2; sub(/^\*/, "", f); if (f == a) { print $1; found = 1 } } END { exit !found }' "$checksums")" \
        || err "no checksum entry for $asset in checksums.txt"
    got="$(sha256_of "$file")"
    [ "$want" = "$got" ] || err "checksum mismatch for $asset: expected $want, got $got"
}

main() {
    os="$(detect_os)"
    arch="$(detect_arch)"
    asset="cpass_${os}_${arch}.tar.gz"
    install_dir="$(pick_install_dir)"

    workdir="$(mktemp -d)"
    trap 'rm -rf "$workdir"' EXIT

    archive="$workdir/$asset"
    checksums="$workdir/checksums.txt"

    curl -fsSL "$base_url/dl/$version/$asset" -o "$archive" \
        || err "download failed: $base_url/dl/$version/$asset"
    curl -fsSL "$base_url/dl/$version/checksums.txt" -o "$checksums" \
        || err "download failed: $base_url/dl/$version/checksums.txt"

    verify_checksum "$archive" "$asset" "$checksums"

    tar -xzf "$archive" -C "$workdir" cpass
    chmod +x "$workdir/cpass"

    mkdir -p "$install_dir"
    mv "$workdir/cpass" "$install_dir/cpass"

    installed_version="$("$install_dir/cpass" version 2>/dev/null || true)"
    [ -n "$installed_version" ] || installed_version="cpass $version"
    echo "$installed_version installed to $install_dir/cpass"
    case ":$PATH:" in
        *":$install_dir:"*) ;;
        *) echo "note: $install_dir is not on your PATH; add it to your shell profile." ;;
    esac
}

main "$@"
