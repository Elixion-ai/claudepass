#!/bin/sh
# ClaudePass installer.
#
#   curl -fsSL https://raw.githubusercontent.com/gumruyanzh/claudepass/main/install.sh | sh
#
# claudepass is a PRIVATE repo (ADR-0006: closed source). Downloading a
# release asset therefore needs one of, tried in this order:
#   1. the `gh` CLI, already authenticated (`gh auth status`) — no extra
#      setup, this is what the maintainer's own machine uses.
#   2. GITHUB_TOKEN in the environment, a token with read access to the
#      repo — used directly against the GitHub REST API.
#   3. neither: the script tries a plain, unauthenticated download, which
#      only succeeds if the repo/release has been made public.
#
# Env vars (all optional):
#   CPASS_REPO         owner/repo to install from  (default gumruyanzh/claudepass)
#   CPASS_VERSION       "latest" or an explicit tag, e.g. v0.1.0 (default latest)
#   CPASS_INSTALL_DIR   where to put the binary (default: see pick_install_dir)
#   GITHUB_TOKEN         a token with access to CPASS_REPO's releases
#   CPASS_BASE_URL      override the download origin entirely — for a public
#                       releases-only mirror repo, or for testing against a
#                       local fixture server. When set, the asset is fetched
#                       from "$CPASS_BASE_URL/releases/download/<tag>/<asset>"
#                       with no authentication, and CPASS_VERSION must be an
#                       explicit tag ("latest" resolution is skipped).
#
# CI / tests: `CPASS_INSTALL_DIR=$(mktemp -d) sh install.sh` installs into a
# temp prefix instead of touching the real system paths.

set -eu

repo="${CPASS_REPO:-gumruyanzh/claudepass}"
version="${CPASS_VERSION:-latest}"
base_url="${CPASS_BASE_URL:-}"

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

# json_field FILE FIELD — a tiny JSON scalar/array-of-object field reader
# with no jq/python3 dependency required, since install.sh must run on any
# box that merely has curl and a POSIX shell. Good enough for GitHub's
# release JSON shape; not a general JSON parser.
json_field() {
    grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" | head -1 | sed -E 's/.*: *"([^"]*)"/\1/'
}

# asset_id FILE NAME — id of the release asset whose "name" equals NAME,
# by scanning consecutive "id": N / "name": "..." pairs in the JSON.
asset_id() {
    awk -v want="$2" '
        /"id":/ { match($0, /[0-9]+/); id = substr($0, RSTART, RLENGTH) }
        /"name":/ {
            name = $0
            gsub(/.*"name"[[:space:]]*:[[:space:]]*"/, "", name)
            gsub(/".*/, "", name)
            if (name == want) { print id; found = 1; exit }
        }
        END { if (!found) exit 1 }
    ' "$1"
}

resolve_tag() {
    if [ -n "$base_url" ]; then
        [ "$version" = "latest" ] && err "CPASS_VERSION must be an explicit tag when CPASS_BASE_URL is set"
        echo "$version"
        return
    fi
    if [ "$version" != "latest" ]; then
        echo "$version"
        return
    fi
    if have gh && gh auth status >/dev/null 2>&1; then
        gh release view --repo "$repo" --json tagName -q .tagName
        return
    fi
    tmp="$(mktemp)"
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        curl -fsSL -H "Authorization: token $GITHUB_TOKEN" -H 'Accept: application/vnd.github+json' \
            "https://api.github.com/repos/$repo/releases/latest" -o "$tmp" \
            || err "could not resolve the latest release of $repo (check GITHUB_TOKEN has access)"
    else
        curl -fsSL "https://api.github.com/repos/$repo/releases/latest" -o "$tmp" \
            || err "could not resolve the latest release of $repo. $repo is private; set GITHUB_TOKEN or authenticate 'gh', then retry."
    fi
    tag="$(json_field "$tmp" tag_name)"
    rm -f "$tmp"
    [ -n "$tag" ] || err "could not read a tag_name from the releases/latest response"
    echo "$tag"
}

download_asset() {
    tag="$1" asset="$2" dest="$3"

    if [ -n "$base_url" ]; then
        curl -fsSL "$base_url/releases/download/$tag/$asset" -o "$dest" && return
        err "download failed: $base_url/releases/download/$tag/$asset"
    fi

    if have gh && gh auth status >/dev/null 2>&1; then
        gh release download "$tag" --repo "$repo" --pattern "$asset" --output "$dest" --clobber && return
        err "gh release download failed for $repo@$tag ($asset)"
    fi

    if [ -n "${GITHUB_TOKEN:-}" ]; then
        meta="$(mktemp)"
        curl -fsSL -H "Authorization: token $GITHUB_TOKEN" -H 'Accept: application/vnd.github+json' \
            "https://api.github.com/repos/$repo/releases/tags/$tag" -o "$meta" \
            || err "could not fetch release metadata for $repo@$tag"
        id="$(asset_id "$meta" "$asset")" || err "no asset named $asset in $repo@$tag"
        rm -f "$meta"
        curl -fsSL -H "Authorization: token $GITHUB_TOKEN" -H 'Accept: application/octet-stream' \
            "https://api.github.com/repos/$repo/releases/assets/$id" -o "$dest" && return
        err "asset download failed: $repo@$tag asset id $id"
    fi

    # Last resort: works only if the repo/release is public.
    curl -fsSL "https://github.com/$repo/releases/download/$tag/$asset" -o "$dest" && return
    err "$repo is private and no 'gh' auth or GITHUB_TOKEN was found. Either: \
export GITHUB_TOKEN=\$(gh auth token) (or any token with read access to $repo), \
or run 'gh auth login' first."
}

main() {
    os="$(detect_os)"
    arch="$(detect_arch)"
    asset="cpass_${os}_${arch}.tar.gz"
    install_dir="$(pick_install_dir)"

    tag="$(resolve_tag)"
    workdir="$(mktemp -d)"
    trap 'rm -rf "$workdir"' EXIT

    archive="$workdir/$asset"
    download_asset "$tag" "$asset" "$archive"

    tar -xzf "$archive" -C "$workdir" cpass
    chmod +x "$workdir/cpass"

    mkdir -p "$install_dir"
    mv "$workdir/cpass" "$install_dir/cpass"

    echo "cpass $tag installed to $install_dir/cpass"
    case ":$PATH:" in
        *":$install_dir:"*) ;;
        *) echo "note: $install_dir is not on your PATH; add it to your shell profile." ;;
    esac
}

main "$@"
