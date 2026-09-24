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
# Verification (CLA-79, see docs/SECURITY.md "Verifying a release"):
#   1. same-origin sha256 — the archive's checksum matches the entry in
#      claudepass.com's own checksums.txt. Always done; the baseline this
#      script has always had.
#   2. cross-origin checksum — that same checksums.txt is byte-identical
#      to the copy GoReleaser uploaded straight to the GitHub Release, an
#      independent origin claudepass.com's own deploy pipeline cannot
#      touch. Always attempted; a *mismatch* is refused outright (the
#      install aborts) since two origins disagreeing on the same file is
#      exactly what a compromised mirror looks like. GitHub being
#      unreachable is a different, non-fatal condition — see below.
#   3. cosign signature — checksums.txt's keyless Sigstore signature
#      (produced by release.yml's `cosign sign-blob`, fetched from the
#      same GitHub Release), verified when `cosign` is on PATH.
#   4. build-provenance attestation — the downloaded archive itself,
#      checked against GitHub's attestation store (populated by
#      release.yml's `actions/attest-build-provenance`) with
#      `gh attestation verify`, when `gh` is on PATH.
# Levels 3 and 4 are opportunistic supply-chain hardening, like Redaction
# in the cpass binary itself (docs/SECURITY.md): best-effort, not a
# guarantee. Their tool being absent, or a signature/attestation not yet
# existing for an older release, is reported and does not block install —
# only an actual, found-and-checked mismatch at level 2 does. Whatever was
# actually achieved is printed before install finishes.
#
# Env vars (all optional):
#   CPASS_VERSION       "latest" or an explicit tag, e.g. v0.1.2 (default latest)
#   CPASS_INSTALL_DIR   where to put the binary (default: see pick_install_dir)
#   CPASS_BASE_URL      override the download origin entirely — for a
#                       mirror, or for testing against a local fixture
#                       server. When set, the asset and checksums.txt are
#                       fetched from "$CPASS_BASE_URL/dl/<version>/..." with
#                       no authentication.
#   CPASS_GITHUB_URL    override the origin level 3/4 above cross-check
#                       against (default https://github.com/<owner>/<repo>)
#                       — for testing against a local fixture server, same
#                       idea as CPASS_BASE_URL.
#   CPASS_SKIP_SIGNATURE_VERIFY
#                       any non-empty value skips levels 3 and 4 entirely
#                       (cosign/gh attestation checks make real network
#                       calls to GitHub/Sigstore, so this exists for
#                       air-gapped installs and for this script's own
#                       offline test suite). Level 2's cross-origin
#                       checksum check is unaffected — it degrades to a
#                       note-and-continue on its own when GitHub can't be
#                       reached, with no separate opt-out needed.
#
# CI / tests: `CPASS_INSTALL_DIR=$(mktemp -d) sh install.sh` installs into a
# temp prefix instead of touching the real system paths.

set -eu

version="${CPASS_VERSION:-latest}"
base_url="${CPASS_BASE_URL:-https://claudepass.com}"

# The GitHub Release copy install.sh cross-checks against (levels 2-4
# above). Hardcoded, like .goreleaser.yaml's own release.github block and
# release.yml — this is the one repo cpass's release pipeline actually
# publishes to, not something a mirror should be able to redirect.
gh_owner="Elixion-ai"
gh_repo="claudepass"
github_base="${CPASS_GITHUB_URL:-https://github.com/$gh_owner/$gh_repo}"

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

# github_dl_url NAME — the GitHub Release download URL for a same-named
# asset (checksums.txt, checksums.txt.sigstore.json, ...) of the resolved $version,
# under $github_base. Mirrors GitHub's own two URL shapes: the "latest"
# alias redirects to whatever tag is newest, an explicit tag addresses it
# directly — same distinction install.sh's own /dl/ fetches already make.
github_dl_url() {
    gh_asset="$1"
    if [ "$version" = "latest" ]; then
        printf '%s/releases/latest/download/%s' "$github_base" "$gh_asset"
    else
        printf '%s/releases/download/%s/%s' "$github_base" "$version" "$gh_asset"
    fi
}

# verify_cross_origin CHECKSUMS WORKDIR — level 2. Fetches the GitHub
# Release's own checksums.txt and compares it byte-for-byte against the
# one already verified same-origin. A real mismatch aborts the install
# (err, fail closed); GitHub being unreachable at all — offline, a
# firewalled network, a fixture test that doesn't mock this route — is
# reported and skipped rather than treated as a security failure, since
# "can't reach a second origin" and "two origins disagree" are different
# conditions and only the second one is evidence of tampering.
cross_origin_status="skipped (could not reach GitHub Releases)"
verify_cross_origin() {
    checksums="$1" workdir="$2"
    ghsum="$workdir/checksums.txt.github"
    url="$(github_dl_url checksums.txt)"
    if curl -fsSL "$url" -o "$ghsum" 2>/dev/null; then
        if cmp -s "$checksums" "$ghsum"; then
            cross_origin_status="ok (matches $github_base)"
        else
            err "checksums.txt from $base_url disagrees with the GitHub Release copy at $url — refusing to install (possible compromised mirror); see docs/SECURITY.md"
        fi
    else
        echo "note: could not reach $url to cross-check checksums.txt against GitHub Releases; continuing with same-origin verification only" >&2
    fi
}

# verify_signature CHECKSUMS ARCHIVE WORKDIR — levels 3 and 4. Opportunistic:
# each check runs only if its tool is on PATH, and neither one blocks
# install on its own (see the header comment above for why).
signature_status="unavailable (cosign not installed)"
attestation_status="unavailable (gh not installed)"
verify_signature() {
    checksums="$1" archive="$2" workdir="$3"

    if [ -n "${CPASS_SKIP_SIGNATURE_VERIFY:-}" ]; then
        signature_status="skipped (CPASS_SKIP_SIGNATURE_VERIFY set)"
        attestation_status="skipped (CPASS_SKIP_SIGNATURE_VERIFY set)"
        return
    fi

    if have cosign; then
        bundle="$workdir/checksums.txt.sigstore.json"
        cosign_err="$workdir/cosign.stderr"
        bundle_url="$(github_dl_url checksums.txt.sigstore.json)"
        if curl -fsSL "$bundle_url" -o "$bundle" 2>/dev/null; then
            if cosign verify-blob \
                --certificate-identity-regexp "^https://github\\.com/${gh_owner}/${gh_repo}/" \
                --certificate-oidc-issuer https://token.actions.githubusercontent.com \
                --bundle "$bundle" \
                "$checksums" >/dev/null 2>"$cosign_err"; then
                signature_status="verified (cosign, keyless/Sigstore)"
            elif grep -qi "unknown flag\|could not parse\|unsupported bundle\|unmarshal" "$cosign_err"; then
                # A cosign too old to read a Sigstore bundle says nothing
                # about the download itself.
                signature_status="unavailable (installed cosign cannot read Sigstore bundles; upgrade cosign)"
            else
                signature_status="FAILED (cosign could not verify checksums.txt's signature)"
                echo "warning: cosign could not verify checksums.txt's signature — the download may be tampered; see docs/SECURITY.md" >&2
            fi
        else
            signature_status="unavailable (no published signature for $version)"
        fi
    fi

    if have gh; then
        gh_err="$workdir/gh-attestation.stderr"
        # --owner and --repo are mutually exclusive to gh, and --repo takes
        # "<owner>/<repo>", not a bare repo name — pass only the combined
        # form, the same identity the cosign branch above pins with
        # --certificate-identity-regexp.
        if gh attestation verify "$archive" --repo "$gh_owner/$gh_repo" >/dev/null 2>"$gh_err"; then
            attestation_status="verified (gh attestation, build provenance)"
        elif grep -qi "no attestations found\|HTTP 404" "$gh_err"; then
            # gh's own wording for "nothing to check yet" — an older
            # release cut before CLA-79, or a repo/artifact gh has never
            # seen an attestation for. Not evidence of tampering.
            attestation_status="unavailable (no matching attestation found for $version)"
        else
            # Any other failure — including "found an attestation but it
            # didn't verify against this archive" — is a real problem, not
            # "this release predates the feature". Report it as such,
            # mirroring signature_status's FAILED case above.
            attestation_status="FAILED (gh attestation could not verify build provenance)"
            echo "warning: gh attestation could not verify $archive's build provenance — the download may be tampered; see docs/SECURITY.md" >&2
        fi
    fi
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
    verify_cross_origin "$checksums" "$workdir"
    verify_signature "$checksums" "$archive" "$workdir"

    tar -xzf "$archive" -C "$workdir" cpass
    chmod +x "$workdir/cpass"

    mkdir -p "$install_dir"
    mv "$workdir/cpass" "$install_dir/cpass"

    installed_version="$("$install_dir/cpass" version 2>/dev/null || true)"
    [ -n "$installed_version" ] || installed_version="cpass $version"
    echo "$installed_version installed to $install_dir/cpass"
    echo "verification: sha256 (same-origin) + cross-origin checksum: $cross_origin_status + cosign signature: $signature_status + attestation: $attestation_status"
    case ":$PATH:" in
        *":$install_dir:"*) ;;
        *) echo "note: $install_dir is not on your PATH; add it to your shell profile." ;;
    esac
}

main "$@"
