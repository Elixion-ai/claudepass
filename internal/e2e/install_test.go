package e2e

// Exercises install.sh (the curl-installer at repo root, CLA-16) against
// local fixture HTTP servers standing in for claudepass.com's /dl/ release
// mirror and, since CLA-79, the GitHub Release copy install.sh
// cross-checks checksums.txt against — so it runs offline. It drives the
// actual shell script, the same boundary a user's
// "curl -fsSL https://claudepass.com/install.sh | sh" invokes, using the
// script's CPASS_BASE_URL/CPASS_GITHUB_URL/CPASS_INSTALL_DIR escape
// hatches documented at the top of install.sh for exactly this purpose.
// Every test here also sets CPASS_SKIP_SIGNATURE_VERIFY=1: the cosign and
// `gh attestation verify` checks (CLA-79 levels 3-4) are opportunistic and
// would otherwise reach out to the real Sigstore/GitHub APIs for an
// object that only exists in these fixtures — see install.sh's own header
// comment for why that's a separate, always-available opt-out from the
// cross-origin checksum check the tests below exercise directly.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// installShPath resolves the repo-root install.sh under test, the same
// file every doc/README one-liner (and deploy.sh's own publish step)
// eventually serves verbatim.
func installShPath(t *testing.T) string {
	t.Helper()
	scriptPath, err := filepath.Abs("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("install.sh not found at %s: %v", scriptPath, err)
	}
	return scriptPath
}

// dlFixtureServer stands in for claudepass.com's own /dl/ mirror: it
// serves archive at /dl/<tag>/<asset> and checksums at
// /dl/<tag>/checksums.txt.
func dlFixtureServer(t *testing.T, tag, asset string, archive, checksums []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/dl/"+tag+"/"+asset, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive) // best-effort: a failed write makes the test client fail downstream anyway
	})
	mux.HandleFunc("/dl/"+tag+"/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(checksums) // best-effort, see above
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// ghFixtureServer stands in for the GitHub Release copy install.sh
// cross-checks checksums.txt against (CLA-79, level 2): it serves
// checksums at the same path shape github_dl_url builds,
// /releases/download/<tag>/checksums.txt.
func ghFixtureServer(t *testing.T, tag string, checksums []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/download/"+tag+"/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(checksums) // best-effort, see above
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// closedServer returns a URL nothing is listening on — deterministically
// unreachable, unlike relying on real internet access, for exercising
// install.sh's "GitHub is unreachable" note-and-continue path (as opposed
// to the "GitHub answered and disagrees" hard-fail path) without an actual
// network dependency in the test suite.
func closedServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // closed immediately: connections to its URL now refuse
	return srv.URL
}

func TestInstallShInstallsIntoTempPrefix(t *testing.T) {
	scriptPath := installShPath(t)

	const tag = "v9.9.9"
	asset := fmt.Sprintf("cpass_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	wantOutput := "cpass v9.9.9-test\n"

	archive := fixtureArchive(t, wantOutput)
	checksums := fixtureChecksums(asset, archive)

	dlSrv := dlFixtureServer(t, tag, asset, archive, checksums)
	// The GitHub Release copy matches — cross-origin verification (level
	// 2) should pass silently rather than blocking install.
	ghSrv := ghFixtureServer(t, tag, checksums)

	installDir := t.TempDir()
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = append(os.Environ(),
		"CPASS_BASE_URL="+dlSrv.URL,
		"CPASS_GITHUB_URL="+ghSrv.URL,
		"CPASS_VERSION="+tag,
		"CPASS_INSTALL_DIR="+installDir,
		// cosign/gh attestation verification (levels 3-4) would make real
		// calls to Sigstore/GitHub's API for an object that only exists in
		// this test's fixture servers; skip them here the same way a truly
		// air-gapped install would (see install.sh's own header comment).
		// The cross-origin checksum check above is unaffected by this.
		"CPASS_SKIP_SIGNATURE_VERIFY=1",
	)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("install.sh failed: %v\nstdout: %s\nstderr: %s", err, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), installDir) {
		t.Errorf("install.sh should report the install dir, got: %s", out.String())
	}
	if !strings.Contains(out.String(), wantOutput[:len(wantOutput)-1]) {
		t.Errorf("install.sh should report the installed version, got: %s", out.String())
	}
	if !strings.Contains(out.String(), "cross-origin checksum: ok") {
		t.Errorf("install.sh should report the cross-origin checksum as ok, got: %s", out.String())
	}
	if !strings.Contains(out.String(), "cosign signature: skipped") || !strings.Contains(out.String(), "attestation: skipped") {
		t.Errorf("install.sh should report signature/attestation as skipped when CPASS_SKIP_SIGNATURE_VERIFY is set, got: %s", out.String())
	}

	binPath := filepath.Join(installDir, "cpass")
	info, err := os.Stat(binPath)
	if err != nil {
		t.Fatalf("cpass was not installed: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("installed cpass is not executable: %v", info.Mode())
	}

	ranOut, err := exec.Command(binPath).CombinedOutput()
	if err != nil {
		t.Fatalf("running installed cpass: %v: %s", err, ranOut)
	}
	if string(ranOut) != wantOutput {
		t.Fatalf("installed cpass printed %q, want %q", ranOut, wantOutput)
	}
}

func TestInstallShFailsOnChecksumMismatch(t *testing.T) {
	scriptPath := installShPath(t)

	const tag = "v9.9.9"
	asset := fmt.Sprintf("cpass_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	archive := fixtureArchive(t, "cpass v9.9.9-test\n")
	// A checksums.txt whose entry does not match the served archive — a
	// tampered or corrupted download must be refused, not installed.
	badChecksums := []byte(strings.Repeat("0", 64) + "  " + asset + "\n")

	dlSrv := dlFixtureServer(t, tag, asset, archive, badChecksums)

	installDir := t.TempDir()
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = append(os.Environ(),
		"CPASS_BASE_URL="+dlSrv.URL,
		"CPASS_GITHUB_URL="+closedServer(t), // never reached: same-origin fails first
		"CPASS_VERSION="+tag,
		"CPASS_INSTALL_DIR="+installDir,
		"CPASS_SKIP_SIGNATURE_VERIFY=1",
	)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected install.sh to fail on a checksum mismatch, stderr: %s", errb.String())
	}
	if !strings.Contains(errb.String(), "checksum mismatch") {
		t.Fatalf("expected a checksum mismatch error, got: %s", errb.String())
	}
	if _, err := os.Stat(filepath.Join(installDir, "cpass")); err == nil {
		t.Fatalf("cpass should not be installed after a checksum mismatch")
	}
}

// TestInstallShFailsOnCrossOriginChecksumMismatch is CLA-79's core new
// regression: a same-origin-valid (archive, checksums.txt) pair from a
// compromised claudepass.com mirror must still be refused when it
// disagrees with the independent copy GoReleaser uploaded straight to the
// GitHub Release — this is exactly the attack install.sh could not detect
// before this ticket (a consistent trojaned pair from one compromised
// origin used to pass verification outright).
func TestInstallShFailsOnCrossOriginChecksumMismatch(t *testing.T) {
	scriptPath := installShPath(t)

	const tag = "v9.9.9"
	asset := fmt.Sprintf("cpass_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	archive := fixtureArchive(t, "cpass v9.9.9-test\n")
	checksums := fixtureChecksums(asset, archive) // matches the archive: same-origin check passes

	dlSrv := dlFixtureServer(t, tag, asset, archive, checksums)
	// The GitHub Release copy is for a *different* archive entirely — as
	// if the claudepass.com mirror were compromised and serving a
	// consistent trojaned pair that, on its own, verifies perfectly.
	otherChecksums := fixtureChecksums(asset, fixtureArchive(t, "cpass v9.9.9-trojan\n"))
	ghSrv := ghFixtureServer(t, tag, otherChecksums)

	installDir := t.TempDir()
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = append(os.Environ(),
		"CPASS_BASE_URL="+dlSrv.URL,
		"CPASS_GITHUB_URL="+ghSrv.URL,
		"CPASS_VERSION="+tag,
		"CPASS_INSTALL_DIR="+installDir,
		"CPASS_SKIP_SIGNATURE_VERIFY=1",
	)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected install.sh to fail on a cross-origin checksums.txt mismatch, stderr: %s", errb.String())
	}
	if !strings.Contains(errb.String(), "GitHub Release") {
		t.Fatalf("expected a cross-origin/GitHub Release mismatch error, got: %s", errb.String())
	}
	if _, err := os.Stat(filepath.Join(installDir, "cpass")); err == nil {
		t.Fatalf("cpass should not be installed after a cross-origin checksum mismatch")
	}
}

// TestInstallShContinuesWhenGitHubUnreachable asserts the non-fatal side
// of level 2: GitHub being unreachable (offline, a firewalled network) is
// not treated as evidence of tampering the way an actual mismatch is —
// install proceeds on same-origin verification alone, with a clear note.
func TestInstallShContinuesWhenGitHubUnreachable(t *testing.T) {
	scriptPath := installShPath(t)

	const tag = "v9.9.9"
	asset := fmt.Sprintf("cpass_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	wantOutput := "cpass v9.9.9-test\n"
	archive := fixtureArchive(t, wantOutput)
	checksums := fixtureChecksums(asset, archive)

	dlSrv := dlFixtureServer(t, tag, asset, archive, checksums)

	installDir := t.TempDir()
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = append(os.Environ(),
		"CPASS_BASE_URL="+dlSrv.URL,
		"CPASS_GITHUB_URL="+closedServer(t),
		"CPASS_VERSION="+tag,
		"CPASS_INSTALL_DIR="+installDir,
		"CPASS_SKIP_SIGNATURE_VERIFY=1",
	)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("install.sh should still succeed when GitHub is unreachable: %v\nstdout: %s\nstderr: %s", err, out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), "could not reach") {
		t.Errorf("install.sh should note that GitHub was unreachable, got stderr: %s", errb.String())
	}
	if !strings.Contains(out.String(), "cross-origin checksum: skipped") {
		t.Errorf("install.sh should report the cross-origin checksum as skipped, got: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(installDir, "cpass")); err != nil {
		t.Fatalf("cpass should still be installed when only the cross-origin check was skipped: %v", err)
	}
}

// fixtureArchive builds a tar.gz containing one executable file, "cpass",
// a shell script that prints wantOutput — standing in for the real
// cross-compiled binary an actual release ships.
func fixtureArchive(t *testing.T, wantOutput string) []byte {
	t.Helper()
	content := []byte("#!/bin/sh\nprintf '%s'\n")
	content = []byte(strings.Replace(string(content), "%s", wantOutput, 1))

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{Name: "cpass", Mode: 0o755, Size: int64(len(content))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fixtureChecksums renders a GoReleaser-style checksums.txt entry for a
// single asset, matching the "<hex sha256>  <filename>" shape install.sh's
// verify_checksum parses.
func fixtureChecksums(asset string, archive []byte) []byte {
	sum := sha256.Sum256(archive)
	return []byte(hex.EncodeToString(sum[:]) + "  " + asset + "\n")
}
