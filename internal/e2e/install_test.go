package e2e

// Exercises install.sh (the curl-installer at repo root, CLA-16) against a
// local fixture HTTP server standing in for claudepass.com's /dl/ release
// mirror, so it runs offline. It drives the actual shell script, the same
// boundary a user's "curl -fsSL https://claudepass.com/install.sh | sh"
// invokes, using the script's CPASS_BASE_URL/CPASS_INSTALL_DIR escape
// hatches documented at the top of install.sh for exactly this purpose.

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

func TestInstallShInstallsIntoTempPrefix(t *testing.T) {
	scriptPath, err := filepath.Abs("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("install.sh not found at %s: %v", scriptPath, err)
	}

	const tag = "v9.9.9"
	asset := fmt.Sprintf("cpass_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	wantOutput := "cpass v9.9.9-test\n"

	archive := fixtureArchive(t, wantOutput)
	checksums := fixtureChecksums(asset, archive)

	mux := http.NewServeMux()
	mux.HandleFunc("/dl/"+tag+"/"+asset, func(w http.ResponseWriter, r *http.Request) {
		w.Write(archive)
	})
	mux.HandleFunc("/dl/"+tag+"/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write(checksums)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	installDir := t.TempDir()
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = append(os.Environ(),
		"CPASS_BASE_URL="+srv.URL,
		"CPASS_VERSION="+tag,
		"CPASS_INSTALL_DIR="+installDir,
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
	scriptPath, err := filepath.Abs("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}

	const tag = "v9.9.9"
	asset := fmt.Sprintf("cpass_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	archive := fixtureArchive(t, "cpass v9.9.9-test\n")
	// A checksums.txt whose entry does not match the served archive — a
	// tampered or corrupted download must be refused, not installed.
	badChecksums := []byte(strings.Repeat("0", 64) + "  " + asset + "\n")

	mux := http.NewServeMux()
	mux.HandleFunc("/dl/"+tag+"/"+asset, func(w http.ResponseWriter, r *http.Request) {
		w.Write(archive)
	})
	mux.HandleFunc("/dl/"+tag+"/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write(badChecksums)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	installDir := t.TempDir()
	cmd := exec.Command("sh", scriptPath)
	cmd.Env = append(os.Environ(),
		"CPASS_BASE_URL="+srv.URL,
		"CPASS_VERSION="+tag,
		"CPASS_INSTALL_DIR="+installDir,
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
