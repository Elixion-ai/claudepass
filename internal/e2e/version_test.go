package e2e

// Confirms the exact mechanism .goreleaser.yaml relies on: building cmd/cpass
// with -ldflags "-X claudepass/internal/cli.Version=..." (CLA-16) actually
// changes what `cpass version` prints, and that an unflagged build falls
// back to "dev" rather than silently printing an empty string.

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionIsInjectedAtBuildTime(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "cpass")
	cmd := exec.Command("go", "build",
		"-ldflags", "-X claudepass/internal/cli.Version=1.2.3-test",
		"-o", bin, "claudepass/cmd/cpass")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build with injected version: %v: %s", err, out)
	}

	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("cpass version: %v: %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "cpass 1.2.3-test" {
		t.Fatalf("cpass version = %q, want %q", got, "cpass 1.2.3-test")
	}

	// --version is documented as an alias in cli.go's usage path.
	out, err = exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("cpass --version: %v: %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "cpass 1.2.3-test" {
		t.Fatalf("cpass --version = %q, want %q", got, "cpass 1.2.3-test")
	}
}

func TestVersionDefaultsToDevWithoutLdflags(t *testing.T) {
	bin := buildRelease(t)
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("cpass version: %v: %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "cpass dev" {
		t.Fatalf("cpass version = %q, want %q", got, "cpass dev")
	}
}
