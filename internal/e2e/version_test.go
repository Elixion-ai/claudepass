package e2e

// Confirms the exact mechanism .goreleaser.yaml relies on: building cmd/cpass
// with -ldflags "-X github.com/Elixion-ai/claudepass/internal/cli.Version=..." (CLA-16) actually
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
		"-ldflags", "-X github.com/Elixion-ai/claudepass/internal/cli.Version=1.2.3-test",
		"-o", bin, "github.com/Elixion-ai/claudepass/cmd/cpass")
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

// TestVersionNeverPrintsBlankWithoutLdflags is CLA-81's e2e companion to
// internal/cli's TestVersionFallsBackToBuildInfo (which exercises
// effectiveVersion's fallback logic directly, with a faked build info, so
// it doesn't depend on this process's own VCS state). An unflagged build
// must never print a bare "cpass " with nothing after it — and, since Go
// itself auto-embeds VCS info for a build run inside a git checkout like
// this one, buildRelease's plain `go build` now typically reports a real
// git-derived pseudo-version here rather than the old hardcoded "dev": this
// only pins the one thing that holds regardless of the environment's VCS
// info (a checkout with no tags, a shallow clone, -buildvcs=false, ...),
// which is that the version is never silently empty.
func TestVersionNeverPrintsBlankWithoutLdflags(t *testing.T) {
	bin := buildRelease(t)
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("cpass version: %v: %s", err, out)
	}
	got := strings.TrimSpace(string(out))
	if !strings.HasPrefix(got, "cpass ") || got == "cpass " {
		t.Fatalf("cpass version = %q, want \"cpass <something>\"", got)
	}
}
