package e2e

// TestDeployScriptPublishesInstallScript guards against a regression found
// during the claudepass.com launch (CLA-41 wiring stage): install.sh lives
// at the repo root (so internal/e2e/install_test.go can exercise the exact
// file a user's `curl .../install.sh | sh` runs), but deploy/deploy.sh only
// ever rsynced site/ to the server. install.sh is not under site/, so it
// was never published — https://claudepass.com/install.sh 404'd in
// production even though README.md, site/install/index.html, and
// docs/SECURITY.md all advertise it as the install command. This test
// fails the day that rsync step is removed or renamed, rather than relying
// on someone noticing a live 404.
import (
	"regexp"
	"strings"
	"testing"
)

func TestDeployScriptPublishesInstallScript(t *testing.T) {
	script := readRepoFile(t, "deploy/deploy.sh")

	// A step that rsyncs the repo-root install.sh to some remote path
	// ending in "site/install.sh" — not merely mentioning the filename in
	// a comment (docs/SECURITY.md's comment about install.sh, for
	// instance, doesn't count).
	re := regexp.MustCompile(`(?m)^\s*rsync\s+[^\n]*\binstall\.sh\b[^\n]*site/install\.sh`)
	if !re.MatchString(script) {
		t.Fatal("deploy/deploy.sh has no rsync step publishing install.sh to <remote>/site/install.sh — " +
			"https://claudepass.com/install.sh will 404 even though the file is in git")
	}

	// It must be the repo-root install.sh (the file install_test.go
	// exercises), not some other copy — the source argument should be a
	// bare "install.sh", not e.g. "site/install.sh".
	if strings.Contains(script, "rsync -az site/install.sh") {
		t.Fatal("deploy.sh should publish the repo-root install.sh, not a copy already living under site/")
	}
}
