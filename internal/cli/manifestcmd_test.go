package cli

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Elixion-ai/claudepass/internal/broker"
	"github.com/Elixion-ai/claudepass/internal/manifest"
	"github.com/Elixion-ai/claudepass/internal/vault"
)

// manifestTestEnv sets CPASS_HOME to a fresh temp directory, creates a Vault
// there under a fixed CPASS_KEY, and returns it ready for v.Add/v.Save.
// Every manifestcmd_test.go case points at its own home, so nothing reads
// or writes a developer's real Vault or Global Manifest.
func manifestTestEnv(t *testing.T) *vault.Vault {
	t.Helper()
	home := t.TempDir()
	t.Setenv(broker.EnvHome, home)
	key := bytes.Repeat([]byte{0x24}, vault.KeySize)
	t.Setenv(broker.EnvKey, base64.StdEncoding.EncodeToString(key))
	vp, err := broker.VaultPath()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Create(vp, key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func runManifest(e *env, args ...string) int {
	e.args = args
	return cmdManifest(e)
}

// TestManifestCheckEffectiveReportsGlobalOverridesAndMissing is the
// regression test for CLA-95: cpass manifest check --effective must show
// the union manifest.Refs actually computes — a Global-only Handle tagged
// GLOBAL, a project Entry that replaces a reachable Global default tagged
// OVERRIDES-GLOBAL, an ordinary project-only Entry with no tag, and any
// unresolvable Handle tagged MISSING with a non-zero exit — rather than
// auditing one file's Entries in isolation the way a plain `manifest check`
// does.
func TestManifestCheckEffectiveReportsGlobalOverridesAndMissing(t *testing.T) {
	v := manifestTestEnv(t)
	for _, h := range []string{"openai/key", "stripe/live", "db/url"} {
		if _, err := v.Add(h, h+"-value-xyzxyzxyz", vault.AddOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}

	gm, err := manifest.LoadGlobal()
	if err != nil {
		t.Fatal(err)
	}
	gm.Add(manifest.Entry{Handle: "openai/key"})
	gm.Add(manifest.Entry{Handle: "stripe/live", Binding: vault.Binding{Name: "FROM_GLOBAL"}})
	if err := gm.SaveGlobal(); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	t.Chdir(root)
	pm := &manifest.Manifest{Path: filepath.Join(root, manifest.FileName)}
	pm.Add(manifest.Entry{Handle: "stripe/live", Binding: vault.Binding{Name: "FROM_PROJECT"}})
	pm.Add(manifest.Entry{Handle: "db/url"})
	pm.Add(manifest.Entry{Handle: "sendgrid/key"}) // never stored: must report MISSING
	if err := pm.Save(); err != nil {
		t.Fatal(err)
	}

	e, out, errb := newPlainEnv()
	code := runManifest(e, "check", "--effective")
	if code != ExitError {
		t.Fatalf("code = %d, want ExitError (%d); stdout=%s stderr=%s", code, ExitError, out, errb)
	}
	stdout := out.String()

	openaiLine := grepLine(t, stdout, "openai/key")
	if !strings.Contains(openaiLine, "GLOBAL") || strings.Contains(openaiLine, "OVERRIDES-GLOBAL") {
		t.Fatalf("global-only handle must be tagged GLOBAL, not OVERRIDES-GLOBAL: %q", openaiLine)
	}
	if strings.Contains(openaiLine, "MISSING") {
		t.Fatalf("openai/key is in the Vault, must not be MISSING: %q", openaiLine)
	}

	stripeLine := grepLine(t, stdout, "stripe/live")
	if !strings.Contains(stripeLine, "OVERRIDES-GLOBAL") {
		t.Fatalf("project's own Entry must be tagged OVERRIDES-GLOBAL: %q", stripeLine)
	}
	if !strings.Contains(stripeLine, "FROM_PROJECT") || strings.Contains(stripeLine, "FROM_GLOBAL") {
		t.Fatalf("the project's own Binding must win, not the Global one: %q", stripeLine)
	}

	dbLine := grepLine(t, stdout, "db/url")
	if strings.Contains(dbLine, "GLOBAL") || strings.Contains(dbLine, "MISSING") {
		t.Fatalf("an ordinary project-only Entry must carry no Global tag and be available: %q", dbLine)
	}

	sendgridLine := grepLine(t, stdout, "sendgrid/key")
	if !strings.Contains(sendgridLine, "MISSING") {
		t.Fatalf("a Handle absent from the Vault must be tagged MISSING: %q", sendgridLine)
	}
	if !strings.Contains(errb.String(), "1 of 4 effective handle(s) missing") {
		t.Fatalf("stderr summary: %q", errb.String())
	}
}

// grepLine returns the one line of out naming needle, failing the test if
// there isn't exactly one.
func grepLine(t *testing.T, out, needle string) string {
	t.Helper()
	var found string
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			found = line
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly one line naming %q, got %d in:\n%s", needle, n, out)
	}
	return found
}

// TestManifestCheckEffectiveAllAvailable is the all-ok path: every Handle
// the union resolves — Global and project alike — is in the Vault, so the
// command reports each line and exits ExitOK with the summary grammar
// `manifest check` itself uses ("ok: all N ... are available").
func TestManifestCheckEffectiveAllAvailable(t *testing.T) {
	v := manifestTestEnv(t)
	if _, err := v.Add("openai/key", "openai-value-xyzxyzxyz", vault.AddOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	gm, err := manifest.LoadGlobal()
	if err != nil {
		t.Fatal(err)
	}
	gm.Add(manifest.Entry{Handle: "openai/key"})
	if err := gm.SaveGlobal(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Chdir(root)
	pm := &manifest.Manifest{Path: filepath.Join(root, manifest.FileName)}
	if err := pm.Save(); err != nil {
		t.Fatal(err)
	}

	e, out, errb := newPlainEnv()
	code := runManifest(e, "check", "--effective")
	if code != ExitOK {
		t.Fatalf("code = %d, want ExitOK; stdout=%s stderr=%s", code, out, errb)
	}
	if !strings.Contains(out.String(), "ok: all 1 effective handle(s)") {
		t.Fatalf("stdout: %q", out.String())
	}
}

// TestManifestCheckEffectiveRejectsGlobalFlag: -g means "check the Global
// Manifest instead of this project's", which --effective (always the
// project's own union view) cannot combine with.
func TestManifestCheckEffectiveRejectsGlobalFlag(t *testing.T) {
	manifestTestEnv(t)
	root := t.TempDir()
	t.Chdir(root)
	e, _, errb := newPlainEnv()
	code := runManifest(e, "check", "--effective", "-g")
	if code != ExitUsage {
		t.Fatalf("code = %d, want ExitUsage; stderr=%s", code, errb)
	}
	if !strings.Contains(errb.String(), "mutually exclusive") {
		t.Fatalf("stderr: %q", errb.String())
	}
}

// TestManifestCheckEffectiveNeedsAProjectManifest matches the plain
// `manifest check` behaviour: with no .claudepass.toml found here or above,
// the command fails with the same ErrNotFound message rather than silently
// reporting zero effective Handles.
func TestManifestCheckEffectiveNeedsAProjectManifest(t *testing.T) {
	manifestTestEnv(t)
	t.Chdir(t.TempDir())
	e, _, errb := newPlainEnv()
	code := runManifest(e, "check", "--effective")
	if code != ExitError {
		t.Fatalf("code = %d, want ExitError; stderr=%s", code, errb)
	}
	if !strings.Contains(errb.String(), "no "+manifest.FileName+" found") {
		t.Fatalf("stderr: %q", errb.String())
	}
}

// TestManifestInitWarnsAtABroadRoot is the regression test for CLA-96:
// `cpass manifest init` run at the caller's own home directory must warn,
// loudly but not fatally, before writing .claudepass.toml — a Manifest
// there would turn every Global Handle this machine ever declares into an
// ambient default for every subdirectory beneath it.
func TestManifestInitWarnsAtABroadRoot(t *testing.T) {
	manifestTestEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(home)
	e, out, errb := newPlainEnv()
	code := runManifest(e, "init")
	if code != ExitOK {
		t.Fatalf("init: %d; stderr=%s", code, errb)
	}
	if !strings.Contains(errb.String(), "broad ancestor") {
		t.Fatalf("want a broad-root warning, got stderr=%q", errb.String())
	}
	if !strings.Contains(out.String(), "created ") {
		t.Fatalf("init must still succeed even with the warning: stdout=%q", out.String())
	}
}

// TestManifestInitStaysQuietForAnOrdinaryDirectory is the flip side: an
// ordinary project directory, never $HOME or /, must draw no warning at
// all — the whole point is that this stays silent for the common case.
func TestManifestInitStaysQuietForAnOrdinaryDirectory(t *testing.T) {
	manifestTestEnv(t)
	t.Chdir(t.TempDir())
	e, _, errb := newPlainEnv()
	code := runManifest(e, "init")
	if code != ExitOK {
		t.Fatalf("init: %d; stderr=%s", code, errb)
	}
	if errb.String() != "" {
		t.Fatalf("an ordinary directory must draw no warning at all: stderr=%q", errb.String())
	}
}
