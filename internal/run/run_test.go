package run

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Elixion-ai/claudepass/internal/broker"
	"github.com/Elixion-ai/claudepass/internal/vault"
)

// TestExposedReminderUsesFormatExposedWhenSet is the regression test for
// the bug where the Exposed-reminder line Run prints to Spec.Warn was
// always a hand-rolled plain Fprintf, never routed through the CLI's own
// coloured env.exposed helper (docs/CLI-STYLE.md's Colour section assigns
// the Handle ember, "Exposed" red, and the date dim grey). FormatExposed
// lets a caller (internal/cli's cmdRun/cmdCapture) supply that rendering;
// left nil, the reminder keeps today's plain wording unchanged.
func TestExposedReminderUsesFormatExposedWhenSet(t *testing.T) {
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
	if _, err := v.Add("stripe/live", "sk_live_51H8xJ2eZvKYlo2CTrunFormatExposedVALUEabc", vault.AddOptions{Exposed: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}

	run := func(format func(handle, since string) string) string {
		var stdout, stderr, warn bytes.Buffer
		code, err := Run(Spec{
			Refs:        []broker.Ref{{Handle: "stripe/live"}},
			Argv:        []string{"sh", "-c", ":"},
			UnsafeAllow: true,
			Stdout:      &stdout, Stderr: &stderr, Warn: &warn,
			FormatExposed: format,
		})
		if err != nil || code != 0 {
			t.Fatalf("Run: code=%d err=%v stderr=%s", code, err, stderr.String())
		}
		return warn.String()
	}

	plain := run(nil)
	wantPlain := "cpass: stripe/live is Exposed since test, rotate it\n"
	// since is "an unknown date" unless ExposedAt is set; Add with Exposed
	// via AddOptions does set an Exposures entry with At=now, so assert on
	// the stable parts instead of the date.
	if !strings.Contains(plain, "cpass: stripe/live is Exposed since ") || !strings.HasSuffix(plain, ", rotate it\n") {
		t.Fatalf("FormatExposed=nil: got %q, want default plain wording (like %q)", plain, wantPlain)
	}

	coloured := run(func(handle, since string) string {
		return "COLOURED(" + handle + "," + since + ")"
	})
	if !strings.HasPrefix(coloured, "COLOURED(stripe/live,") || !strings.HasSuffix(coloured, ")\n") {
		t.Fatalf("FormatExposed set: got %q, want it to route the reminder through the supplied formatter", coloured)
	}
}

// TestNewRunDirTightensExistingRunParentPermissions covers CLA-58: the
// shared run/ parent directory under CPASS_HOME
// (runRoot: $CPASS_HOME/run/) must be tightened to 0700 even when it
// already exists (e.g. left at 0755 by a stray umask, or an install that
// predates this hardening), matching the same fix already applied to
// CPASS_HOME itself (vault.Save), the passphrase salt/kdf directory, and
// the Broker socket directory. MkdirAll is a no-op on a directory that
// already exists, regardless of its current mode, so without an explicit
// chmod a loosened run/ parent stays loosened forever, letting another
// local user list the names (though not the contents — each per-invocation
// subdirectory is still always freshly created at 0700) of currently-live
// file-Binding directories.
func TestNewRunDirTightensExistingRunParentPermissions(t *testing.T) {
	home := t.TempDir()
	t.Setenv(broker.EnvHome, home)
	root := filepath.Join(home, "run")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}

	d, err := newRunDir()
	if err != nil {
		t.Fatalf("newRunDir: %v", err)
	}
	defer d.destroy()

	st, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("run/ parent mode = %v, want 0700", st.Mode().Perm())
	}
}

// TestRunRegistersCpassKeyPatternWithEmptyRefs is CLA-54's regression test
// for the capture-surface gap: `cpass capture` (internal/cli/capturecmd.go)
// and the MCP `capture` tool (internal/mcp/tools.go callCapture) both open
// the Vault themselves, via their own separate broker.OpenVault() call,
// before Run ever runs, and Refs stays empty in the common case (capture
// only ever populates Refs from --with, and the MCP tool has no
// --with-equivalent field at all). The old guard, len(spec.Refs) > 0, used
// Refs as a proxy for "this call's own broker.Resolve opened the Vault with
// CPASS_KEY" -- a proxy that's always false on this path, so CPASS_KEY
// never got registered as a redact Pattern even though it genuinely was the
// unlock source. This pins the fix directly against Run's own Spec,
// independent of how either caller surfaces (or, for MCP capture today,
// discards) stderr -- see TestCaptureRedactsCpassKeyFromStderr (e2e, CLI)
// and TestMCPCaptureRedactsCpassKeyFromStderr (e2e, MCP) for the two real
// callers.
func TestRunRegistersCpassKeyPatternWithEmptyRefs(t *testing.T) {
	t.Setenv(broker.EnvHome, t.TempDir())
	// Deterministic regardless of the host's own CI env var: irrelevant
	// here since Refs is empty either way, but this guard is also gated on
	// !CIMode(), and the point of this test is that gate, not CI mode.
	t.Setenv(broker.EnvCI, "0")
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, vault.KeySize))
	t.Setenv(broker.EnvKey, key)

	var stdout, stderr bytes.Buffer
	script := `printf 'RAWKEY=[%s]\n' '` + key + `' 1>&2`
	code, err := Run(Spec{
		// Refs deliberately nil/empty -- see the doc comment above.
		Argv:        []string{"sh", "-c", script},
		UnsafeAllow: true,
		Stdout:      &stdout, Stderr: &stderr,
	})
	if err != nil || code != 0 {
		t.Fatalf("Run: code=%d err=%v stderr=%s", code, err, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), key) {
		t.Fatalf("CPASS_KEY value leaked with Refs empty: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "[REDACTED:cpass/vault-key]") {
		t.Fatalf("CPASS_KEY marker missing with Refs empty: stderr=%q", stderr.String())
	}
}
