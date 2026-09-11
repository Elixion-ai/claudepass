package run

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"claudepass/internal/broker"
	"claudepass/internal/vault"
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
