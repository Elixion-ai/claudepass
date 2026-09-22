package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIntegrateCodexRemove is CLA-78's acceptance case for `cpass integrate
// codex --remove`: it must delete the delimited section it wrote (or the
// whole file when nothing else remains), leave unrelated content alone, and
// be a safe, idempotent no-op both on a file with no section and on one
// that was never created.
func TestIntegrateCodexRemove(t *testing.T) {
	t.Run("removes the whole file when the section was all there was", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "AGENTS.md")

		if code := Main([]string{"integrate", "codex", "--path", path}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != ExitOK {
			t.Fatalf("install: exit = %d", code)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("install did not create %s: %v", path, err)
		}

		var out, errb bytes.Buffer
		code := Main([]string{"integrate", "codex", "--path", path, "--remove"}, strings.NewReader(""), &out, &errb)
		if code != ExitOK {
			t.Fatalf("remove: exit = %d, stderr = %q", code, errb.String())
		}
		if !strings.Contains(out.String(), "removed "+path) {
			t.Fatalf("remove stdout = %q, want it to mention removing %s", out.String(), path)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after --remove: %v", path, err)
		}
	})

	t.Run("removes only the section when unrelated content remains", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "AGENTS.md")
		if err := os.WriteFile(path, []byte("# My Project\n\nSome unrelated setup notes.\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		if code := Main([]string{"integrate", "codex", "--path", path}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != ExitOK {
			t.Fatalf("install: exit = %d", code)
		}

		var out, errb bytes.Buffer
		code := Main([]string{"integrate", "codex", "--path", path, "--remove"}, strings.NewReader(""), &out, &errb)
		if code != ExitOK {
			t.Fatalf("remove: exit = %d, stderr = %q", code, errb.String())
		}
		remaining, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s was deleted, want it kept (unrelated content remained): %v", path, err)
		}
		if !strings.Contains(string(remaining), "Some unrelated setup notes.") {
			t.Fatalf("unrelated content not preserved: %q", remaining)
		}
		if strings.Contains(string(remaining), "ClaudePass Vault") {
			t.Fatalf("ClaudePass section not removed: %q", remaining)
		}
	})

	t.Run("is a safe no-op on a file that was never created", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "AGENTS.md")

		var out, errb bytes.Buffer
		code := Main([]string{"integrate", "codex", "--path", path, "--remove"}, strings.NewReader(""), &out, &errb)
		if code != ExitOK {
			t.Fatalf("exit = %d, stderr = %q", code, errb.String())
		}
		if errb.Len() != 0 {
			t.Fatalf("unexpected stderr %q", errb.String())
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("--remove created %s out of nothing", path)
		}
	})

	t.Run("is idempotent: a second --remove finds nothing left", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "AGENTS.md")
		if code := Main([]string{"integrate", "codex", "--path", path}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != ExitOK {
			t.Fatal("install failed")
		}
		if code := Main([]string{"integrate", "codex", "--path", path, "--remove"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != ExitOK {
			t.Fatal("first remove failed")
		}

		var out, errb bytes.Buffer
		code := Main([]string{"integrate", "codex", "--path", path, "--remove"}, strings.NewReader(""), &out, &errb)
		if code != ExitOK {
			t.Fatalf("second remove: exit = %d, stderr = %q", code, errb.String())
		}
		if errb.Len() != 0 {
			t.Fatalf("unexpected stderr %q", errb.String())
		}
	})
}

// TestIntegrateClaudeStampsPluginVersionFromCLIVersion is CLA-82's
// end-to-end regression test: plugin.json's own "version" field must track
// a tagged release, not stay frozen at whatever the embedded source file
// says. It simulates a release build the way GoReleaser's ldflags do (see
// .goreleaser.yaml) — setting the package-level Version var directly,
// since that's exactly what -X github.com/.../internal/cli.Version={{
// .Version }} does at link time — then asserts the plugin.json `cpass
// integrate claude` installs carries that same tagged version, with no
// separate release-time stamping step to keep in sync or forget.
func TestIntegrateClaudeStampsPluginVersionFromCLIVersion(t *testing.T) {
	origVersion := Version
	t.Cleanup(func() { Version = origVersion })
	Version = "v3.4.5"

	dir := t.TempDir()
	var out, errb bytes.Buffer
	code := Main([]string{"integrate", "claude", "--path", dir}, strings.NewReader(""), &out, &errb)
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %q", code, errb.String())
	}

	manifestRaw, err := os.ReadFile(filepath.Join(dir, "claudepass", ".claude-plugin", "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("plugin.json is not valid JSON: %v", err)
	}
	if manifest["version"] != "v3.4.5" {
		t.Fatalf("plugin.json version = %v, want the tagged release version v3.4.5", manifest["version"])
	}
}

// TestIntegrateClaudeRemove is CLA-78's acceptance case for `cpass
// integrate claude --remove`: it must delete the installed plugin
// directory and be a safe, idempotent no-op when nothing was installed.
func TestIntegrateClaudeRemove(t *testing.T) {
	t.Run("removes the installed plugin directory", func(t *testing.T) {
		dir := t.TempDir()

		if code := Main([]string{"integrate", "claude", "--path", dir}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != ExitOK {
			t.Fatal("install failed")
		}
		target := filepath.Join(dir, "claudepass")
		if _, err := os.Stat(target); err != nil {
			t.Fatalf("install did not create %s: %v", target, err)
		}

		var out, errb bytes.Buffer
		code := Main([]string{"integrate", "claude", "--path", dir, "--remove"}, strings.NewReader(""), &out, &errb)
		if code != ExitOK {
			t.Fatalf("remove: exit = %d, stderr = %q", code, errb.String())
		}
		if !strings.Contains(out.String(), "removed "+target) {
			t.Fatalf("remove stdout = %q, want it to mention removing %s", out.String(), target)
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after --remove: %v", target, err)
		}
	})

	t.Run("is a safe no-op when nothing was installed", func(t *testing.T) {
		dir := t.TempDir()

		var out, errb bytes.Buffer
		code := Main([]string{"integrate", "claude", "--path", dir, "--remove"}, strings.NewReader(""), &out, &errb)
		if code != ExitOK {
			t.Fatalf("exit = %d, stderr = %q", code, errb.String())
		}
		if errb.Len() != 0 {
			t.Fatalf("unexpected stderr %q", errb.String())
		}
		if _, err := os.Stat(filepath.Join(dir, "claudepass")); !os.IsNotExist(err) {
			t.Fatal("--remove created a plugin directory out of nothing")
		}
	})

	t.Run("is idempotent: a second --remove finds nothing left", func(t *testing.T) {
		dir := t.TempDir()
		if code := Main([]string{"integrate", "claude", "--path", dir}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != ExitOK {
			t.Fatal("install failed")
		}
		if code := Main([]string{"integrate", "claude", "--path", dir, "--remove"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != ExitOK {
			t.Fatal("first remove failed")
		}

		var out, errb bytes.Buffer
		code := Main([]string{"integrate", "claude", "--path", dir, "--remove"}, strings.NewReader(""), &out, &errb)
		if code != ExitOK {
			t.Fatalf("second remove: exit = %d, stderr = %q", code, errb.String())
		}
		if errb.Len() != 0 {
			t.Fatalf("unexpected stderr %q", errb.String())
		}
	})
}
