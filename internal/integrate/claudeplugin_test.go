package integrate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pluginfiles "github.com/Elixion-ai/claudepass/plugins/claude-code"
)

// testVersion stands in for the running cpass binary's own version (what
// cli.effectiveVersion() returns) across this file's tests — a real caller
// always has one to pass, so no test here calls WriteClaudePlugin with an
// empty version.
const testVersion = "v1.2.3-test"

func TestWriteClaudePluginFreshInstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claudepass")
	changed, err := WriteClaudePlugin(dir, testVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("fresh install should report changed")
	}

	for _, rel := range []string{
		filepath.Join(".claude-plugin", "plugin.json"),
		filepath.Join("hooks", "hooks.json"),
		filepath.Join("skills", "claudepass", "SKILL.md"),
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
	}

	manifestRaw, err := os.ReadFile(filepath.Join(dir, ".claude-plugin", "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("plugin.json is not valid JSON: %v", err)
	}
	if manifest["name"] != "claudepass" {
		t.Fatalf("plugin.json name = %v, want claudepass", manifest["name"])
	}
}

// TestWriteClaudePluginStampsRequestedVersion is CLA-82's regression test:
// plugin.json's own "version" field was frozen at whatever the embedded
// source file happened to say (unchanged across 7 tagged releases) because
// WriteClaudePlugin copied it byte-for-byte. It must instead always carry
// the version passed in — normally the installing binary's own version,
// which for a release build is exactly the tagged release version
// (ldflags-injected into cli.Version, read back by cli.effectiveVersion) —
// so there is nothing left to remember to bump at release time. Every
// other field must still match the embedded source file untouched.
func TestWriteClaudePluginStampsRequestedVersion(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claudepass")
	if _, err := WriteClaudePlugin(dir, "v7.8.9"); err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile(filepath.Join(dir, ".claude-plugin", "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("plugin.json is not valid JSON: %v", err)
	}
	if manifest["version"] != "v7.8.9" {
		t.Fatalf("plugin.json version = %v, want v7.8.9", manifest["version"])
	}

	sourceRaw, err := pluginfiles.FS.ReadFile(pluginManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var source map[string]any
	if err := json.Unmarshal(sourceRaw, &source); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"name", "displayName", "description", "author"} {
		got, want := fmt.Sprint(manifest[field]), fmt.Sprint(source[field])
		if got != want {
			t.Fatalf("plugin.json %s = %v, want %v (unchanged from the embedded source)", field, got, want)
		}
	}
}

// TestWriteClaudePluginVersionBumpIsNotSilentlyIgnored asserts a stale
// installed version is treated as drift, not as "already up to date": a
// second call with a different version reports changed and rewrites
// plugin.json, exactly the same as any other content change would.
func TestWriteClaudePluginVersionBumpIsNotSilentlyIgnored(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claudepass")
	if _, err := WriteClaudePlugin(dir, "v1.0.0"); err != nil {
		t.Fatal(err)
	}
	changed, err := WriteClaudePlugin(dir, "v1.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("a version bump must report changed, not silently keep the stale installed version")
	}
	manifestRaw, err := os.ReadFile(filepath.Join(dir, ".claude-plugin", "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest["version"] != "v1.0.1" {
		t.Fatalf("plugin.json version = %v, want v1.0.1", manifest["version"])
	}
}

// TestStampVersionPreservesUnknownTopLevelFields is CLA-82's review
// regression (major): stampVersion used to round-trip plugin.json through
// a five-field Go struct, so json.Unmarshal silently dropped any
// top-level key that struct didn't know about (e.g. a future "keywords"
// or "homepage" field), and json.MarshalIndent then wrote the installed
// copy back out without it — even though the embedded source file still
// had it. stampVersion must instead touch only the "version" value and
// leave every other byte — known field or not, and its position in the
// file — exactly as it was.
func TestStampVersionPreservesUnknownTopLevelFields(t *testing.T) {
	source := []byte(`{
  "name": "claudepass",
  "displayName": "ClaudePass",
  "description": "Secrets for AI coding agents.",
  "version": "0.1.0",
  "keywords": ["secrets", "agents"],
  "homepage": "https://claudepass.com",
  "author": {
    "name": "ClaudePass"
  }
}
`)
	out, err := stampVersion(source, "v9.9.9")
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("stamped plugin.json is not valid JSON: %v\n%s", err, out)
	}
	if m["version"] != "v9.9.9" {
		t.Fatalf("version = %v, want v9.9.9", m["version"])
	}
	if kw, ok := m["keywords"].([]any); !ok || len(kw) != 2 || kw[0] != "secrets" || kw[1] != "agents" {
		t.Fatalf("keywords field was dropped or altered: %v", m["keywords"])
	}
	if m["homepage"] != "https://claudepass.com" {
		t.Fatalf("homepage field was dropped: %v", m["homepage"])
	}

	// Every byte outside the "version" value's quotes is untouched, not
	// just semantically preserved — field order included.
	want := strings.Replace(string(source), `"version": "0.1.0"`, `"version": "v9.9.9"`, 1)
	if string(out) != want {
		t.Fatalf("stampVersion changed more than the version value.\ngot:  %q\nwant: %q", out, want)
	}
}

// TestStampVersionRejectsMissingVersionField guards the error path a
// silent struct-field drop could otherwise hide: with no "version" field
// at all to stamp, stampVersion must fail loudly rather than writing
// something plugin.json never asked for.
func TestStampVersionRejectsMissingVersionField(t *testing.T) {
	if _, err := stampVersion([]byte(`{"name": "claudepass"}`), "v1.0.0"); err == nil {
		t.Fatal(`expected an error: no "version" field to stamp`)
	}
}

func TestWriteClaudePluginSecondCallReportsUnchanged(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claudepass")
	if _, err := WriteClaudePlugin(dir, testVersion); err != nil {
		t.Fatal(err)
	}
	changed, err := WriteClaudePlugin(dir, testVersion)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("second call with no drift should report unchanged")
	}
}

func TestWriteClaudePluginSkillMatchesSharedSnippet(t *testing.T) {
	// The Claude Code skill must teach exactly the same instructions as
	// every other integration (Codex's AGENTS.md, `cpass integrate
	// --print`): one Snippet, no drift between surfaces.
	dir := filepath.Join(t.TempDir(), "claudepass")
	if _, err := WriteClaudePlugin(dir, testVersion); err != nil {
		t.Fatal(err)
	}
	skill, err := os.ReadFile(filepath.Join(dir, "skills", "claudepass", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(skill)
	// Frontmatter precedes the shared Snippet text.
	if body[:4] != "---\n" {
		t.Fatalf("SKILL.md should open with YAML frontmatter: %q", body)
	}
	end := indexAfterFrontmatter(body)
	if end < 0 {
		t.Fatalf("SKILL.md frontmatter never closes: %q", body)
	}
	got := body[end:]
	got = strings.TrimPrefix(got, "\n") // one blank line conventionally separates frontmatter from content
	if got != Snippet {
		t.Fatalf("SKILL.md body must equal the shared Snippet verbatim.\ngot:  %q\nwant: %q", got, Snippet)
	}
}

func TestRemoveClaudePluginOnAFreshInstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claudepass")
	if _, err := WriteClaudePlugin(dir, testVersion); err != nil {
		t.Fatal(err)
	}
	removed, whole, err := RemoveClaudePlugin(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("expected removed = true")
	}
	if !whole {
		t.Fatal("expected whole = true: nothing but cpass's own files were there")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("plugin directory still exists after RemoveClaudePlugin: %v", err)
	}
}

func TestRemoveClaudePluginWhenNothingInstalledIsANoop(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claudepass")
	removed, _, err := RemoveClaudePlugin(dir)
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("expected removed = false: dir was never created")
	}
}

func TestRemoveClaudePluginIsIdempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claudepass")
	if _, err := WriteClaudePlugin(dir, testVersion); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RemoveClaudePlugin(dir); err != nil {
		t.Fatal(err)
	}
	removed, _, err := RemoveClaudePlugin(dir)
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("second RemoveClaudePlugin should report nothing left to remove")
	}
}

// TestRemoveClaudePluginLeavesAnUnrelatedDirectoryAlone is the safety
// regression: --remove must never blindly os.RemoveAll whatever --path
// happens to point at. A directory with no .claude-plugin/plugin.json
// naming this plugin is left untouched.
func TestRemoveClaudePluginLeavesAnUnrelatedDirectoryAlone(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "not-ours.txt")
	if err := os.WriteFile(sentinel, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	removed, _, err := RemoveClaudePlugin(dir)
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("expected removed = false: no ClaudePass plugin manifest here")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("unrelated file was deleted: %v", err)
	}
}

// TestRemoveClaudePluginPreservesFilesItDidNotWrite is CLA-78's review
// regression (blocker): RemoveClaudePlugin used to os.RemoveAll the whole
// installed directory, destroying any file a user or another tool had
// since added alongside the ones cpass wrote. It must instead delete only
// the files WriteClaudePlugin itself wrote and leave everything else —
// and the directories holding it — standing.
func TestRemoveClaudePluginPreservesFilesItDidNotWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claudepass")
	if _, err := WriteClaudePlugin(dir, testVersion); err != nil {
		t.Fatal(err)
	}

	// A file dropped alongside SKILL.md, inside a cpass-owned directory...
	extraInOwnedDir := filepath.Join(dir, "skills", "claudepass", "my-own-notes.txt")
	if err := os.WriteFile(extraInOwnedDir, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	// ...and a whole extra directory of the user's own at the plugin root.
	extraDir := filepath.Join(dir, "my-extra-dir")
	if err := os.MkdirAll(extraDir, 0o755); err != nil {
		t.Fatal(err)
	}
	extraInExtraDir := filepath.Join(extraDir, "todo.txt")
	if err := os.WriteFile(extraInExtraDir, []byte("keep me too"), 0o644); err != nil {
		t.Fatal(err)
	}

	removed, whole, err := RemoveClaudePlugin(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("expected removed = true: cpass's own files were deleted")
	}
	if whole {
		t.Fatal("expected whole = false: unrelated files are still inside dir")
	}

	// cpass's own files are gone.
	for _, rel := range []string{
		filepath.Join(".claude-plugin", "plugin.json"),
		filepath.Join("hooks", "hooks.json"),
		filepath.Join("skills", "claudepass", "SKILL.md"),
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); !os.IsNotExist(err) {
			t.Fatalf("%s should have been removed: %v", rel, err)
		}
	}
	// Directories cpass wrote into but that now hold nothing of ours are
	// gone too (hooks/, .claude-plugin/) -- but not skills/, since
	// skills/claudepass/ still holds the user's own file.
	for _, rel := range []string{"hooks", ".claude-plugin"} {
		if _, err := os.Stat(filepath.Join(dir, rel)); !os.IsNotExist(err) {
			t.Fatalf("%s should have been cleaned up as empty: %v", rel, err)
		}
	}

	// The user's own files, and the directories holding them, survive.
	for _, path := range []string{extraInOwnedDir, extraInExtraDir} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("unrelated file was deleted: %v", err)
		}
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("plugin directory should still exist (unrelated content remains): %v", err)
	}
}

// indexAfterFrontmatter returns the offset of the first byte after a
// leading "---\n...\n---\n" YAML frontmatter block, or -1 if it never
// closes.
func indexAfterFrontmatter(s string) int {
	if len(s) < 4 || s[:4] != "---\n" {
		return -1
	}
	rest := s[4:]
	for i := 0; i+4 <= len(rest); i++ {
		if rest[i:i+4] == "---\n" && (i == 0 || rest[i-1] == '\n') {
			return 4 + i + 4
		}
	}
	return -1
}
