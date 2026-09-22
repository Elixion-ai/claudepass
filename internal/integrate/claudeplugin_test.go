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
	removed, err := RemoveClaudePlugin(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("expected removed = true")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("plugin directory still exists after RemoveClaudePlugin: %v", err)
	}
}

func TestRemoveClaudePluginWhenNothingInstalledIsANoop(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claudepass")
	removed, err := RemoveClaudePlugin(dir)
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
	if _, err := RemoveClaudePlugin(dir); err != nil {
		t.Fatal(err)
	}
	removed, err := RemoveClaudePlugin(dir)
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
	removed, err := RemoveClaudePlugin(dir)
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
