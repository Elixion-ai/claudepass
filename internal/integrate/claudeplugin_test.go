package integrate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteClaudePluginFreshInstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claudepass")
	changed, err := WriteClaudePlugin(dir)
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

func TestWriteClaudePluginSecondCallReportsUnchanged(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claudepass")
	if _, err := WriteClaudePlugin(dir); err != nil {
		t.Fatal(err)
	}
	changed, err := WriteClaudePlugin(dir)
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
	if _, err := WriteClaudePlugin(dir); err != nil {
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
