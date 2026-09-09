package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntegrateCodexFreshRepoCreatesFile(t *testing.T) {
	ve := newVault(t)
	repo := t.TempDir()
	r := ve.runIn(repo, nil, "integrate", "codex")
	if r.code != 0 {
		t.Fatalf("integrate codex: %s", r)
	}
	if !strings.Contains(r.stdout, "created") {
		t.Fatalf("expected a created message: %s", r)
	}
	raw, err := os.ReadFile(filepath.Join(repo, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	for _, want := range []string{"<!-- cpass:begin -->", "<!-- cpass:end -->", "cpass run", "cpass capture", "cpass manifest check", ".env"} {
		if !strings.Contains(content, want) {
			t.Fatalf("AGENTS.md missing %q:\n%s", want, content)
		}
	}
}

func TestIntegrateCodexPreservesUnrelatedContentAndAppends(t *testing.T) {
	ve := newVault(t)
	repo := t.TempDir()
	unrelated := "# My Project\n\nSetup notes that have nothing to do with cpass.\n"
	agentsPath := filepath.Join(repo, "AGENTS.md")
	if err := os.WriteFile(agentsPath, []byte(unrelated), 0o644); err != nil {
		t.Fatal(err)
	}
	r := ve.runIn(repo, nil, "integrate", "codex")
	if r.code != 0 {
		t.Fatalf("integrate codex: %s", r)
	}
	raw, _ := os.ReadFile(agentsPath)
	content := string(raw)
	if !strings.Contains(content, unrelated) {
		t.Fatalf("unrelated content not preserved:\n%s", content)
	}
	if !strings.Contains(content, "<!-- cpass:begin -->") {
		t.Fatalf("section not appended:\n%s", content)
	}
}

func TestIntegrateCodexSecondRunLeavesFileUnchanged(t *testing.T) {
	ve := newVault(t)
	repo := t.TempDir()
	if r := ve.runIn(repo, nil, "integrate", "codex"); r.code != 0 {
		t.Fatalf("first run: %s", r)
	}
	agentsPath := filepath.Join(repo, "AGENTS.md")
	before, _ := os.ReadFile(agentsPath)
	r := ve.runIn(repo, nil, "integrate", "codex")
	if r.code != 0 {
		t.Fatalf("second run: %s", r)
	}
	if !strings.Contains(r.stdout, "already up to date") {
		t.Fatalf("expected an unchanged message: %s", r)
	}
	after, _ := os.ReadFile(agentsPath)
	if string(before) != string(after) {
		t.Fatalf("file changed on second run:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestIntegrateCodexPathFlag(t *testing.T) {
	ve := newVault(t)
	repo := t.TempDir()
	r := ve.runIn(repo, nil, "integrate", "codex", "--path", "docs/CODEX.md")
	if r.code != 0 {
		t.Fatalf("integrate codex --path: %s", r)
	}
	if _, err := os.Stat(filepath.Join(repo, "docs", "CODEX.md")); err != nil {
		t.Fatalf("file not written at --path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo, "AGENTS.md")); err == nil {
		t.Fatal("default AGENTS.md should not have been written when --path is given")
	}
}

func TestIntegratePrintOutputsSnippetOnly(t *testing.T) {
	ve := newVault(t)
	r := ve.runIn(t.TempDir(), nil, "integrate", "--print")
	if r.code != 0 {
		t.Fatalf("integrate --print: %s", r)
	}
	if strings.Contains(r.stdout, "<!-- cpass:begin -->") || strings.Contains(r.stdout, "<!-- cpass:end -->") {
		t.Fatalf("--print should output the snippet only, no delimiters: %s", r.stdout)
	}
	if !strings.Contains(r.stdout, "cpass run") || !strings.Contains(r.stdout, "cpass capture") || !strings.Contains(r.stdout, "cpass manifest check") {
		t.Fatalf("--print missing expected instructions: %s", r.stdout)
	}
	if r.stderr != "" {
		t.Fatalf("--print wrote to stderr: %s", r.stderr)
	}
}

func TestIntegrateMCPPrintsJSONSnippet(t *testing.T) {
	ve := newVault(t)
	r := ve.runIn(t.TempDir(), nil, "integrate", "mcp")
	if r.code != 0 {
		t.Fatalf("integrate mcp: %s", r)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &cfg); err != nil {
		t.Fatalf("snippet is not valid JSON: %v\n%s", err, r.stdout)
	}
	servers, ok := cfg["mcpServers"].(map[string]any)
	if !ok {
		t.Fatalf("snippet missing mcpServers: %s", r.stdout)
	}
	cp, ok := servers["claudepass"].(map[string]any)
	if !ok || cp["command"] != "cpass" {
		t.Fatalf("snippet missing a claudepass server entry running cpass: %s", r.stdout)
	}
	if r.stderr != "" {
		t.Fatalf("integrate mcp wrote to stderr: %s", r.stderr)
	}
}

func TestIntegrateMCPRejectsExtraArgs(t *testing.T) {
	ve := newVault(t)
	r := ve.runIn(t.TempDir(), nil, "integrate", "mcp", "extra")
	if r.code != 2 {
		t.Fatalf("expected ExitUsage for extra args: %s", r)
	}
}

func TestIntegrateUnknownTargetIsUsageError(t *testing.T) {
	ve := newVault(t)
	r := ve.runIn(t.TempDir(), nil, "integrate", "nonsense")
	if r.code != 2 {
		t.Fatalf("expected ExitUsage for unknown target: %s", r)
	}
}

func TestIntegrateClaudeFreshInstallWritesPluginFiles(t *testing.T) {
	ve := newVault(t)
	skillsDir := t.TempDir()
	r := ve.run(nil, "integrate", "claude", "--path", skillsDir)
	if r.code != 0 {
		t.Fatalf("integrate claude: %s", r)
	}
	if !strings.Contains(r.stdout, "installed the ClaudePass plugin") {
		t.Fatalf("expected an installed message: %s", r)
	}
	pluginDir := filepath.Join(skillsDir, "claudepass")

	manifestRaw, err := os.ReadFile(filepath.Join(pluginDir, ".claude-plugin", "plugin.json"))
	if err != nil {
		t.Fatalf("plugin.json: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("plugin.json is not valid JSON: %v\n%s", err, manifestRaw)
	}
	if manifest["name"] != "claudepass" {
		t.Fatalf("plugin.json name: %v", manifest["name"])
	}

	hooksRaw, err := os.ReadFile(filepath.Join(pluginDir, "hooks", "hooks.json"))
	if err != nil {
		t.Fatalf("hooks.json: %v", err)
	}
	var hooks struct {
		Hooks struct {
			UserPromptSubmit []struct {
				Hooks []struct {
					Type    string `json:"type"`
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"UserPromptSubmit"`
			PreToolUse []struct {
				Matcher string `json:"matcher"`
				Hooks   []struct {
					Type    string `json:"type"`
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(hooksRaw, &hooks); err != nil {
		t.Fatalf("hooks.json is not valid JSON: %v\n%s", err, hooksRaw)
	}
	if len(hooks.Hooks.UserPromptSubmit) != 1 || len(hooks.Hooks.UserPromptSubmit[0].Hooks) != 1 ||
		hooks.Hooks.UserPromptSubmit[0].Hooks[0].Command != "cpass intercept" {
		t.Fatalf("UserPromptSubmit should register cpass intercept: %s", hooksRaw)
	}
	if len(hooks.Hooks.PreToolUse) != 1 || hooks.Hooks.PreToolUse[0].Matcher != "Bash" ||
		len(hooks.Hooks.PreToolUse[0].Hooks) != 1 || hooks.Hooks.PreToolUse[0].Hooks[0].Command != "cpass policy --hook" {
		t.Fatalf("PreToolUse should register cpass policy --hook on matcher Bash: %s", hooksRaw)
	}

	skillRaw, err := os.ReadFile(filepath.Join(pluginDir, "skills", "claudepass", "SKILL.md"))
	if err != nil {
		t.Fatalf("SKILL.md: %v", err)
	}
	skill := string(skillRaw)
	if !strings.HasPrefix(skill, "---\n") {
		t.Fatalf("SKILL.md should start with YAML frontmatter: %s", skill)
	}
	for _, want := range []string{"description:", "cpass run", "cpass capture", "cpass manifest check", ".env", "Handle"} {
		if !strings.Contains(skill, want) {
			t.Fatalf("SKILL.md missing %q:\n%s", want, skill)
		}
	}
}

func TestIntegrateClaudeSecondRunReportsUpToDate(t *testing.T) {
	ve := newVault(t)
	skillsDir := t.TempDir()
	if r := ve.run(nil, "integrate", "claude", "--path", skillsDir); r.code != 0 {
		t.Fatalf("first run: %s", r)
	}
	before, err := os.ReadFile(filepath.Join(skillsDir, "claudepass", "hooks", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := ve.run(nil, "integrate", "claude", "--path", skillsDir)
	if r.code != 0 {
		t.Fatalf("second run: %s", r)
	}
	if !strings.Contains(r.stdout, "already up to date") {
		t.Fatalf("expected an unchanged message: %s", r)
	}
	after, err := os.ReadFile(filepath.Join(skillsDir, "claudepass", "hooks", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("file changed on second run:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestIntegrateClaudePluginValidatesAgainstRealClaudeBinary(t *testing.T) {
	claudeBin, err := exec.LookPath("claude")
	if err != nil {
		t.Skip("claude CLI not installed on this machine; skipping live validation")
	}
	ve := newVault(t)
	skillsDir := t.TempDir()
	if r := ve.run(nil, "integrate", "claude", "--path", skillsDir); r.code != 0 {
		t.Fatalf("integrate claude: %s", r)
	}
	out, err := exec.Command(claudeBin, "plugin", "validate", filepath.Join(skillsDir, "claudepass"), "--strict").CombinedOutput()
	if err != nil {
		t.Fatalf("claude plugin validate failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Validation passed") {
		t.Fatalf("expected validation to pass: %s", out)
	}
}
