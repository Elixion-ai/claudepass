package e2e

import (
	"encoding/json"
	"os"
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
