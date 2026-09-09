package integrate

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"

	pluginfiles "claudepass/plugins/claude-code"
)

// WriteClaudePlugin materialises the embedded Claude Code plugin
// (.claude-plugin/plugin.json, hooks/hooks.json, skills/claudepass/SKILL.md)
// into dir, creating it and any parent directories as needed. It writes
// only the files that differ from what's already there and reports whether
// anything changed, so a caller can print "already up to date" the way
// integrate codex does.
//
// dir is meant to be a Claude Code skills-directory plugin folder, e.g.
// ~/.claude/skills/claudepass: any folder there containing a
// .claude-plugin/plugin.json loads automatically, with no marketplace and
// no install step (see the "Skills-directory plugins" section of Claude
// Code's plugin reference). That needs nothing from this machine's `claude`
// binary — not even for it to be installed yet — which keeps this function
// pure I/O and the caller trivially testable against a temp directory.
func WriteClaudePlugin(dir string) (bool, error) {
	changed := false
	err := fs.WalkDir(pluginfiles.FS, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(dir, name)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		content, err := pluginfiles.FS.ReadFile(name)
		if err != nil {
			return err
		}
		if existing, rerr := os.ReadFile(target); rerr == nil && bytes.Equal(existing, content) {
			return nil
		}
		changed = true
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, content, 0o644)
	})
	return changed, err
}
