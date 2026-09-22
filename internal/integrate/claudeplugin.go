package integrate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	pluginfiles "github.com/Elixion-ai/claudepass/plugins/claude-code"
)

// PluginName is the "name" field WriteClaudePlugin's embedded
// .claude-plugin/plugin.json carries, and the marker RemoveClaudePlugin
// checks for before deleting anything: the one fact that tells it a
// directory is a plugin cpass itself installed, as opposed to some other
// directory a stray --path happened to point at.
const PluginName = "claudepass"

// pluginManifestPath is .claude-plugin/plugin.json's path as fs.WalkDir
// names it (forward slashes, relative to pluginfiles.FS's root) — the one
// file WriteClaudePlugin treats specially, to stamp its "version" field
// rather than copy it byte-for-byte.
const pluginManifestPath = ".claude-plugin/plugin.json"

// pluginManifest mirrors plugin.json's shape — just enough to stamp
// "version" without disturbing field order or dropping a field a future
// edit adds there and this struct doesn't yet know about (RawMessage keeps
// author's shape opaque, verbatim, regardless of what it contains).
type pluginManifest struct {
	Name        string          `json:"name"`
	DisplayName string          `json:"displayName"`
	Description string          `json:"description"`
	Version     string          `json:"version"`
	Author      json.RawMessage `json:"author"`
}

// stampVersion returns plugin.json's content with "version" set to
// version, formatted the same way the source file is (two-space indent,
// one trailing newline) so a rebuild of the embedded FS with no other
// change still round-trips byte-for-byte.
func stampVersion(content []byte, version string) ([]byte, error) {
	var m pluginManifest
	if err := json.Unmarshal(content, &m); err != nil {
		return nil, fmt.Errorf("stamp plugin.json version: %w", err)
	}
	m.Version = version
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("stamp plugin.json version: %w", err)
	}
	return append(out, '\n'), nil
}

// WriteClaudePlugin materialises the embedded Claude Code plugin
// (.claude-plugin/plugin.json, hooks/hooks.json, skills/claudepass/SKILL.md)
// into dir, creating it and any parent directories as needed. It writes
// only the files that differ from what's already there and reports whether
// anything changed, so a caller can print "already up to date" the way
// integrate codex does.
//
// plugin.json's own "version" field is stamped with version — normally the
// installing cpass binary's own version (cli.effectiveVersion(), including
// CLA-81's go-install fallback) — rather than copied straight from the
// embedded file, whose committed value has no way to track a tagged
// release on its own (CLA-82): this ties what Claude Code shows for the
// installed plugin to the cpass binary that installed it, by construction,
// with nothing to remember to keep in sync at release time.
//
// dir is meant to be a Claude Code skills-directory plugin folder, e.g.
// ~/.claude/skills/claudepass: any folder there containing a
// .claude-plugin/plugin.json loads automatically, with no marketplace and
// no install step (see the "Skills-directory plugins" section of Claude
// Code's plugin reference). That needs nothing from this machine's `claude`
// binary — not even for it to be installed yet — which keeps this function
// pure I/O and the caller trivially testable against a temp directory.
func WriteClaudePlugin(dir, version string) (bool, error) {
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
		if name == pluginManifestPath {
			if content, err = stampVersion(content, version); err != nil {
				return err
			}
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

// RemoveClaudePlugin deletes the plugin directory at dir — but only when it
// still looks like the plugin WriteClaudePlugin itself installed there (a
// .claude-plugin/plugin.json naming PluginName). A missing dir, or one
// whose manifest doesn't match, reports no change rather than deleting
// anything: --remove must be a safe, idempotent no-op both when nothing
// was ever installed and when --path was pointed at an unrelated
// directory, never a blind os.RemoveAll of whatever's there.
func RemoveClaudePlugin(dir string) (bool, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ".claude-plugin", "plugin.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	var manifest struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil || manifest.Name != PluginName {
		return false, nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return false, err
	}
	return true, nil
}
