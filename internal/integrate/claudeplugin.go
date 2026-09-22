package integrate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

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

// pluginRelFiles returns the file paths (skipping directories) that
// WriteClaudePlugin writes under a plugin install directory, exactly as
// fs.WalkDir visits pluginfiles.FS. RemoveClaudePlugin reads this same list
// so the two functions can never drift about what "a file cpass wrote"
// means: it is never allowed to delete anything this list doesn't name.
func pluginRelFiles() ([]string, error) {
	var files []string
	err := fs.WalkDir(pluginfiles.FS, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, filepath.FromSlash(name))
		}
		return nil
	})
	return files, err
}

// RemoveClaudePlugin deletes only the files WriteClaudePlugin itself wrote
// under dir (.claude-plugin/plugin.json, hooks/hooks.json,
// skills/claudepass/SKILL.md — see pluginRelFiles), then removes any parent
// directory that ends up empty as a result, walking up towards dir. It
// never touches a file it didn't itself write, or a directory still
// holding one: a user (or another tool) may have since added a file of
// their own inside the installed plugin folder, and --remove must leave
// that alone rather than deleting it with the rest — never a blind
// os.RemoveAll of whatever's there (CLA-78).
//
// It first checks dir's .claude-plugin/plugin.json names PluginName, the
// same guard as before: a missing dir, or one whose manifest doesn't
// match, reports removed = false rather than deleting anything, so --path
// pointed at an unrelated directory is always a safe no-op.
//
// removed reports whether anything cpass wrote was actually deleted. whole
// reports whether dir itself ended up empty and was removed too, as
// opposed to some unrelated file surviving inside it — the same
// distinction integrate codex --remove already draws between "the whole
// thing is gone" and "only our part was", so the caller can print the
// right message either way.
func RemoveClaudePlugin(dir string) (removed, whole bool, err error) {
	raw, err := os.ReadFile(filepath.Join(dir, ".claude-plugin", "plugin.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return false, false, nil
		}
		return false, false, err
	}
	var manifest struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil || manifest.Name != PluginName {
		return false, false, nil
	}

	files, err := pluginRelFiles()
	if err != nil {
		return false, false, err
	}

	// parentDirs collects every directory (relative to dir) that held a
	// file we just deleted, so it can be cleaned up below if — and only
	// if — nothing else is left in it.
	parentDirs := map[string]bool{}
	for _, rel := range files {
		if rerr := os.Remove(filepath.Join(dir, rel)); rerr != nil {
			if !os.IsNotExist(rerr) {
				return removed, false, rerr
			}
			continue
		}
		removed = true
		for d := filepath.Dir(rel); d != "."; d = filepath.Dir(d) {
			parentDirs[d] = true
		}
	}

	// Remove directories left empty by that deletion, deepest first, so a
	// directory a user also put an unrelated file into is left standing —
	// along with every ancestor up to dir — instead of being deleted out
	// from under that file: os.Remove only ever succeeds on an empty
	// directory.
	ordered := make([]string, 0, len(parentDirs))
	for d := range parentDirs {
		ordered = append(ordered, d)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return strings.Count(ordered[i], string(filepath.Separator)) > strings.Count(ordered[j], string(filepath.Separator))
	})
	for _, d := range ordered {
		_ = os.Remove(filepath.Join(dir, d)) // ignore: non-empty (unrelated content left behind) or already gone
	}
	whole = os.Remove(dir) == nil // same: only succeeds once dir itself is empty

	return removed, whole, nil
}
