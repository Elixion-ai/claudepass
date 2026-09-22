package manifest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Elixion-ai/claudepass/internal/broker"
)

// Refs builds the complete Ref list for a command running in dir: the
// Global Manifest's Handles as a base layer, with the project Manifest's own
// declarations layered over them. It is the single Handle source every
// surface uses — `cpass run` with no --with, and the MCP run_with_secrets
// tool with no explicit handles list — so both see exactly the same set.
//
// A project Manifest declaring a Handle the Global Manifest also declares
// replaces it outright, Binding and all: a project's own committed contract
// always beats the machine's ambient default for that Handle.
//
// Global Handles reach a directory only when that directory belongs to a
// project that has been introduced to ClaudePass — a Manifest found here or
// above — and only when the walk up to that Manifest does not cross out of a
// nested repository (see globalReaches). A directory nobody has ever run
// `cpass manifest init` for gets no Global Handles at all, and neither does
// an unfamiliar repo cloned inside one that has.
//
// notices carries anything the human should hear that is not worth failing
// over. A project's own Manifest failing to parse is still fatal — it is a
// committed contract, and a run that quietly ignored it would be worse than
// one that stops — but the machine-wide layer is ambient, so a global.toml
// that cannot be read costs this run its Global Handles and a line saying
// so, rather than taking down every project on the machine at once.
func Refs(dir string, includeGlobal bool) (refs []broker.Ref, notices []string, err error) {
	p, err := Find(dir)
	if errors.Is(err, ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	m, err := Load(p)
	if err != nil {
		return nil, nil, err
	}
	if includeGlobal && !m.GlobalDisabled {
		reaches, err := globalReaches(dir, filepath.Dir(p))
		if err != nil {
			return nil, nil, err
		}
		if reaches {
			gm, err := LoadGlobal()
			if err != nil {
				notices = append(notices, fmt.Sprintf(
					"cpass: your Global Manifest is unreadable (%v); skipping Global Handles for this run — run `cpass manifest check -g` once it is fixed", err))
			} else {
				for _, en := range gm.Entries {
					refs = append(refs, broker.Ref{Handle: en.Handle, Declared: en.Binding, FromGlobal: true})
				}
				// `cpass manifest init` warns at the moment a Manifest is
				// planted at a broad ancestor, but a Manifest can end up
				// broad other ways too — hand-copied, git-cloned straight
				// into $HOME. This is the run-time backstop: only once this
				// Manifest actually hands a directory a Global Handle,
				// worth saying, and cheap enough (one filepath comparison)
				// to check on every run without it costing an ordinary
				// project root anything.
				if len(gm.Entries) > 0 {
					if broad, _ := BroadRoot(filepath.Dir(p)); broad {
						notices = append(notices, broadRootNotice(filepath.Dir(p)))
					}
				}
			}
		}
	}
	for _, en := range m.Entries {
		refs = replaceOrAppend(refs, broker.Ref{Handle: en.Handle, Declared: en.Binding})
	}
	return refs, notices, nil
}

// GlobalReachable reports whether the Global Manifest, if any, actually
// reaches dir — the same gate Refs applies internally when deciding whether
// to layer it in at all: dir must belong to a project with its own
// Manifest, that project must not have opted out
// (`[options] global = false`), and the walk from dir up to the Manifest's
// root must not cross a nested repository of its own (globalReaches).
//
// It exists for callers outside Refs that need to know reachability on its
// own, without also wanting the merged Ref list — `cpass manifest check
// --effective` uses it to tell a project Entry that overrides a reachable
// Global default apart from one that merely happens to share a Handle name
// with a Global Manifest that was never going to reach this directory
// anyway (opted out, or across a nested-repository boundary).
func GlobalReachable(dir string) (bool, error) {
	p, err := Find(dir)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	m, err := Load(p)
	if err != nil {
		return false, err
	}
	if m.GlobalDisabled {
		return false, nil
	}
	return globalReaches(dir, filepath.Dir(p))
}

// replaceOrAppend puts r in refs, replacing any Ref for the same Handle —
// including its FromGlobal mark, since a Handle a project declares itself is
// no longer reaching that project by way of the Global Manifest.
func replaceOrAppend(refs []broker.Ref, r broker.Ref) []broker.Ref {
	for i := range refs {
		if refs[i].Handle == r.Handle {
			refs[i] = r
			return refs
		}
	}
	return append(refs, r)
}

// globalReaches reports whether the Global Manifest applies to dir, given
// that root is the directory whose Manifest governs it.
//
// It does when dir is root, or is below root without an intervening
// repository of its own. Crossing a nested .git on the way up means dir
// belongs to some other project that merely happens to sit inside this one —
// a dependency cloned into vendor/, a scratch checkout under tmp/ — which
// nobody reviewed and nobody introduced to ClaudePass. Such a directory gets
// no Global Handles, so an install script it runs cannot reach the machine's
// ambient Secrets. (The outer project's own explicitly declared Handles do
// still reach it, exactly as they do today: that is the pre-existing meaning
// of a committed Manifest, and this gate does not change it.)
func globalReaches(dir, root string) (bool, error) {
	// Resolve both paths to their physical form before walking. The walk is
	// lexical — filepath.Dir is string surgery — while the boundary test is
	// a syscall the kernel resolves through symlinks, and the two disagree
	// the moment a symlink is involved. A link at the project root pointing
	// into a nested repository (pnpm and monorepo tooling create these all
	// the time, and one `ln -s` makes one by hand) would otherwise have a
	// lexical parent of the project root itself: the walk would step clean
	// over the directory holding the nested .git and hand an untrusted tree
	// every Global Handle. Resolving both ends makes filepath.Dir climb the
	// real ancestor chain. Both must be resolved, not just dir: on macOS a
	// project under /tmp resolves to /private/tmp, and comparing a resolved
	// dir against an unresolved root would never match.
	d, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}
	resolvedDir, err1 := filepath.EvalSymlinks(d)
	resolvedRoot, err2 := filepath.EvalSymlinks(filepath.Clean(root))
	if err1 != nil || err2 != nil {
		// A dangling link, a permission error, a directory renamed out from
		// under us. Withhold rather than guess, the same as the walk below
		// does when the two paths turn out not to relate.
		return false, nil
	}
	d, root = resolvedDir, resolvedRoot
	for d != root {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return false, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			// Walked to the filesystem root without meeting root: the two
			// paths do not relate the way Find says they do (a symlinked
			// cwd, a racing rename). Withhold Global rather than guess.
			return false, nil
		}
		d = parent
	}
	return true, nil
}
