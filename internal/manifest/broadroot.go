package manifest

import (
	"fmt"
	"os"
	"path/filepath"
)

// BroadRoot reports whether dir is the filesystem root or the caller's own
// home directory — an ancestor broad enough that a Manifest planted there
// turns every Global Handle this machine ever declares into an ambient
// default for every subdirectory beneath it: scratch checkouts, downloads,
// anything that happens to nest under it, none of which were ever reviewed
// or introduced to ClaudePass with their own `cpass manifest init`.
//
// Not exhaustive by design — a symlinked or bind-mounted equivalent of
// either is not detected, and neither is a merely-large ancestor like the
// parent of every user's home directory (`/Users`, `/home`) — but the two
// cases a Manifest is actually likely to land in by accident: `cpass
// manifest init` run from an unchanged shell right after `cd ~`, or from a
// script whose working directory resolved wrong and landed at `/`. This is
// a disclosed residual (docs/THREATS.md), the same honest shape as
// globalReaches's own `.git`-presence limitation, not a claim of
// exhaustive coverage.
func BroadRoot(dir string) (bool, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}
	abs = filepath.Clean(abs)
	if abs == string(filepath.Separator) {
		return true, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// No resolvable home directory to compare against: withhold rather
		// than guess, the same caution globalReaches uses when a path
		// cannot be resolved.
		return false, nil
	}
	home = filepath.Clean(home)
	if abs == home {
		return true, nil
	}
	// Resolve both through symlinks before giving up — a home directory
	// reached by a different, linked path (common on macOS, where /tmp
	// itself is a symlink to /private/tmp) must still match. Only trust the
	// resolved comparison when both sides resolve cleanly; otherwise the
	// literal comparison above is the final answer, the same fallback
	// globalReaches uses for a dangling link or a permission error.
	resolvedAbs, err1 := filepath.EvalSymlinks(abs)
	resolvedHome, err2 := filepath.EvalSymlinks(home)
	if err1 != nil || err2 != nil {
		return false, nil
	}
	return resolvedAbs == resolvedHome, nil
}

// broadRootNotice renders the run-time warning Refs emits (once per run, on
// stderr, never blocking) the moment a broad-root Manifest actually hands a
// directory a Global Handle. root is the Manifest's own directory, not the
// caller's cwd — this project's committed file is what sits at the broad
// ancestor, however deep the command asking for its Handles happens to run
// from.
func broadRootNotice(root string) string {
	return fmt.Sprintf(
		"cpass: your Manifest at %s sits at a broad ancestor (your home directory, or /) — every Global Handle on this machine reaches every directory beneath it; run `cpass manifest init` somewhere narrower if that is not what you want",
		root)
}
