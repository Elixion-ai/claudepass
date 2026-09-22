package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Elixion-ai/claudepass/internal/broker"
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

// broadRootWarnedDirName is the sentinel directory Refs uses to remember
// which broad-root Manifest directories it has already warned about: one
// empty marker file per root, named by that root's hash (see
// broadRootWarnedMarkerPath).
const broadRootWarnedDirName = "broadroot-warned"

// broadRootWarnedDir is where that sentinel lives: alongside the Vault and
// the Global Manifest itself, under $CPASS_HOME, so it is per-machine (one
// warning history per Vault) and respects the same CPASS_HOME override the
// tests already use to keep every case isolated from a developer's real
// home.
func broadRootWarnedDir() (string, error) {
	home, err := broker.Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, broadRootWarnedDirName), nil
}

// broadRootWarnedMarkerPath names the marker file for root inside dir. root
// is an arbitrary directory path — it can contain separators, spaces or
// anything else the filesystem allows — so it is hashed into a fixed-width,
// filename-safe token rather than used as a path component directly.
func broadRootWarnedMarkerPath(dir, root string) string {
	sum := sha256.Sum256([]byte(root))
	return filepath.Join(dir, hex.EncodeToString(sum[:]))
}

// shouldWarnBroadRoot reports whether root (a broad-root Manifest's own
// directory, not the caller's cwd) has already drawn the run-time backstop
// notice, recording it as warned if not. This is what makes Refs's notice
// actually fire once per Manifest, as CLA-96's acceptance criteria and
// docs/THREATS.md item 10 both promise, rather than on every call — Refs is
// the Handle source for both `cpass run` (runcmd.go forwards every notice
// straight to stderr) and the MCP `run_with_secrets` tool (internal/mcp
// rides every notice into the tool_result content block that lands in an
// Agent's own Context), so an unsuppressed repeat would inject this line
// into that Context on literally every tool call.
//
// The check and the recording are one atomic step, not a read followed by a
// separate write: it creates root's marker file with O_CREATE|O_EXCL, which
// the OS guarantees only one caller can win for a given path, on every
// platform this binary ships for. That closes the race a plain
// check-then-act (read the sentinel, decide, then write it) leaves open —
// several `cpass` processes racing the very first time a broad-root
// Manifest ever serves a Global Handle (an Agent's parallel tool-call
// batch, or several agents sharing one machine) could otherwise all pass
// the "not yet warned" read before any of them finished writing, and each
// emit its own notice.
//
// It fails open: when the marker directory cannot be created, or the
// marker file cannot be created for any reason other than "it already
// exists" (a fresh $CPASS_HOME, a read-only filesystem), it reports "not
// yet warned" so Refs still emits the notice this run — a security-relevant
// line appearing too often beats it silently never appearing — it just
// cannot suppress a repeat until the marker directory becomes writable.
func shouldWarnBroadRoot(root string) bool {
	dir, err := broadRootWarnedDir()
	if err != nil {
		return true
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return true
	}
	marker := broadRootWarnedMarkerPath(dir, root)
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			// Some caller — this one earlier, another process, or a
			// concurrent goroutine racing this same call — already won
			// the race to create this root's marker: already warned.
			return false
		}
		// Any other error (permissions, a read-only filesystem): fail
		// open, same as a missing $CPASS_HOME above.
		return true
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(root + "\n")
	return true
}
