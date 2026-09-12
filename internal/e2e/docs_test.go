package e2e

// This file keeps README.md, docs/SECURITY.md, and the source honest with
// each other (CLA-17): the README's quickstart is executed, line for line,
// against a built binary rather than merely read, and SECURITY.md's claims
// about every CPASS_* environment variable and on-disk path are
// cross-checked against what the source actually references.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// repoRoot finds the repository root from this file's own location, so the
// test works regardless of the working directory `go test` was invoked
// from.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine this test file's location")
	}
	// This file lives at <root>/internal/e2e/docs_test.go.
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// --- README quickstart: run every command against a built binary ---

const quickstartBegin = "<!-- quickstart:begin -->"
const quickstartEnd = "<!-- quickstart:end -->"

// quickstartCommands extracts the commands from README.md's fenced ```bash
// block between the quickstart:begin/end markers: one non-blank,
// non-comment line per command, in order.
func quickstartCommands(t *testing.T) []string {
	t.Helper()
	readme := readRepoFile(t, "README.md")

	bi := strings.Index(readme, quickstartBegin)
	ei := strings.Index(readme, quickstartEnd)
	if bi < 0 || ei < 0 || ei < bi {
		t.Fatal("README.md is missing the <!-- quickstart:begin/end --> markers around the quickstart code block")
	}
	block := readme[bi:ei]

	fs := strings.Index(block, "```bash")
	if fs < 0 {
		t.Fatal("quickstart block has no ```bash fenced code")
	}
	fs += len("```bash")
	fe := strings.Index(block[fs:], "```")
	if fe < 0 {
		t.Fatal("quickstart block's ```bash fence is never closed")
	}
	code := block[fs : fs+fe]

	var cmds []string
	for _, line := range strings.Split(code, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cmds = append(cmds, line)
	}
	if len(cmds) == 0 {
		t.Fatal("no commands found in the README quickstart block")
	}
	return cmds
}

// TestReadmeQuickstartRunsAgainstBuiltBinary runs every command in the
// README's 60-second quickstart, in order, exactly as written, in a shell,
// against the same cpass binary the rest of this suite builds. It is the
// scripted check CLA-17 requires: a change that breaks the quickstart (a
// renamed flag, a command that now gets refused) fails this test, not just
// a human's read-through.
func TestReadmeQuickstartRunsAgainstBuiltBinary(t *testing.T) {
	cmds := quickstartCommands(t)

	// A directory containing a "cpass" on PATH, since the quickstart is
	// written the way a person actually types it: a bare "cpass ...", not
	// an absolute path to the binary under test.
	binDir := t.TempDir()
	linked := filepath.Join(binDir, "cpass")
	if err := os.Symlink(cpassBin, linked); err != nil {
		t.Fatalf("link cpass onto PATH: %v", err)
	}

	home := t.TempDir()    // CPASS_HOME (the Vault, run dir, ...) and $HOME (integrate claude's default target)
	project := t.TempDir() // cwd: where the Manifest and plugin get written

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	env := append(baseEnv(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HOME="+home,
		"CPASS_HOME="+home,
		"CPASS_KEY="+base64.StdEncoding.EncodeToString(key),
		// Built with -tags e2e (see TestMain): lets `cpass add` accept a
		// value on stdin instead of demanding a real terminal, standing in
		// for what a human types at the hidden prompt this step shows.
		"CPASS_TEST_STDIN=1",
	)
	const fakeSecretValue = "sk_live_51QuickstartDemoNotARealKeyABCDEF"

	var last result
	for i, line := range cmds {
		cmd := exec.Command("sh", "-c", line)
		cmd.Dir = project
		cmd.Env = env
		cmd.Stdin = strings.NewReader(fakeSecretValue + "\n")
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		runErr := cmd.Run()
		code := 0
		if ee, ok := runErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if runErr != nil {
			t.Fatalf("quickstart line %d (%q) could not run at all: %v", i+1, line, runErr)
		}
		last = result{code: code, stdout: out.String(), stderr: errb.String()}
		if code != 0 {
			t.Fatalf("quickstart line %d failed: %q\n%s", i+1, line, last)
		}
	}

	if !strings.Contains(last.stdout, "deploy: authenticated") {
		t.Fatalf("final quickstart command did not prove the Secret reached the child's environment: %s", last)
	}
	if strings.Contains(last.stdout+last.stderr, fakeSecretValue) {
		t.Fatalf("the Secret's own value leaked into the quickstart's output: %s", last)
	}
}

// --- docs/SECURITY.md cross-checked against the source ---

// cpassEnvVarRe matches a CPASS_* token the way it appears in Go source,
// shell scripts, and prose alike.
var cpassEnvVarRe = regexp.MustCompile(`CPASS_[A-Z0-9_]+`)

// sourceFilesForDocCheck returns the paths this repo's CPASS_* usage and
// on-disk paths should be grepped from: every .go file plus install.sh,
// skipping VCS and agent-worktree metadata.
func sourceFilesForDocCheck(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".claude", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") || filepath.Base(path) == "install.sh" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return files
}

// TestSecurityDocListsEveryEnvVar greps every .go file and install.sh for a
// CPASS_* token and asserts docs/SECURITY.md names every one it finds. This
// is CLA-17's acceptance bullet made durable: it fails the day source code
// starts reading a CPASS_* variable this doc doesn't yet mention, rather
// than relying on a human noticing.
func TestSecurityDocListsEveryEnvVar(t *testing.T) {
	root := repoRoot(t)
	security := readRepoFile(t, filepath.Join("docs", "SECURITY.md"))

	found := map[string]bool{}
	for _, path := range sourceFilesForDocCheck(t, root) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, m := range cpassEnvVarRe.FindAllString(string(b), -1) {
			found[m] = true
		}
	}
	if len(found) == 0 {
		t.Fatal("no CPASS_* tokens found in the source at all — the scan itself is broken")
	}

	var missing []string
	for name := range found {
		if !strings.Contains(security, name) {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("docs/SECURITY.md does not mention every CPASS_* variable found in the source: %s", strings.Join(missing, ", "))
	}
}

// knownPathConstants are the on-disk paths and file names cpass reads or
// writes, each pulled from the Go constant that defines it. If a future
// change adds a new on-disk path, add its literal here alongside
// documenting it in docs/SECURITY.md — this list is intentionally explicit
// rather than inferred, since a generic "any string literal" scan would be
// far too noisy to be a useful check.
var knownPathConstants = []struct {
	literal string
	source  string
}{
	{"vault.cpv", "internal/broker/broker.go: VaultPath"},
	{"broker.salt", "internal/broker/passphrase.go: saltPath"},
	{"cpass.sock", "internal/broker/process_unix.go: socketFileName"},
	{"redactions.log", "internal/run/run.go: logPath"},
	{"CPASS_HOME/run", "internal/run/files.go: runRoot (the file-Binding temp-dir root)"},
	{".claudepass.toml", "internal/manifest/manifest.go: FileName"},
}

// TestSecurityDocListsEveryKnownPath asserts docs/SECURITY.md's path table
// names every on-disk location cpass is known to touch.
func TestSecurityDocListsEveryKnownPath(t *testing.T) {
	security := readRepoFile(t, filepath.Join("docs", "SECURITY.md"))
	var missing []string
	for _, p := range knownPathConstants {
		if !strings.Contains(security, p.literal) {
			missing = append(missing, p.literal+" ("+p.source+")")
		}
	}
	if len(missing) > 0 {
		t.Fatalf("docs/SECURITY.md does not mention every known on-disk path: %s", strings.Join(missing, "; "))
	}
}
