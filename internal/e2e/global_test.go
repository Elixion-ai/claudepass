package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// project makes a directory under a fresh temp root and runs manifest init in
// it, returning the path — the "this machine has been introduced to this
// project" state that Global Handles require.
func (ve *vaultEnv) project(t *testing.T, flags ...string) string {
	t.Helper()
	dir := t.TempDir()
	args := append([]string{"manifest", "init"}, flags...)
	if r := ve.runIn(dir, nil, args...); r.code != 0 {
		t.Fatalf("manifest init: %s", r)
	}
	return dir
}

// injected runs the helper in dir and returns the environment it observed.
func (ve *vaultEnv) injected(t *testing.T, dir string, args ...string) (string, result) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "observed.txt")
	full := append(append([]string{"run"}, args...), "--", helperBin)
	r := ve.runIn(dir, []string{"HELPER_OUT=" + out}, full...)
	seen, _ := os.ReadFile(out)
	return string(seen), r
}

func TestAddGlobalStoresTheSecretAndDeclaresIt(t *testing.T) {
	ve := newVault(t)
	r := ve.add("openai/key", "openai-key-value-xyz", "-g")
	if r.code != 0 {
		t.Fatalf("add -g: %s", r)
	}
	// Two facts, two lines: the Secret was stored, and it was declared.
	if !strings.Contains(r.stdout, "stored openai/key") || !strings.Contains(r.stdout, "declared openai/key in ") {
		t.Fatalf("add -g stdout: %q", r.stdout)
	}
	if !strings.Contains(r.stdout, "global.toml") {
		t.Fatalf("add -g must name the Global Manifest: %q", r.stdout)
	}
	// --global is the same flag.
	if r := ve.add("stripe/live", "stripe-live-value-xyz", "--global"); r.code != 0 {
		t.Fatalf("add --global: %s", r)
	}
	raw, err := os.ReadFile(filepath.Join(ve.home, "global.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"openai-key-value-xyz", "stripe-live-value-xyz"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("the Global Manifest holds a value:\n%s", raw)
		}
	}
	// ls shows the declaration without being asked twice.
	if r := ve.run(nil, "ls", "-l"); !strings.Contains(r.stdout, "GLOBAL") {
		t.Fatalf("ls -l: %q", r.stdout)
	}
	if r := ve.run(nil, "ls", "--global"); !strings.Contains(r.stdout, "openai/key") {
		t.Fatalf("ls --global: %q", r.stdout)
	}
}

func TestGlobalHandleReachesAProjectThatNeverDeclaredIt(t *testing.T) {
	ve := newVault(t)
	ve.add("openai/key", "openai-key-value-xyz", "-g")
	repo := ve.project(t)
	// The whole point: no `cpass manifest add` in this project at all.
	seen, r := ve.injected(t, repo)
	if r.code != 0 {
		t.Fatalf("run: %s", r)
	}
	if !strings.Contains(seen, "OPENAI_KEY=openai-key-value-xyz") {
		t.Fatalf("Global Handle not injected:\n%s", seen)
	}
	// And from a subdirectory, which is where a command usually runs.
	sub := filepath.Join(repo, "internal", "cli")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if seen, _ := ve.injected(t, sub); !strings.Contains(seen, "OPENAI_KEY=openai-key-value-xyz") {
		t.Fatalf("Global Handle did not reach a subdirectory:\n%s", seen)
	}
}

func TestGlobalHandleWithheldWithoutAProjectManifest(t *testing.T) {
	ve := newVault(t)
	ve.add("openai/key", "openai-key-value-xyz", "-g")
	seen, r := ve.injected(t, t.TempDir())
	if r.code != 0 {
		t.Fatalf("run: %s", r)
	}
	if strings.Contains(seen, "OPENAI_KEY") {
		t.Fatalf("a directory outside any project must receive nothing:\n%s", seen)
	}
}

func TestGlobalHandleWithheldAcrossANestedRepository(t *testing.T) {
	ve := newVault(t)
	ve.add("openai/key", "openai-key-value-xyz", "-g")
	ve.add("db/url", "postgres://user:pw@host/db")
	repo := ve.project(t)
	if r := ve.runIn(repo, nil, "manifest", "add", "db/url"); r.code != 0 {
		t.Fatalf("manifest add: %s", r)
	}
	// An unfamiliar repo cloned inside the project — the shape that makes a
	// dependency install script dangerous.
	nested := filepath.Join(repo, "tmp", "untrusted")
	if err := os.MkdirAll(filepath.Join(nested, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	seen, r := ve.injected(t, nested)
	if r.code != 0 {
		t.Fatalf("run: %s", r)
	}
	if strings.Contains(seen, "OPENAI_KEY") {
		t.Fatalf("a Global Handle crossed a nested repository boundary:\n%s", seen)
	}
	// The outer project's own declared Handle is unaffected: that has always
	// been what a committed Manifest means, and this feature does not change it.
	if !strings.Contains(seen, "DB_URL=postgres://") {
		t.Fatalf("project Handles must still reach a nested directory:\n%s", seen)
	}
}

func TestProjectManifestOverridesTheGlobalBinding(t *testing.T) {
	ve := newVault(t)
	ve.add("openai/key", "openai-key-value-xyz", "-g")
	repo := ve.project(t)
	if r := ve.runIn(repo, nil, "manifest", "add", "openai/key", "--binding", "PROJECT_SAYS"); r.code != 0 {
		t.Fatalf("manifest add: %s", r)
	}
	seen, _ := ve.injected(t, repo)
	if !strings.Contains(seen, "PROJECT_SAYS=openai-key-value-xyz") {
		t.Fatalf("the project's Binding must win:\n%s", seen)
	}
	if strings.Contains(seen, "OPENAI_KEY=") {
		t.Fatalf("the Global Binding must be replaced, not added alongside:\n%s", seen)
	}
}

func TestBothOptOutsSuppressGlobalHandles(t *testing.T) {
	ve := newVault(t)
	ve.add("openai/key", "openai-key-value-xyz", "-g")
	ve.add("db/url", "postgres://user:pw@host/db")
	repo := ve.project(t)
	ve.runIn(repo, nil, "manifest", "add", "db/url")

	// Per-run.
	seen, _ := ve.injected(t, repo, "--no-global")
	if strings.Contains(seen, "OPENAI_KEY") || !strings.Contains(seen, "DB_URL=") {
		t.Fatalf("--no-global:\n%s", seen)
	}
	// Durable, committed.
	if r := ve.runIn(repo, nil, "manifest", "global", "off"); r.code != 0 || !strings.Contains(r.stdout, "disabled") {
		t.Fatalf("manifest global off: %s", r)
	}
	seen, _ = ve.injected(t, repo)
	if strings.Contains(seen, "OPENAI_KEY") || !strings.Contains(seen, "DB_URL=") {
		t.Fatalf("manifest global off:\n%s", seen)
	}
	// The opt-out survives an unrelated edit to the Manifest.
	ve.add("extra/one", "extra-value-one")
	if r := ve.runIn(repo, nil, "manifest", "add", "extra/one"); r.code != 0 {
		t.Fatalf("manifest add: %s", r)
	}
	seen, _ = ve.injected(t, repo)
	if strings.Contains(seen, "OPENAI_KEY") {
		t.Fatalf("the opt-out was lost when the Manifest was rewritten:\n%s", seen)
	}
	// And it reverses.
	if r := ve.runIn(repo, nil, "manifest", "global", "on"); r.code != 0 || !strings.Contains(r.stdout, "enabled") {
		t.Fatalf("manifest global on: %s", r)
	}
	if seen, _ := ve.injected(t, repo); !strings.Contains(seen, "OPENAI_KEY=") {
		t.Fatalf("manifest global on:\n%s", seen)
	}
	// manifest init --no-global opts a project out from birth.
	fresh := ve.project(t, "--no-global")
	if seen, _ := ve.injected(t, fresh); strings.Contains(seen, "OPENAI_KEY") {
		t.Fatalf("manifest init --no-global:\n%s", seen)
	}
}

func TestStaleGlobalHandleIsSkippedNotFatal(t *testing.T) {
	ve := newVault(t)
	ve.add("ghost/key", "ghost-value-ghostxyz", "-g")
	ve.add("db/url", "postgres://user:pw@host/db")
	repo := ve.project(t)
	ve.runIn(repo, nil, "manifest", "add", "db/url")
	// The Secret is gone but the machine-wide declaration remains: exactly
	// what `cpass rm` without `cpass local` leaves behind.
	if r := ve.run(nil, "rm", "ghost/key"); r.code != 0 {
		t.Fatalf("rm: %s", r)
	}
	seen, r := ve.injected(t, repo)
	if r.code != 0 {
		t.Fatalf("one drifted Global declaration must not break the project: %s", r)
	}
	if !strings.Contains(r.stderr, "ghost/key") || !strings.Contains(r.stderr, "cpass local ghost/key") {
		t.Fatalf("the notice must name the Handle and the cure: %q", r.stderr)
	}
	if !strings.Contains(seen, "DB_URL=postgres://") {
		t.Fatalf("every other Secret must still be injected:\n%s", seen)
	}
	// A missing *project* Handle is still fatal — a committed Manifest is a
	// contract, and this feature does not soften it.
	if r := ve.runIn(repo, nil, "manifest", "add", "sendgrid/key"); r.code != 0 {
		t.Fatalf("manifest add: %s", r)
	}
	_, r = ve.injected(t, repo)
	if r.code == 0 || !strings.Contains(r.stderr, "no such handle: sendgrid/key") {
		t.Fatalf("a missing project Handle must still fail: %s", r)
	}
}

func TestGlobalInvolvedBindingCollisionIsRefused(t *testing.T) {
	ve := newVault(t)
	ve.add("openai/key", "openai-key-value-xyz", "-g", "--binding", "SHARED_VAR")
	ve.add("stripe/live", "stripe-live-value-xyz")
	repo := ve.project(t)
	ve.runIn(repo, nil, "manifest", "add", "stripe/live", "--binding", "SHARED_VAR")
	_, r := ve.injected(t, repo)
	if r.code != 1 || !strings.Contains(r.stderr, "handle collision") || !strings.Contains(r.stderr, "SHARED_VAR") {
		t.Fatalf("a Global-involved collision must be refused: %s", r)
	}
	// With the Global layer out of the way the same project resolves as it
	// always has: no new failure for a project that never opted in.
	if _, r := ve.injected(t, repo, "--no-global"); r.code != 0 {
		t.Fatalf("--no-global must clear the collision: %s", r)
	}
}

func TestGlobalAndLocalPromoteAndDemoteAnExistingHandle(t *testing.T) {
	ve := newVault(t)
	ve.add("openai/key", "openai-key-value-xyz")
	repo := ve.project(t)
	if seen, _ := ve.injected(t, repo); strings.Contains(seen, "OPENAI_KEY") {
		t.Fatalf("not global yet:\n%s", seen)
	}
	if r := ve.run(nil, "global", "openai/key"); r.code != 0 || !strings.Contains(r.stdout, "declared openai/key in ") {
		t.Fatalf("cpass global: %s", r)
	}
	if seen, _ := ve.injected(t, repo); !strings.Contains(seen, "OPENAI_KEY=openai-key-value-xyz") {
		t.Fatalf("cpass global did not take effect:\n%s", seen)
	}
	if r := ve.run(nil, "local", "openai/key"); r.code != 0 || !strings.Contains(r.stdout, "removed openai/key from ") {
		t.Fatalf("cpass local: %s", r)
	}
	if seen, _ := ve.injected(t, repo); strings.Contains(seen, "OPENAI_KEY") {
		t.Fatalf("cpass local did not take effect:\n%s", seen)
	}
	// The Secret itself is untouched: local undeclares, it does not delete.
	if r := ve.run(nil, "ls"); !strings.Contains(r.stdout, "openai/key") {
		t.Fatalf("cpass local must not remove the Secret: %q", r.stdout)
	}
	if r := ve.run(nil, "local", "openai/key"); r.code == 0 || !strings.Contains(r.stderr, "not declared in") {
		t.Fatalf("undeclaring twice should say so: %s", r)
	}
}

func TestManifestAddAndCheckTargetTheGlobalManifest(t *testing.T) {
	ve := newVault(t)
	ve.add("openai/key", "openai-key-value-xyz")
	// -g needs no project to stand in, unlike every other manifest subcommand.
	bare := t.TempDir()
	if r := ve.runIn(bare, nil, "manifest", "add", "openai/key", "-g"); r.code != 0 {
		t.Fatalf("manifest add -g outside a project: %s", r)
	}
	if r := ve.runIn(bare, nil, "manifest", "check", "-g"); r.code != 0 || !strings.Contains(r.stdout, "all 1 handles") {
		t.Fatalf("manifest check -g: %s", r)
	}
	if r := ve.runIn(bare, nil, "manifest", "add", "sendgrid/key", "--global"); r.code != 0 {
		t.Fatalf("manifest add --global: %s", r)
	}
	r := ve.runIn(bare, nil, "manifest", "check", "-g")
	if r.code != 1 || !strings.Contains(r.stderr, "sendgrid/key") {
		t.Fatalf("manifest check -g must name the missing Handle: %s", r)
	}
}

// TestManifestCheckEffectiveShowsTheUnion is the binary-boundary regression
// test for CLA-95: `cpass manifest check --effective` must report the same
// union manifest.Refs computes for `cpass run` — a Global-only Handle
// tagged GLOBAL, the project's own override of a reachable Global default
// tagged OVERRIDES-GLOBAL, an ordinary project-only Handle with neither
// tag, and exit 0 once every effective Handle is available.
func TestManifestCheckEffectiveShowsTheUnion(t *testing.T) {
	ve := newVault(t)
	ve.add("openai/key", "openai-key-value-xyz", "-g")
	ve.add("stripe/live", "stripe-live-value-xyz", "-g", "--binding", "FROM_GLOBAL")
	ve.add("db/url", "postgres-value-xyz")
	repo := ve.project(t)
	ve.runIn(repo, nil, "manifest", "add", "db/url")
	ve.runIn(repo, nil, "manifest", "add", "stripe/live", "--binding", "FROM_PROJECT")

	r := ve.runIn(repo, nil, "manifest", "check", "--effective")
	if r.code != 0 {
		t.Fatalf("manifest check --effective: %s", r)
	}
	for _, want := range []string{"openai/key", "GLOBAL", "stripe/live", "OVERRIDES-GLOBAL", "FROM_PROJECT", "db/url"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("stdout missing %q: %s", want, r)
		}
	}
	if strings.Contains(r.stdout, "FROM_GLOBAL") {
		t.Fatalf("the project's own Binding must be shown, not the Global one: %s", r)
	}

	// A Handle the project declares itself but never stored is MISSING and
	// costs the command a non-zero exit, matching `manifest check`'s own
	// exit-code contract.
	ve.runIn(repo, nil, "manifest", "add", "sendgrid/key")
	r = ve.runIn(repo, nil, "manifest", "check", "--effective")
	if r.code != 1 || !strings.Contains(r.stdout, "sendgrid/key") || !strings.Contains(r.stdout, "MISSING") {
		t.Fatalf("manifest check --effective with a missing handle: %s", r)
	}
}

func TestGlobalHandleInCIModeDegradesToASkip(t *testing.T) {
	ve := newVault(t)
	ve.add("openai/key", "openai-key-value-xyz", "-g")
	repo := ve.project(t)
	ve.add("db/url", "postgres://user:pw@host/db")
	ve.runIn(repo, nil, "manifest", "add", "db/url")
	out := filepath.Join(t.TempDir(), "observed.txt")
	// A CI runner that happens to share a CPASS_HOME carrying a global.toml
	// must not hard-fail on a Handle the project's own Manifest never named.
	r := ve.runIn(repo, []string{"CPASS_CI=1", "DB_URL=ci-db-value", "HELPER_OUT=" + out}, "run", "--", helperBin)
	if r.code != 0 {
		t.Fatalf("CI run: %s", r)
	}
	if !strings.Contains(r.stderr, "openai/key") || !strings.Contains(r.stderr, "OPENAI_KEY is not set") {
		t.Fatalf("CI skip notice: %q", r.stderr)
	}
	seen, _ := os.ReadFile(out)
	if !strings.Contains(string(seen), "DB_URL=ci-db-value") {
		t.Fatalf("CI environment:\n%s", seen)
	}
}

func TestGlobalHandleValuesAreRedactedLikeAnyOther(t *testing.T) {
	ve := newVault(t)
	ve.add("openai/key", leakVal, "-g")
	repo := ve.project(t)
	r := ve.runIn(repo, []string{"CPASS_TEST_TTY=1"}, "run", "--unsafe-allow", "--", "sh", "-c", "echo $OPENAI_KEY")
	if strings.Contains(r.stdout, leakVal) {
		t.Fatalf("a Global Handle's value escaped Redaction: %s", r)
	}
	if !strings.Contains(r.stdout, "[REDACTED:openai/key]") {
		t.Fatalf("want the redaction marker: %s", r)
	}
}

// TestDeclaringAnUnknownHandleGloballyWarns: a typo in a Global declaration
// would otherwise become a skip notice on every run in every project, so it
// is named once, at the moment it is made — without refusing, since
// declaring ahead of storing is legal for any Manifest.
func TestDeclaringAnUnknownHandleGloballyWarns(t *testing.T) {
	ve := newVault(t)
	r := ve.run(nil, "global", "typo/handle")
	if r.code != 0 {
		t.Fatalf("declaring ahead of storing must stay legal: %s", r)
	}
	if !strings.Contains(r.stderr, "not in the Vault yet") {
		t.Fatalf("want a warning naming the gap: %q", r.stderr)
	}
	if !strings.Contains(r.stdout, "declared typo/handle in ") {
		t.Fatalf("the declaration must still be made: %q", r.stdout)
	}
	// A Handle that is there draws no warning.
	ve.add("openai/key", "openai-key-value-xyz")
	if r := ve.run(nil, "global", "openai/key"); r.stderr != "" {
		t.Fatalf("unexpected warning: %q", r.stderr)
	}
}

// TestExplicitWithOnAStaleGlobalHandleStillFails: naming a Handle on the
// command line makes it explicitly requested, so it must hard-fail when it
// cannot be resolved rather than be skipped as a drifted Global declaration.
// The merge that layers --with over the Global set has to clear the ambient
// mark, or an operator who asked for a Secret by name gets a command that
// runs happily without it.
func TestExplicitWithOnAStaleGlobalHandleStillFails(t *testing.T) {
	ve := newVault(t)
	ve.add("openai/key", "openai-key-value-xyz", "-g")
	repo := ve.project(t)
	if r := ve.run(nil, "rm", "openai/key"); r.code != 0 {
		t.Fatalf("rm: %s", r)
	}
	// Ambient: skipped, run proceeds.
	if _, r := ve.injected(t, repo); r.code != 0 {
		t.Fatalf("the ambient case must still be a skip: %s", r)
	}
	// Explicitly asked for: fatal.
	_, r := ve.injected(t, repo, "--with", "openai/key")
	if r.code == 0 || !strings.Contains(r.stderr, "no such handle: openai/key") {
		t.Fatalf("an explicitly requested Handle must hard-fail: %s", r)
	}
	// Same when --with also renames the Binding.
	_, r = ve.injected(t, repo, "--with", "openai/key:MY_VAR")
	if r.code == 0 || !strings.Contains(r.stderr, "no such handle: openai/key") {
		t.Fatalf("--with with a Binding override must hard-fail too: %s", r)
	}
}

// TestAnUnreadableGlobalManifestDoesNotBreakEverything: one corrupt file in
// the ClaudePass home must not stop every project on the machine. The run
// loses its Global Handles and says so; the project's own keep working, and
// a plain `cpass ls` — which never read that file before this feature — does
// not start depending on it at all.
func TestAnUnreadableGlobalManifestDoesNotBreakEverything(t *testing.T) {
	ve := newVault(t)
	ve.add("db/url", "postgres://user:pw@host/db")
	repo := ve.project(t)
	ve.runIn(repo, nil, "manifest", "add", "db/url")
	if err := os.WriteFile(filepath.Join(ve.home, "global.toml"),
		[]byte("[secrets]\nthis line has no equals sign\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	seen, r := ve.injected(t, repo)
	if r.code != 0 {
		t.Fatalf("a corrupt Global Manifest must not fail the run: %s", r)
	}
	if !strings.Contains(r.stderr, "Global Manifest is unreadable") {
		t.Fatalf("want a notice saying why Global Handles are missing: %q", r.stderr)
	}
	if !strings.Contains(seen, "DB_URL=postgres://") {
		t.Fatalf("the project's own Handles must still be injected:\n%s", seen)
	}
	if r := ve.run(nil, "ls"); r.code != 0 || !strings.Contains(r.stdout, "db/url") {
		t.Fatalf("a plain listing must not depend on global.toml: %s", r)
	}
	// Asking about the Global Manifest, though, does report that it is broken.
	if r := ve.run(nil, "ls", "--global"); r.code == 0 {
		t.Fatalf("ls --global should surface the corruption: %s", r)
	}
}

// TestBroadRootRunTimeNoticeFiresOnlyOnce is the live-reproduction
// regression test for CLA-96's major review finding: a Manifest sitting at
// a broad ancestor (here, $HOME — reached the way the ticket describes,
// hand-copied rather than through `cpass manifest init`, which would have
// warned and still written it) must draw the run-time backstop notice on
// the first `cpass run` and stay silent on every one after, exactly as
// docs/THREATS.md item 12 promises ("the first time"). Unsuppressed, this
// line rides straight into an Agent's own Context on every tool call
// (runcmd.go forwards every notice to stderr; the MCP `run_with_secrets`
// tool rides it into the tool_result content block), which is the noise
// this regression closes.
func TestBroadRootRunTimeNoticeFiresOnlyOnce(t *testing.T) {
	ve := newVault(t)
	ve.add("openai/key", "openai-key-value-xyz", "-g")
	root := t.TempDir()
	env := []string{"HOME=" + root}
	if r := ve.runIn(root, env, "manifest", "init"); r.code != 0 {
		t.Fatalf("manifest init: %s", r)
	}
	broadRootNotices := func() int {
		r := ve.runIn(root, env, "run", "--", "true")
		if r.code != 0 {
			t.Fatalf("cpass run: %s", r)
		}
		return strings.Count(r.stderr, "broad ancestor")
	}
	if n := broadRootNotices(); n != 1 {
		t.Fatalf("first cpass run: want exactly 1 broad-root notice, got %d", n)
	}
	if n := broadRootNotices(); n != 0 {
		t.Fatalf("second cpass run: want the notice suppressed, got %d", n)
	}
	if n := broadRootNotices(); n != 0 {
		t.Fatalf("third cpass run: want the notice suppressed, got %d", n)
	}
	// manifest check --effective goes through the same manifest.Refs, so it
	// must not resurrect the notice either.
	r := ve.runIn(root, env, "manifest", "check", "--effective")
	if strings.Count(r.stderr, "broad ancestor") != 0 {
		t.Fatalf("manifest check --effective: want the notice suppressed, got stderr=%q", r.stderr)
	}
}
