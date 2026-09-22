package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Elixion-ai/claudepass/internal/broker"
	"github.com/Elixion-ai/claudepass/internal/vault"
)

// fixture builds a home holding a Global Manifest with the given Handles and
// a project rooted at root/project declaring its own, and returns the project
// root. Every test here points CPASS_HOME at a fresh directory, so nothing
// reads or writes the developer's real Global Manifest.
func fixture(t *testing.T, global, project []Entry) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("CPASS_HOME", home)
	if global != nil {
		gm := &Manifest{Path: filepath.Join(home, GlobalFileName)}
		for _, e := range global {
			gm.Add(e)
		}
		if err := gm.SaveGlobal(); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	m := &Manifest{Path: filepath.Join(root, FileName)}
	for _, e := range project {
		m.Add(e)
	}
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	return root
}

func handles(refs []broker.Ref) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.Handle)
	}
	return out
}

func mkdir(t *testing.T, parts ...string) string {
	t.Helper()
	p := filepath.Join(parts...)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRefsUnionsGlobalUnderProject(t *testing.T) {
	root := fixture(t,
		[]Entry{{Handle: "openai/key"}, {Handle: "stripe/live", Binding: vault.Binding{Name: "FROM_GLOBAL"}}},
		[]Entry{{Handle: "stripe/live", Binding: vault.Binding{Name: "FROM_PROJECT"}}})
	refs, _, err := Refs(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("refs: %+v", refs)
	}
	byHandle := map[string]int{}
	for i, r := range refs {
		byHandle[r.Handle] = i
	}
	openai := refs[byHandle["openai/key"]]
	if !openai.FromGlobal || openai.Declared.Name != "OPENAI_KEY" {
		t.Fatalf("global-only Handle: %+v", openai)
	}
	// The project's own declaration replaces the Global one outright,
	// Binding and FromGlobal mark alike.
	stripe := refs[byHandle["stripe/live"]]
	if stripe.FromGlobal || stripe.Declared.Name != "FROM_PROJECT" {
		t.Fatalf("project must win over Global: %+v", stripe)
	}
}

func TestRefsReachSubdirectoriesOfTheProject(t *testing.T) {
	root := fixture(t, []Entry{{Handle: "openai/key"}}, []Entry{{Handle: "db/url"}})
	sub := mkdir(t, root, "internal", "cli")
	refs, _, err := Refs(sub, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := handles(refs); len(got) != 2 {
		t.Fatalf("a subdirectory of the project must still receive Global Handles, got %v", got)
	}
}

func TestRefsWithheldAcrossANestedRepository(t *testing.T) {
	root := fixture(t, []Entry{{Handle: "openai/key"}}, []Entry{{Handle: "db/url"}})
	// An unfamiliar repo cloned inside an onboarded project: its own .git is
	// the boundary Global Handles do not cross, so an install script it runs
	// cannot reach the machine's ambient Secrets.
	nested := mkdir(t, root, "tmp", "untrusted")
	mkdir(t, nested, ".git")
	refs, _, err := Refs(nested, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		if r.FromGlobal {
			t.Fatalf("Global Handle %s crossed a nested repository boundary", r.Handle)
		}
	}
	// The outer project's own declared Handle still reaches it, exactly as
	// it did before this feature existed.
	if got := handles(refs); len(got) != 1 || got[0] != "db/url" {
		t.Fatalf("project Handles must be unaffected by the gate, got %v", got)
	}
	// A .git *file* (a git worktree or submodule checkout) is a boundary too.
	wt := mkdir(t, root, "tmp", "worktree")
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: /elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	refs, _, err = Refs(wt, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		if r.FromGlobal {
			t.Fatalf("Global Handle %s crossed a .git file boundary", r.Handle)
		}
	}
}

func TestRefsWithoutAProjectManifestReturnsNothing(t *testing.T) {
	fixture(t, []Entry{{Handle: "openai/key"}}, nil)
	// A directory nobody ever introduced to ClaudePass: no Manifest above it,
	// so no Handles at all, Global ones included.
	refs, _, err := Refs(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Fatalf("want no refs outside any project, got %+v", refs)
	}
}

func TestRefsHonoursGlobalDisabledAndIncludeGlobal(t *testing.T) {
	root := fixture(t, []Entry{{Handle: "openai/key"}}, []Entry{{Handle: "db/url"}})
	// The per-run opt-out (cpass run --no-global).
	refs, _, err := Refs(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := handles(refs); len(got) != 1 || got[0] != "db/url" {
		t.Fatalf("includeGlobal=false: %v", got)
	}
	// The durable, committed opt-out (cpass manifest global off).
	m, err := Load(filepath.Join(root, FileName))
	if err != nil {
		t.Fatal(err)
	}
	m.GlobalDisabled = true
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	refs, _, err = Refs(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := handles(refs); len(got) != 1 || got[0] != "db/url" {
		t.Fatalf("GlobalDisabled: %v", got)
	}
}

func TestRefsWithNoGlobalManifestAtAll(t *testing.T) {
	root := fixture(t, nil, []Entry{{Handle: "db/url"}})
	refs, _, err := Refs(root, true)
	if err != nil {
		t.Fatalf("a machine that has never declared a Global Handle must not error: %v", err)
	}
	if got := handles(refs); len(got) != 1 || got[0] != "db/url" {
		t.Fatalf("refs: %v", got)
	}
}

// TestGlobalWithheldThroughASymlinkIntoANestedRepository is the regression
// test for a hole in the boundary walk: it climbs the path lexically while
// the .git check is a syscall the kernel resolves through links, so a link
// at the project root pointing inside a nested repository had a lexical
// parent of the project root itself — stepping clean over the directory that
// holds the nested .git and handing an untrusted tree every Global Handle.
// Package managers and monorepo tools create exactly this shape routinely.
func TestGlobalWithheldThroughASymlinkIntoANestedRepository(t *testing.T) {
	root := fixture(t, []Entry{{Handle: "openai/key"}}, []Entry{{Handle: "db/url"}})
	nested := mkdir(t, root, "vendor", "dep")
	mkdir(t, nested, ".git")
	src := mkdir(t, nested, "src")
	link := filepath.Join(root, "hack")
	if err := os.Symlink(src, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	refs, _, err := Refs(link, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		if r.FromGlobal {
			t.Fatalf("a Global Handle reached %s through a symlink into a nested repository", link)
		}
	}
	// A symlink that stays inside the project is not a boundary: resolving
	// paths must not cost the ordinary case its Global Handles.
	inside := mkdir(t, root, "internal", "cli")
	ok := filepath.Join(root, "shortcut")
	if err := os.Symlink(inside, ok); err != nil {
		t.Fatal(err)
	}
	refs, _, err = Refs(ok, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("a symlink within the project must still receive Global Handles, got %v", handles(refs))
	}
}

// TestUnreadableGlobalManifestCostsOnlyItsOwnHandles: the machine-wide layer
// is ambient, so a global.toml that will not parse must not take down every
// project on the machine at once — the project's own committed Handles still
// resolve, and the human hears why the ambient ones did not.
func TestUnreadableGlobalManifestCostsOnlyItsOwnHandles(t *testing.T) {
	root := fixture(t, []Entry{{Handle: "openai/key"}}, []Entry{{Handle: "db/url"}})
	p, err := GlobalPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("[secrets]\nthis line has no equals sign\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	refs, notices, err := Refs(root, true)
	if err != nil {
		t.Fatalf("a corrupt Global Manifest must not fail the run: %v", err)
	}
	if got := handles(refs); len(got) != 1 || got[0] != "db/url" {
		t.Fatalf("the project's own Handles must still resolve, got %v", got)
	}
	if len(notices) != 1 || !strings.Contains(notices[0], "Global Manifest is unreadable") {
		t.Fatalf("notices: %v", notices)
	}
	// A corrupt *project* Manifest is still fatal: it is a committed contract.
	if err := os.WriteFile(filepath.Join(root, FileName), []byte("[secrets]\n\"Bad Handle\" = \"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Refs(root, true); err == nil {
		t.Fatal("a corrupt project Manifest must still be fatal")
	}
}

// TestGlobalReachableMatchesRefs is the regression seam for cpass manifest
// check --effective: GlobalReachable must agree with what Refs itself would
// have done — true for an onboarded project's own root and subdirectories,
// false outside any project, across a nested repository, and once the
// project opts out (per-Handle presence in the merged Refs list already
// covers the Global-Manifest-missing-entirely case).
func TestGlobalReachableMatchesRefs(t *testing.T) {
	root := fixture(t, []Entry{{Handle: "openai/key"}}, []Entry{{Handle: "db/url"}})

	if reachable, err := GlobalReachable(root); err != nil || !reachable {
		t.Fatalf("the project's own root must be reachable: %v %v", reachable, err)
	}
	sub := mkdir(t, root, "internal", "cli")
	if reachable, err := GlobalReachable(sub); err != nil || !reachable {
		t.Fatalf("a subdirectory of the project must be reachable: %v %v", reachable, err)
	}

	outside := t.TempDir()
	if reachable, err := GlobalReachable(outside); err != nil || reachable {
		t.Fatalf("a directory outside any project must not be reachable: %v %v", reachable, err)
	}

	nested := mkdir(t, root, "tmp", "untrusted")
	mkdir(t, nested, ".git")
	if reachable, err := GlobalReachable(nested); err != nil || reachable {
		t.Fatalf("a nested repository must not be reachable: %v %v", reachable, err)
	}

	m, err := Load(filepath.Join(root, FileName))
	if err != nil {
		t.Fatal(err)
	}
	m.GlobalDisabled = true
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	if reachable, err := GlobalReachable(root); err != nil || reachable {
		t.Fatalf("an opted-out project must not be reachable: %v %v", reachable, err)
	}
}

// TestRefsWarnsWhenABroadRootManifestServesAGlobalHandle is the regression
// test for CLA-96: a Manifest whose own root is a broad ancestor (here,
// $HOME) must draw a run-time notice the moment it actually hands the
// caller a Global Handle — the backstop for a Manifest that ended up broad
// some way other than `cpass manifest init` (hand-copied, git-cloned
// straight into $HOME).
func TestRefsWarnsWhenABroadRootManifestServesAGlobalHandle(t *testing.T) {
	root := fixture(t, []Entry{{Handle: "openai/key"}}, nil)
	t.Setenv("HOME", root)
	refs, notices, err := Refs(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := handles(refs); len(got) != 1 || got[0] != "openai/key" {
		t.Fatalf("the Global Handle must still be served: %v", got)
	}
	found := false
	for _, n := range notices {
		if strings.Contains(n, "broad ancestor") && strings.Contains(n, root) {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a broad-root notice naming %s, got %v", root, notices)
	}
}

// TestRefsStaysQuietForAnOrdinaryProjectRoot is the flip side: an ordinary
// project directory — never $HOME, never / — must never draw the
// broad-root notice, however many Global Handles it receives.
func TestRefsStaysQuietForAnOrdinaryProjectRoot(t *testing.T) {
	root := fixture(t, []Entry{{Handle: "openai/key"}, {Handle: "stripe/live"}}, nil)
	_, notices, err := Refs(root, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range notices {
		if strings.Contains(n, "broad ancestor") {
			t.Fatalf("an ordinary project root must never draw the broad-root notice: %v", notices)
		}
	}
}

// TestRefsBroadRootStaysQuietWithNoGlobalHandleServed: the warning is about
// a broad-root Manifest actually serving a Global Handle, not merely
// existing at a broad root — a machine with nothing declared globally yet
// must not be warned about a hazard that has no effect yet.
func TestRefsBroadRootStaysQuietWithNoGlobalHandleServed(t *testing.T) {
	root := fixture(t, nil, []Entry{{Handle: "db/url"}})
	t.Setenv("HOME", root)
	_, notices, err := Refs(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(notices) != 0 {
		t.Fatalf("no Global Handle was served, so no notice should fire: %v", notices)
	}
}
