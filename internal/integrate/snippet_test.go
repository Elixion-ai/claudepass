package integrate

import (
	"strings"
	"testing"
)

func TestApplyFreshFileWritesSection(t *testing.T) {
	got, changed := Apply("")
	if !changed {
		t.Fatal("expected changed on empty content")
	}
	if start, end, ok := findSection(got); !ok || start != 0 || end != len(got) {
		t.Fatalf("section not the whole file: %q", got)
	}
}

func TestApplyPreservesUnrelatedContentAndAppends(t *testing.T) {
	original := "# My Project\n\nSome unrelated setup notes.\n"
	got, changed := Apply(original)
	if !changed {
		t.Fatal("expected changed on unrelated content")
	}
	if !strings.Contains(got, original) {
		t.Fatalf("unrelated content not preserved: %q", got)
	}
	if _, _, ok := findSection(got); !ok {
		t.Fatalf("section not appended: %q", got)
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	original := "# My Project\n\nSome unrelated setup notes.\n"
	once, _ := Apply(original)
	twice, changed := Apply(once)
	if changed {
		t.Fatal("second Apply should report no change")
	}
	if twice != once {
		t.Fatalf("second Apply changed content:\nfirst:  %q\nsecond: %q", once, twice)
	}
}

func TestApplyReplacesStaleSectionInPlace(t *testing.T) {
	before := "before\n" + beginMarker + "\nstale instructions\n" + endMarker + "\nafter\n"
	got, changed := Apply(before)
	if !changed {
		t.Fatal("expected changed when the section is stale")
	}
	if !strings.Contains(got, "before\n") || !strings.Contains(got, "after\n") {
		t.Fatalf("content outside the section not preserved: %q", got)
	}
	if strings.Contains(got, "stale instructions") {
		t.Fatalf("stale section not replaced: %q", got)
	}
	if !strings.Contains(got, Snippet) {
		t.Fatalf("current snippet not written: %q", got)
	}
}

func TestRemoveSectionOnFileWithNoSectionIsANoop(t *testing.T) {
	original := "# My Project\n\nSome unrelated setup notes.\n"
	got, found := RemoveSection(original)
	if found {
		t.Fatal("expected found = false: there is no section to remove")
	}
	if got != original {
		t.Fatalf("content changed with nothing to remove: %q", got)
	}
}

func TestRemoveSectionStripsItAndPreservesTheRest(t *testing.T) {
	original := "# My Project\n\nSome unrelated setup notes.\n"
	withSection, _ := Apply(original)
	got, found := RemoveSection(withSection)
	if !found {
		t.Fatal("expected found = true")
	}
	if got != original {
		t.Fatalf("RemoveSection(Apply(x)) != x:\n got:  %q\nwant: %q", got, original)
	}
	if _, _, ok := findSection(got); ok {
		t.Fatalf("section still present after RemoveSection: %q", got)
	}
}

func TestRemoveSectionOnAFileThatWasOnlyTheSectionLeavesNothing(t *testing.T) {
	withSection, _ := Apply("")
	got, found := RemoveSection(withSection)
	if !found {
		t.Fatal("expected found = true")
	}
	if got != "" {
		t.Fatalf("expected empty result (whole file should be deleted by the caller), got %q", got)
	}
}

func TestRemoveSectionReplacesAStaleSectionCleanly(t *testing.T) {
	// A section written by an older cpass, with different instruction
	// text, must still be recognised and removed by marker alone.
	before := "before\n" + beginMarker + "\nstale instructions\n" + endMarker + "\nafter\n"
	got, found := RemoveSection(before)
	if !found {
		t.Fatal("expected found = true")
	}
	if strings.Contains(got, "stale instructions") || strings.Contains(got, beginMarker) {
		t.Fatalf("stale section not fully removed: %q", got)
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Fatalf("content outside the section not preserved: %q", got)
	}
}

func TestRemoveSectionIsIdempotent(t *testing.T) {
	withSection, _ := Apply("# My Project\n")
	once, _ := RemoveSection(withSection)
	twice, found := RemoveSection(once)
	if found {
		t.Fatal("second RemoveSection should find nothing left to remove")
	}
	if twice != once {
		t.Fatalf("second RemoveSection changed content:\nfirst:  %q\nsecond: %q", once, twice)
	}
}
