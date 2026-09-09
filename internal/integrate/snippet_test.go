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
