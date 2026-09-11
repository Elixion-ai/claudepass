// W26: the "Excluded Clichés" icon guardrail (CONTEXT.md's Excluded icons
// list) is otherwise only a written rule — this test makes it enforceable.
// It fails the build the moment a new SVG lands under site/assets/ whose
// filename suggests one of the five banned generic-security clichés
// (Padlock, Hoodie-Hacker Shield, Matrix-Rain, Sparkle/Starburst, Soft
// Rounded Keyhole), so the check exists in CI without anyone remembering to
// look at CONTEXT.md during review.
package site

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// excludedIconTerms mirrors CONTEXT.md's "Excluded icons" list. Keep the two
// in sync: a term added to one belongs in the other.
var excludedIconTerms = []string{
	"lock", "padlock", "shield", "hoodie", "hacker", "matrix", "sparkle", "starburst", "keyhole",
}

func TestNoExcludedIconFilenames(t *testing.T) {
	root := filepath.FromSlash("../../site/assets")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(path), ".svg") {
			return nil
		}
		name := strings.ToLower(d.Name())
		for _, term := range excludedIconTerms {
			if strings.Contains(name, term) {
				t.Errorf("%s: filename matches excluded-cliché term %q — see CONTEXT.md's Excluded icons list (Padlock, Hoodie-Hacker Shield, Matrix-Rain, Sparkle/Starburst, Soft Rounded Keyhole)", path, term)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
}
