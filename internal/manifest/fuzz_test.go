package manifest

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Elixion-ai/claudepass/internal/broker"
)

// FuzzManifestLoad feeds arbitrary text through Load (via a temp file,
// since Load reads from disk), seeded from TestRoundTripAndFind's own
// written form and a few malformed shapes. It asserts no panic and that
// Save(Load(x)) is stable: saving what was just loaded and loading that
// back must reproduce the identical parsed Manifest.
func FuzzManifestLoad(f *testing.F) {
	seeds := []string{
		"[secrets]\n\"stripe/live\" = \"STRIPE_SECRET_KEY\"\n\"gcp/sa\" = { binding = \"GOOGLE_APPLICATION_CREDENTIALS\", kind = \"file\" }\n\"github/token\" = \"\"\n",
		"[options]\nglobal = false\n\n[secrets]\n\"a/b\" = \"\"\n",
		"[options]\nsomething-newer = true\n\n[secrets]\n",
		"[unknown-section]\nsome = line\n\n[secrets]\n\"x/y\" = \"Z\"\n",
		"",
		"not a section or assignment\n",
		"[secrets]\nno-equals-sign\n",
		"[secrets]\n\"bad handle!\" = \"X\"\n",
		"[secrets]\n\"a/b\" = { kind = \"bogus\" }\n",
		"[secrets]\n\"a/b\" = \"quote\\\"inside\"\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		dir := t.TempDir()
		path := filepath.Join(dir, FileName)
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		m, err := Load(path)
		if err != nil {
			// Invalid input: nothing further to assert. Load must not
			// panic, which f.Fuzz itself already enforces.
			return
		}
		if err := m.Save(); err != nil {
			t.Fatalf("Save after Load failed: %v\nsource: %q", err, src)
		}
		again, err := Load(path)
		if err != nil {
			t.Fatalf("re-Load after Save failed: %v\nsource: %q", err, src)
		}
		if !reflect.DeepEqual(m.Entries, again.Entries) || m.GlobalDisabled != again.GlobalDisabled {
			t.Fatalf("Save(Load(x)) not stable\nsource: %q\nfirst:  %+v (GlobalDisabled=%v)\nsecond: %+v (GlobalDisabled=%v)",
				src, m.Entries, m.GlobalDisabled, again.Entries, again.GlobalDisabled)
		}
	})
}

// FuzzLoadGlobal is FuzzManifestLoad's counterpart for the Global Manifest:
// same file format, loaded and saved through LoadGlobal/SaveGlobal instead,
// which additionally exercise GlobalPath's dependency on broker.Home and
// SaveGlobal's directory creation.
func FuzzLoadGlobal(f *testing.F) {
	seeds := []string{
		"[secrets]\n\"openai/key\" = \"OPENAI_API_KEY\"\n",
		"",
		"[secrets]\n\"a/b\" = { binding = \"C\", kind = \"file\" }\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		home := t.TempDir()
		t.Setenv(broker.EnvHome, home)
		path, err := GlobalPath()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		m, err := LoadGlobal()
		if err != nil {
			return
		}
		if err := m.SaveGlobal(); err != nil {
			t.Fatalf("SaveGlobal after LoadGlobal failed: %v\nsource: %q", err, src)
		}
		again, err := LoadGlobal()
		if err != nil {
			t.Fatalf("re-LoadGlobal after SaveGlobal failed: %v\nsource: %q", err, src)
		}
		if !reflect.DeepEqual(m.Entries, again.Entries) || m.GlobalDisabled != again.GlobalDisabled {
			t.Fatalf("SaveGlobal(LoadGlobal(x)) not stable\nsource: %q\nfirst:  %+v (GlobalDisabled=%v)\nsecond: %+v (GlobalDisabled=%v)",
				src, m.Entries, m.GlobalDisabled, again.Entries, again.GlobalDisabled)
		}
	})
}
