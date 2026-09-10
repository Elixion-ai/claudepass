package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const saJSON = `{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n"}`

func fileVault(t *testing.T) *vaultEnv {
	t.Helper()
	ve := newVault(t)
	if r := ve.add("gcp/sa", saJSON, "--file", "--binding", "GOOGLE_APPLICATION_CREDENTIALS"); r.code != 0 {
		t.Fatalf("add: %s", r)
	}
	return ve
}

func runDirs(t *testing.T, ve *vaultEnv) []os.DirEntry {
	t.Helper()
	entries, _ := os.ReadDir(filepath.Join(ve.home, "run"))
	return entries
}

func TestFileBindingMaterialisedAndDestroyed(t *testing.T) {
	ve := fileVault(t)
	r := ve.run(nil, "run", "--with", "gcp/sa", "--", "sh", "-c",
		`test -f "$GOOGLE_APPLICATION_CREDENTIALS" && wc -c < "$GOOGLE_APPLICATION_CREDENTIALS" && stat -f %Lp "$GOOGLE_APPLICATION_CREDENTIALS" 2>/dev/null || stat -c %a "$GOOGLE_APPLICATION_CREDENTIALS"`)
	if r.code != 0 {
		t.Fatalf("run: %s", r)
	}
	if !strings.Contains(r.stdout, itoa(len(saJSON))) {
		t.Fatalf("want byte count %d: %s", len(saJSON), r)
	}
	if !strings.Contains(r.stdout, "600") {
		t.Fatalf("want mode 600: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, "BEGIN PRIVATE") {
		t.Fatalf("leaked: %s", r)
	}
	if d := runDirs(t, ve); len(d) != 0 {
		t.Fatalf("run dir not cleaned: %v", d)
	}
}

func TestFileBindingPathIsPrivate(t *testing.T) {
	ve := fileVault(t)
	r := ve.run(nil, "run", "--with", "gcp/sa", "--", "sh", "-c", `dirname "$GOOGLE_APPLICATION_CREDENTIALS" | xargs stat -f %Lp 2>/dev/null || dirname "$GOOGLE_APPLICATION_CREDENTIALS" | xargs stat -c %a`)
	if r.code != 0 || !strings.Contains(r.stdout, "700") {
		t.Fatalf("dir mode: %s", r)
	}
}

func TestFileBindingReadersRefused(t *testing.T) {
	ve := fileVault(t)
	for _, script := range []string{
		`cat "$GOOGLE_APPLICATION_CREDENTIALS"`,
		`base64 $GOOGLE_APPLICATION_CREDENTIALS`,
		`cp "$GOOGLE_APPLICATION_CREDENTIALS" /tmp/stolen`,
		`grep . "$GOOGLE_APPLICATION_CREDENTIALS"`,
	} {
		r := ve.run(nil, "run", "--with", "gcp/sa", "--", "sh", "-c", script)
		if r.code != 3 || !strings.Contains(r.stderr, "refused") {
			t.Fatalf("%s: want refusal, got %s", script, r)
		}
	}
	if d := runDirs(t, ve); len(d) != 0 {
		t.Fatalf("run dir left behind after refusal: %v", d)
	}
}

func TestFileBindingContentRedactedEvenWhenDumped(t *testing.T) {
	ve := fileVault(t)
	r := ve.runEnv([]string{"CPASS_TEST_TTY=1"}, nil, "run", "--unsafe-allow", "--with", "gcp/sa", "--", "sh", "-c", `cat "$GOOGLE_APPLICATION_CREDENTIALS"`)
	if r.code != 0 {
		t.Fatalf("run: %s", r)
	}
	if strings.Contains(r.stdout, "BEGIN PRIVATE") || strings.Contains(r.stdout, "service_account") {
		t.Fatalf("content leaked: %s", r)
	}
	if !strings.Contains(r.stdout, "[REDACTED:gcp/sa]") {
		t.Fatalf("marker missing: %s", r)
	}
}

func TestFileBindingCleanedAfterSignalDeath(t *testing.T) {
	ve := fileVault(t)
	r := ve.runEnv([]string{"HELPER_KILL=9"}, nil, "run", "--with", "gcp/sa", "--", helperBin)
	if r.code != 137 {
		t.Fatalf("want 137: %s", r)
	}
	if d := runDirs(t, ve); len(d) != 0 {
		t.Fatalf("run dir not cleaned after SIGKILL: %v", d)
	}
}

func TestStaleRunDirSwept(t *testing.T) {
	ve := fileVault(t)
	stale := filepath.Join(ve.home, "run", "deadbeefdeadbeef")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, ".pid"), []byte("999999"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "gcp-sa"), []byte("leftover"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := ve.run(nil, "run", "--with", "gcp/sa", "--", "true")
	if r.code != 0 {
		t.Fatalf("run: %s", r)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Fatal("stale run dir should have been swept")
	}
}

func TestManifestFileBindingInjectsPath(t *testing.T) {
	ve := fileVault(t)
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, ".claudepass.toml"), []byte("[secrets]\n\"gcp/sa\" = { binding = \"GCP_KEY_FILE\", kind = \"file\" }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "env.txt")
	r := ve.runIn(repo, []string{"HELPER_OUT=" + out}, "run", "--", helperBin)
	if r.code != 0 {
		t.Fatalf("run: %s", r)
	}
	env, _ := os.ReadFile(out)
	if !strings.Contains(string(env), "GCP_KEY_FILE="+filepath.Join(ve.home, "run")) {
		t.Fatalf("path not injected under declared name:\n%s", env)
	}
	if strings.Contains(string(env), "service_account") {
		t.Fatal("value injected instead of path")
	}
}
