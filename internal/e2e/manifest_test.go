package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runIn runs cpass in dir (so the Manifest is found from the cwd).
func (ve *vaultEnv) runIn(dir string, extra []string, args ...string) result {
	ve.t.Helper()
	cmd := exec.Command(cpassBin, args...)
	cmd.Dir = dir
	cmd.Env = append(baseEnv(), "CPASS_HOME="+ve.home, "CPASS_KEY="+ve.key)
	cmd.Env = append(cmd.Env, extra...)
	out, errb := new(strings.Builder), new(strings.Builder)
	cmd.Stdout, cmd.Stderr = out, errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		ve.t.Fatal(err)
	}
	return result{code: code, stdout: out.String(), stderr: errb.String()}
}

func TestManifestInitAddCheckAndRun(t *testing.T) {
	ve := newVault(t)
	ve.add("stripe/live", leakVal)
	ve.add("db/url", "postgres://user:pw@host/db")
	repo := t.TempDir()
	if r := ve.runIn(repo, nil, "manifest", "init"); r.code != 0 {
		t.Fatalf("init: %s", r)
	}
	if r := ve.runIn(repo, nil, "manifest", "init"); r.code == 0 {
		t.Fatalf("second init should fail: %s", r)
	}
	if r := ve.runIn(repo, nil, "manifest", "add", "stripe/live", "--binding", "STRIPE_SECRET_KEY"); r.code != 0 {
		t.Fatalf("add: %s", r)
	}
	if r := ve.runIn(repo, nil, "manifest", "add", "db/url"); r.code != 0 {
		t.Fatalf("add: %s", r)
	}
	raw, _ := os.ReadFile(filepath.Join(repo, ".claudepass.toml"))
	for _, forbidden := range []string{leakVal, "postgres://"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("manifest contains a value: %s", raw)
		}
	}
	if r := ve.runIn(repo, nil, "manifest", "check"); r.code != 0 || !strings.Contains(r.stdout, "all 2 handles") {
		t.Fatalf("check: %s", r)
	}
	// From a subdirectory, run with no --with injects both.
	sub := filepath.Join(repo, "src", "deep")
	os.MkdirAll(sub, 0o755)
	out := filepath.Join(t.TempDir(), "env.txt")
	r := ve.runIn(sub, []string{"HELPER_OUT=" + out}, "run", "--", helperBin)
	if r.code != 0 {
		t.Fatalf("run: %s", r)
	}
	env, _ := os.ReadFile(out)
	if !strings.Contains(string(env), "STRIPE_SECRET_KEY="+leakVal) || !strings.Contains(string(env), "DB_URL=postgres://") {
		t.Fatalf("manifest handles not injected:\n%s", env)
	}
	// --with adds to the Manifest set and can override a declared Binding.
	ve.add("extra/one", "extra-value-one")
	r = ve.runIn(sub, []string{"HELPER_OUT=" + out}, "run", "--with", "extra/one", "--with", "stripe/live:SK", "--", helperBin)
	env, _ = os.ReadFile(out)
	if r.code != 0 || !strings.Contains(string(env), "EXTRA_ONE=extra-value-one") || !strings.Contains(string(env), "SK="+leakVal) {
		t.Fatalf("with + manifest: %s\n%s", r, env)
	}
}

func TestManifestCheckNamesMissingHandlesOnly(t *testing.T) {
	ve := newVault(t)
	ve.add("stripe/live", leakVal)
	repo := t.TempDir()
	ve.runIn(repo, nil, "manifest", "init")
	ve.runIn(repo, nil, "manifest", "add", "stripe/live")
	ve.runIn(repo, nil, "manifest", "add", "sendgrid/key")
	r := ve.runIn(repo, nil, "manifest", "check")
	if r.code != 1 || !strings.Contains(r.stderr, "1 missing") || !strings.Contains(r.stderr, "sendgrid/key") || strings.Contains(r.stderr, "stripe/live") {
		t.Fatalf("check: %s", r)
	}
	r = ve.runIn(repo, nil, "run", "--", helperBin)
	if r.code == 0 || !strings.Contains(r.stderr, "no such handle: sendgrid/key") {
		t.Fatalf("run with missing manifest handle: %s", r)
	}
}

func TestManifestFileBindingDeclaration(t *testing.T) {
	ve := newVault(t)
	repo := t.TempDir()
	ve.runIn(repo, nil, "manifest", "init")
	r := ve.runIn(repo, nil, "manifest", "add", "gcp/sa", "--file", "--binding", "GOOGLE_APPLICATION_CREDENTIALS")
	if r.code != 0 {
		t.Fatalf("add file: %s", r)
	}
	raw, _ := os.ReadFile(filepath.Join(repo, ".claudepass.toml"))
	if !strings.Contains(string(raw), `kind = "file"`) {
		t.Fatalf("file kind not declared: %s", raw)
	}
}

func TestCIModeResolvesFromEnvironmentWithoutVault(t *testing.T) {
	ve := &vaultEnv{t: t, home: t.TempDir(), key: ""} // no vault at all
	repo := t.TempDir()
	os.WriteFile(filepath.Join(repo, ".claudepass.toml"), []byte("[secrets]\n\"stripe/live\" = \"STRIPE_SECRET_KEY\"\n\"db/url\" = \"\"\n"), 0o644)
	out := filepath.Join(t.TempDir(), "env.txt")
	ci := []string{"CPASS_CI=1", "STRIPE_SECRET_KEY=ci-stripe-value", "DB_URL=ci-db-value", "HELPER_OUT=" + out}
	r := ve.runIn(repo, ci, "run", "--", helperBin)
	if r.code != 0 {
		t.Fatalf("ci run: %s", r)
	}
	env, _ := os.ReadFile(out)
	if !strings.Contains(string(env), "STRIPE_SECRET_KEY=ci-stripe-value") || !strings.Contains(string(env), "DB_URL=ci-db-value") {
		t.Fatalf("ci env:\n%s", env)
	}
	// Redaction still applies in CI mode.
	r = ve.runIn(repo, []string{"CPASS_CI=1", "STRIPE_SECRET_KEY=ci-stripe-value", "DB_URL=ci-db-value", "CPASS_TEST_TTY=1"}, "run", "--unsafe-allow", "--", "sh", "-c", "echo $STRIPE_SECRET_KEY")
	if strings.Contains(r.stdout, "ci-stripe-value") || !strings.Contains(r.stdout, "[REDACTED:stripe/live]") {
		t.Fatalf("ci redaction: %s", r)
	}
	// Missing variable names the Handle and the variable.
	r = ve.runIn(repo, []string{"CPASS_CI=1", "STRIPE_SECRET_KEY=x"}, "run", "--", helperBin)
	if r.code == 0 || !strings.Contains(r.stderr, "db/url expects DB_URL") {
		t.Fatalf("ci missing: %s", r)
	}
	// CI=true with no Vault also triggers CI mode; manifest check reports env.
	r = ve.runIn(repo, []string{"CI=true", "STRIPE_SECRET_KEY=x"}, "manifest", "check")
	if r.code != 1 || !strings.Contains(r.stderr, "db/url (DB_URL)") {
		t.Fatalf("ci check: %s", r)
	}
}

func TestRunWithoutManifestOrWithJustRuns(t *testing.T) {
	ve := newVault(t)
	r := ve.runIn(t.TempDir(), nil, "run", "--", "true")
	if r.code != 0 {
		t.Fatalf("no Handles should still run: %s", r)
	}
}
