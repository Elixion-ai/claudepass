package e2e

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	mintOnce sync.Once
	mintBin  string
	mintErr  error
)

// buildMint builds services/license/cmd/mint once per test binary, the
// same lazy-build pattern buildRelease (harness_test.go) uses for cpass
// itself. mint needs no -tags e2e: license.Sign, unlike Verify, never
// consults the e2e-only trusted-key override, so this is the real,
// shippable tool binary — not a test double.
func buildMint(t *testing.T) string {
	t.Helper()
	mintOnce.Do(func() {
		mintBin = filepath.Join(filepath.Dir(cpassBin), "mint")
		cmd := exec.Command("go", "build", "-o", mintBin, "claudepass/services/license/cmd/mint")
		cmd.Stderr = os.Stderr
		mintErr = cmd.Run()
	})
	if mintErr != nil {
		t.Fatal(mintErr)
	}
	return mintBin
}

// TestMintUnderCpassRunActivatesOnBuiltCpass is CLA-43's core acceptance
// bullet: a token minted by services/license/cmd/mint, run the sanctioned
// way (`cpass run --with license/signing-key --`, so the signing key is
// injected by the Broker and never typed, pasted, or seen by an Agent),
// activates on the built cpass binary — and the audit line lands.
//
// It stands in for activating on a *release* cpass binary the same way
// CLA-15's own TestCheckoutWebhookIssuesTokenCpassActivateAccepts does
// (services/license/e2e_test.go): with a generated dev keypair trusted via
// CPASS_TEST_LICENSE_PUBKEY, the e2e-only override that only a -tags e2e
// build reads (internal/license/testhooks_on.go). The real production
// signing key is deliberately never available to this Agent or held in
// this repository (services/license/README.md's NEEDS-HUMAN section) —
// what this proves, that mint's token is exactly the wire format
// license.Verify checks, signed with whatever key LICENSE_SIGNING_KEY
// carries, holds regardless of which key that is.
func TestMintUnderCpassRunActivatesOnBuiltCpass(t *testing.T) {
	mint := buildMint(t)
	ve := newVault(t)
	priv, extra := devLicenseKeypair(t) // internal/e2e/license_test.go's helper

	// The one sanctioned way to hold an owner's signing key on disk at
	// all: as a Secret, injected by `cpass run` under its default Binding
	// for "license/signing-key" (vault.DefaultBindingName) ->
	// LICENSE_SIGNING_KEY, exactly the env var mint reads.
	if r := ve.add("license/signing-key", base64.StdEncoding.EncodeToString(priv)); r.code != 0 {
		t.Fatalf("storing the signing key: %s", r)
	}

	auditPath := filepath.Join(t.TempDir(), "mint-audit.log")
	r := ve.runEnv([]string{"LICENSE_MINT_AUDIT=" + auditPath}, nil,
		"run", "--with", "license/signing-key", "--", mint,
		"--sub", "owner@example.com", "--plan", "pro", "--days", "365")
	if r.code != 0 {
		t.Fatalf("mint under cpass run: %s", r)
	}
	token := strings.TrimSpace(r.stdout)
	if token == "" {
		t.Fatalf("mint printed no token: %s", r)
	}
	if strings.Contains(r.stderr, token) {
		t.Fatalf("token leaked onto stderr: %s", r)
	}

	// The audit line landed, naming the sub/plan, and never the token.
	auditBytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	audit := string(auditBytes)
	if !strings.Contains(audit, "owner@example.com") || !strings.Contains(audit, `"plan":"pro"`) {
		t.Fatalf("audit line missing sub/plan: %s", audit)
	}
	if !strings.Contains(audit, `"jti"`) {
		t.Fatalf("audit line missing jti: %s", audit)
	}
	if strings.Contains(audit, token) {
		t.Fatalf("audit log must never contain the token: %s", audit)
	}

	// The minted token activates on the built cpass binary, on some other
	// machine's CPASS_HOME than the one that minted it.
	home := t.TempDir()
	act := ve.runBin(cpassBin, append(extra, "CPASS_HOME="+home), nil, "license", "activate", token)
	if act.code != 0 {
		t.Fatalf("license activate: %s", act)
	}
	if !strings.Contains(act.stdout, "owner@example.com") || !strings.Contains(act.stdout, "plan pro") {
		t.Fatalf("activate stdout should confirm account and plan: %s", act)
	}

	status := ve.runBin(cpassBin, append(extra, "CPASS_HOME="+home), nil, "license", "status")
	if status.code != 0 || !strings.Contains(status.stdout, "plan: pro") {
		t.Fatalf("status after activation: %s", status)
	}
}

// TestMintNotReachableFromCpassCLI is CLA-43's "not reachable from
// cmd/cpass" bullet at the CLI surface: neither a top-level `cpass mint`
// nor a `cpass license mint` subcommand exists. internal/cli/licensecmds.go
// only ever registers activate/status/deactivate.
func TestMintNotReachableFromCpassCLI(t *testing.T) {
	ve := newVault(t)
	if r := ve.run(nil, "mint"); r.code != 2 || !strings.Contains(r.stderr, "unknown command") {
		t.Fatalf("cpass should have no top-level mint command: %s", r)
	}
	if r := ve.run(nil, "license", "mint"); r.code != 2 || !strings.Contains(r.stderr, "unknown license subcommand") {
		t.Fatalf("cpass license should have no mint subcommand: %s", r)
	}
}

// TestMintPackageNotInCpassBuildGraph is the same bullet at the build-graph
// level: cmd/cpass must not import services/license/cmd/mint (or anything
// under it), so the tool literally cannot end up compiled into the cpass
// binary by accident.
func TestMintPackageNotInCpassBuildGraph(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "claudepass/cmd/cpass").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps claudepass/cmd/cpass: %v: %s", err, out)
	}
	if strings.Contains(string(out), "claudepass/services/license/cmd/mint") {
		t.Fatalf("cmd/cpass's build graph must not include services/license/cmd/mint:\n%s", out)
	}
}
