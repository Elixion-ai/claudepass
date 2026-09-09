package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"claudepass/internal/license"
)

// Token minting belongs to the license-issuing service in production —
// nothing in cpass itself ever signs a token, it only verifies. These
// tests stand in for that service the same way the harness already stands
// in for a Keychain: by generating a dev keypair directly (crypto/ed25519,
// like newVault generates a raw CPASS_KEY) and trusting it for the
// subprocess via CPASS_TEST_LICENSE_PUBKEY, the e2e-only override in
// internal/license/testhooks_on.go. A release binary has no such override;
// only -tags e2e binaries (what cpassBin is built with) read it.
func devLicenseKeypair(t *testing.T) (priv ed25519.PrivateKey, extraEnv []string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, []string{"CPASS_TEST_LICENSE_PUBKEY=" + base64.StdEncoding.EncodeToString(pub)}
}

func mintToken(t *testing.T, priv ed25519.PrivateKey, plan string, exp time.Time) string {
	t.Helper()
	tok, err := license.Sign(priv, license.Payload{
		Sub:  "dev@example.com",
		Plan: plan,
		Iat:  time.Now().Unix(),
		Exp:  exp.Unix(),
		JTI:  "e2e-test-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

const freeLimitMsg = "cpass: free plan holds 3 Secrets; upgrade at https://claudepass.dev/pricing ($9.99/month)"

func TestFreeTierFourthAddRefused(t *testing.T) {
	ve := newVault(t)
	for _, h := range []string{"a/one", "a/two", "a/three"} {
		if r := ve.add(h, "value-long-enough"); r.code != 0 {
			t.Fatalf("add %s: %s", h, r)
		}
	}
	r := ve.add("a/four", "value-long-enough")
	if r.code != 3 {
		t.Fatalf("4th add: want exit %d, got %s", 3, r)
	}
	if strings.TrimSpace(r.stderr) != freeLimitMsg {
		t.Fatalf("4th add stderr = %q, want %q", strings.TrimSpace(r.stderr), freeLimitMsg)
	}
	// Refused add must not have stored anything.
	ls := ve.run(nil, "ls")
	if strings.Count(strings.TrimSpace(ls.stdout), "\n")+1 != 3 {
		t.Fatalf("vault should still hold exactly 3 handles: %s", ls)
	}
}

func TestAddSucceedsAfterActivate(t *testing.T) {
	ve := newVault(t)
	priv, extra := devLicenseKeypair(t)
	for _, h := range []string{"a/one", "a/two", "a/three"} {
		if r := ve.add(h, "value-long-enough"); r.code != 0 {
			t.Fatalf("add %s: %s", h, r)
		}
	}
	if r := ve.add("a/four", "value-long-enough"); r.code != 3 {
		t.Fatalf("want refused before activation: %s", r)
	}

	tok := mintToken(t, priv, license.PlanPro, time.Now().Add(time.Hour))
	r := ve.runEnv(extra, nil, "license", "activate", tok)
	if r.code != 0 {
		t.Fatalf("activate: %s", r)
	}
	if !strings.Contains(r.stdout, "pro") {
		t.Fatalf("activate stdout should mention the plan: %s", r)
	}

	// The 4th add above only failed to store because it was refused before
	// activation; add it again now that a valid license is active.
	r = ve.runEnv(extra, []byte("value-long-enough\n"), "add", "a/four")
	if r.code != 0 {
		t.Fatalf("4th add after activate: %s", r)
	}
	ls := ve.runEnv(extra, nil, "ls")
	if !strings.Contains(ls.stdout, "a/four") {
		t.Fatalf("a/four should now be stored: %s", ls)
	}
}

func TestLicenseStatusShowsPlan(t *testing.T) {
	ve := newVault(t)
	r := ve.run(nil, "license", "status")
	if r.code != 0 || !strings.Contains(r.stdout, "plan: free") {
		t.Fatalf("status with no license: %s", r)
	}

	priv, extra := devLicenseKeypair(t)
	tok := mintToken(t, priv, license.PlanPro, time.Now().Add(24*time.Hour))
	if r := ve.runEnv(extra, nil, "license", "activate", tok); r.code != 0 {
		t.Fatalf("activate: %s", r)
	}
	r = ve.runEnv(extra, nil, "license", "status")
	if r.code != 0 {
		t.Fatalf("status: %s", r)
	}
	if !strings.Contains(r.stdout, "plan: pro") {
		t.Fatalf("status should show plan pro: %s", r)
	}
	if !strings.Contains(r.stdout, "dev@example.com") || !strings.Contains(r.stdout, "limit: unlimited") {
		t.Fatalf("status should show account and unlimited: %s", r)
	}
}

func TestLicenseDeactivate(t *testing.T) {
	ve := newVault(t)
	priv, extra := devLicenseKeypair(t)
	tok := mintToken(t, priv, license.PlanPro, time.Now().Add(time.Hour))
	if r := ve.runEnv(extra, nil, "license", "activate", tok); r.code != 0 {
		t.Fatalf("activate: %s", r)
	}
	if r := ve.run(nil, "license", "deactivate"); r.code != 0 {
		t.Fatalf("deactivate: %s", r)
	}
	r := ve.run(nil, "license", "status")
	if !strings.Contains(r.stdout, "plan: free") {
		t.Fatalf("status after deactivate should be free: %s", r)
	}
}

func TestActivateTamperedTokenRefused(t *testing.T) {
	ve := newVault(t)
	priv, extra := devLicenseKeypair(t)
	tok := mintToken(t, priv, license.PlanPro, time.Now().Add(time.Hour))
	part1, part2, _ := strings.Cut(tok, ".")
	tampered := part1 + "." + flipOneChar(part2)

	r := ve.runEnv(extra, nil, "license", "activate", tampered)
	if r.code == 0 {
		t.Fatalf("tampered token should be refused: %s", r)
	}
	if !strings.Contains(r.stderr, "refused") {
		t.Fatalf("stderr should say refused: %s", r)
	}
	if _, err := os.Stat(filepath.Join(ve.home, license.FileName)); !os.IsNotExist(err) {
		t.Fatal("a refused activation must not create a license file")
	}
	// Still on the free plan, unaffected by the refused attempt.
	if r := ve.run(nil, "license", "status"); !strings.Contains(r.stdout, "plan: free") {
		t.Fatalf("status after refused activation: %s", r)
	}
}

func flipOneChar(s string) string {
	b := []byte(s)
	if len(b) == 0 {
		return "x"
	}
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}

func TestExpiredLicenseDegradesToFreeWithWarning(t *testing.T) {
	ve := newVault(t)
	priv, extra := devLicenseKeypair(t)
	expired := mintToken(t, priv, license.PlanPro, time.Now().Add(-time.Hour))

	r := ve.runEnv(extra, nil, "license", "activate", expired)
	if r.code != 0 {
		t.Fatalf("activating an already-expired but validly-signed token should still store it: %s", r)
	}
	if !strings.Contains(r.stderr, "expired") || !strings.Contains(r.stderr, "free") {
		t.Fatalf("activate should warn about the expiry: %s", r)
	}

	r = ve.runEnv(extra, nil, "license", "status")
	if !strings.Contains(r.stdout, "plan: free") {
		t.Fatalf("status should show the degraded plan: %s", r)
	}
	if !strings.Contains(r.stderr, "expired") {
		t.Fatalf("status should also warn: %s", r)
	}
}

func TestExpiredLicenseNeverLocksExistingSecrets(t *testing.T) {
	ve := newVault(t)
	priv, extra := devLicenseKeypair(t)

	// Activate a currently-valid pro license and store 5 Secrets under it
	// -- well beyond the free limit.
	valid := mintToken(t, priv, license.PlanPro, time.Now().Add(time.Hour))
	if r := ve.runEnv(extra, nil, "license", "activate", valid); r.code != 0 {
		t.Fatalf("activate: %s", r)
	}
	handles := []string{"a/one", "a/two", "a/three", "a/four", "a/five"}
	for _, h := range handles {
		r := ve.runEnv(extra, []byte("value-long-enough\n"), "add", h)
		if r.code != 0 {
			t.Fatalf("add %s under pro: %s", h, r)
		}
	}

	// The license now expires (simulated by activating an
	// already-expired, validly-signed token for the same account, since
	// the harness cannot fast-forward real time).
	expired := mintToken(t, priv, license.PlanPro, time.Now().Add(-time.Minute))
	if r := ve.runEnv(extra, nil, "license", "activate", expired); r.code != 0 {
		t.Fatalf("activate expired: %s", r)
	}

	// All 5 Secrets are still readable...
	ls := ve.runEnv(extra, nil, "ls")
	if ls.code != 0 {
		t.Fatalf("ls after expiry: %s", ls)
	}
	for _, h := range handles {
		if !strings.Contains(ls.stdout, h) {
			t.Fatalf("ls after expiry missing %s: %s", h, ls)
		}
	}

	// ...and runnable.
	run := ve.runEnv(extra, nil, "run", "--with", "a/one", "--", "true")
	if run.code != 0 {
		t.Fatalf("run after expiry: %s", run)
	}

	// But a *new* Secret is refused: the plan is free again. The refusal
	// line sits alongside the expiry warning, which CheckFreeLimit surfaces
	// on every gated call, not only on this one.
	r := ve.runEnv(extra, []byte("value-long-enough\n"), "add", "a/six")
	if r.code != 3 {
		t.Fatalf("add beyond the limit after expiry: want exit %d, got %s", 3, r)
	}
	if !strings.Contains(r.stderr, freeLimitMsg) {
		t.Fatalf("add beyond the limit after expiry stderr = %q, want it to contain %q", r.stderr, freeLimitMsg)
	}
}

func TestLicenseActivateUsageErrors(t *testing.T) {
	ve := newVault(t)
	if r := ve.run(nil, "license"); r.code != 2 {
		t.Fatalf("bare license: want usage error, got %s", r)
	}
	if r := ve.run(nil, "license", "activate"); r.code != 2 {
		t.Fatalf("activate with no token: want usage error, got %s", r)
	}
	if r := ve.run(nil, "license", "bogus"); r.code != 2 {
		t.Fatalf("unknown subcommand: want usage error, got %s", r)
	}
}

// TestReleaseBinaryIgnoresLicenseTestPubkey is the license-package half of
// TestProductionBinaryHasNoTestHooks: a release build (no -tags e2e) must
// have no way to trust a dev keypair, so a token this test can forge is
// refused exactly like a real tampered token would be.
func TestReleaseBinaryIgnoresLicenseTestPubkey(t *testing.T) {
	bin := buildRelease(t)
	ve := newVault(t)
	priv, extra := devLicenseKeypair(t)
	tok := mintToken(t, priv, license.PlanPro, time.Now().Add(time.Hour))

	r := ve.runBin(bin, extra, nil, "license", "activate", tok)
	if r.code == 0 {
		t.Fatalf("release binary must not trust CPASS_TEST_LICENSE_PUBKEY: %s", r)
	}
	if !strings.Contains(r.stderr, "refused") {
		t.Fatalf("release binary should refuse the forged token: %s", r)
	}
	if _, err := os.Stat(filepath.Join(ve.home, license.FileName)); !os.IsNotExist(err) {
		t.Fatal("release binary must not have stored the forged token")
	}
}
