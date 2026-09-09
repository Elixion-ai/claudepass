package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withTestKeypair swaps trustedPublicKey for a fresh test pair for the
// duration of one test, and returns the matching private key to sign with.
// This is a same-package (white-box) test, so it can reach the unexported
// var directly instead of needing the e2e env-var hook, which exists only
// to reach a *built binary* from outside the package.
func withTestKeypair(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	orig := trustedPublicKey
	trustedPublicKey = pub
	t.Cleanup(func() { trustedPublicKey = orig })
	return priv
}

func validPayload() Payload {
	now := time.Now().Unix()
	return Payload{Sub: "dev@example.com", Plan: PlanPro, Iat: now, Exp: now + 3600, JTI: "test-jti-1"}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := withTestKeypair(t)
	p := validPayload()
	tok, err := Sign(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tok, ".") {
		t.Fatalf("token should have two dot-separated segments: %q", tok)
	}
	got, err := Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != p {
		t.Fatalf("payload round-trip mismatch: got %+v, want %+v", got, p)
	}
}

func TestVerifyRejectsForgedKey(t *testing.T) {
	withTestKeypair(t) // trusted key is now this test's pub; sign with a different pair
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	tok, err := Sign(otherPriv, validPayload())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(tok); err != ErrSignature {
		t.Fatalf("want ErrSignature, got %v", err)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	priv := withTestKeypair(t)
	tok, err := Sign(priv, validPayload())
	if err != nil {
		t.Fatal(err)
	}
	part1, part2, _ := strings.Cut(tok, ".")
	// Flip a character in the payload segment: signature no longer matches.
	tampered := flipChar(part1) + "." + part2
	if _, err := Verify(tampered); err != ErrSignature {
		t.Fatalf("want ErrSignature, got %v", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	priv := withTestKeypair(t)
	tok, err := Sign(priv, validPayload())
	if err != nil {
		t.Fatal(err)
	}
	part1, part2, _ := strings.Cut(tok, ".")
	tampered := part1 + "." + flipChar(part2)
	if _, err := Verify(tampered); err != ErrSignature {
		t.Fatalf("want ErrSignature, got %v", err)
	}
}

// flipChar flips the token's first byte, so the caller gets a
// same-length string that differs from the original in exactly one
// place. 'A' flips to 'B' so the result is never mistaken for a no-op.
func flipChar(s string) string {
	if s == "" {
		return "x"
	}
	b := []byte(s)
	if b[0] != 'A' {
		b[0] = 'A'
	} else {
		b[0] = 'B'
	}
	return string(b)
}

func TestVerifyRejectsMalformed(t *testing.T) {
	withTestKeypair(t)
	cases := []string{
		"",
		"no-dot-at-all",
		"onlyonepart.",
		".onlysecondpart",
		"not-base64!!!.also-not-base64!!!",
	}
	for _, c := range cases {
		if _, err := Verify(c); err == nil {
			t.Errorf("Verify(%q): want error, got nil", c)
		} else if err == ErrSignature {
			t.Errorf("Verify(%q): want malformed, got ErrSignature", c)
		}
	}
}

func TestNeedsUpgrade(t *testing.T) {
	cases := []struct {
		name  string
		st    Status
		count int
		want  bool
	}{
		{"free under limit", Status{Plan: PlanFree}, 2, false},
		{"free at limit", Status{Plan: PlanFree}, 3, true},
		{"free over limit", Status{Plan: PlanFree}, 5, true},
		{"pro at what would be the limit", Status{Plan: PlanPro}, 3, false},
		{"pro far over", Status{Plan: PlanPro}, 500, false},
		{"free empty vault", Status{Plan: PlanFree}, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.st.NeedsUpgrade(c.count); got != c.want {
				t.Errorf("NeedsUpgrade(%d) = %v, want %v", c.count, got, c.want)
			}
		})
	}
}

func TestLoadNoStoredToken(t *testing.T) {
	home := t.TempDir()
	st := Load(home)
	if st.Plan != PlanFree || st.Payload != nil || st.Warning != "" {
		t.Fatalf("no token: want plain free Status, got %+v", st)
	}
}

func TestLoadValidUnexpiredToken(t *testing.T) {
	priv := withTestKeypair(t)
	home := t.TempDir()
	p := validPayload()
	tok, err := Sign(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Activate(home, tok); err != nil {
		t.Fatal(err)
	}
	st := Load(home)
	if st.Plan != PlanPro || st.Warning != "" {
		t.Fatalf("valid token: want pro with no warning, got %+v", st)
	}
	if st.Payload == nil || st.Payload.Sub != p.Sub {
		t.Fatalf("payload not carried through: %+v", st.Payload)
	}
}

func TestLoadExpiredTokenDegradesWithWarning(t *testing.T) {
	priv := withTestKeypair(t)
	home := t.TempDir()
	now := time.Now().Unix()
	p := Payload{Sub: "dev@example.com", Plan: PlanPro, Iat: now - 7200, Exp: now - 3600, JTI: "expired-1"}
	tok, err := Sign(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Activate(home, tok); err != nil {
		t.Fatal(err)
	}
	st := Load(home)
	if st.Plan != PlanFree {
		t.Fatalf("expired token should degrade to free plan, got %q", st.Plan)
	}
	if st.Warning == "" {
		t.Fatal("expired token should carry a warning")
	}
	if st.Payload == nil || st.Payload.Sub != p.Sub {
		t.Fatalf("expired token should still report its payload, got %+v", st.Payload)
	}
	if !st.NeedsUpgrade(3) {
		t.Fatal("degraded-to-free Status should gate the free limit")
	}
}

func TestActivateRefusesBadSignatureAndDoesNotStore(t *testing.T) {
	withTestKeypair(t) // trusted key set; sign with an unrelated key below
	home := t.TempDir()
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	tok, err := Sign(otherPriv, validPayload())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Activate(home, tok); err != ErrSignature {
		t.Fatalf("want ErrSignature, got %v", err)
	}
	if _, err := os.Stat(Path(home)); !os.IsNotExist(err) {
		t.Fatal("a refused activation must not write a license file")
	}
}

func TestDeactivateIsIdempotent(t *testing.T) {
	home := t.TempDir()
	if err := Deactivate(home); err != nil {
		t.Fatalf("deactivate on empty home: %v", err)
	}
	priv := withTestKeypair(t)
	tok, _ := Sign(priv, validPayload())
	if _, err := Activate(home, tok); err != nil {
		t.Fatal(err)
	}
	if err := Deactivate(home); err != nil {
		t.Fatal(err)
	}
	if st := Load(home); st.Plan != PlanFree || st.Payload != nil {
		t.Fatalf("after deactivate: want plain free, got %+v", st)
	}
	if err := Deactivate(home); err != nil {
		t.Fatalf("second deactivate should still be a no-op: %v", err)
	}
}

func TestActivateWritesFileMode0600(t *testing.T) {
	priv := withTestKeypair(t)
	home := t.TempDir()
	tok, _ := Sign(priv, validPayload())
	if _, err := Activate(home, tok); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(home, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("license file mode = %v, want 0600", fi.Mode().Perm())
	}
}
