package e2e

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every test here is one known reveal path. Each asserts that the raw value
// never reaches stdout or stderr, and that a marker naming the Handle does.
// Command Policy will later refuse several of these outright; Redaction
// alone must already hold the line.

const leakVal = "sk_live_LEAKTESTvalue0123456"

func leakVault(t *testing.T) *vaultEnv {
	t.Helper()
	ve := newVault(t)
	ve.add("stripe/live", leakVal)
	return ve
}

func assertRedacted(t *testing.T, r result, extraForbidden ...string) {
	t.Helper()
	all := r.stdout + r.stderr
	if strings.Contains(all, leakVal) {
		t.Fatalf("raw value leaked: %s", r)
	}
	for _, f := range extraForbidden {
		if f != "" && strings.Contains(all, f) {
			t.Fatalf("encoded value %q leaked: %s", f, r)
		}
	}
	if !strings.Contains(all, "[REDACTED:stripe/live]") {
		t.Fatalf("marker missing: %s", r)
	}
}

func sh(ve *vaultEnv, script string) result {
	return ve.run(nil, "run", "--with", "stripe/live", "--", "sh", "-c", script)
}

func TestLeakEchoVar(t *testing.T) {
	assertRedacted(t, sh(leakVault(t), `echo "$STRIPE_LIVE"`))
}

func TestLeakEnvDump(t *testing.T) {
	r := sh(leakVault(t), `env`)
	assertRedacted(t, r)
	if !strings.Contains(r.stdout, "STRIPE_LIVE=[REDACTED:stripe/live]") {
		t.Fatalf("env line should show the marker: %s", r)
	}
}

func TestLeakPrintenv(t *testing.T) {
	assertRedacted(t, sh(leakVault(t), `printenv STRIPE_LIVE`))
}

func TestLeakBase64Pipeline(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte(leakVal + "\n"))
	r := sh(leakVault(t), `echo "$STRIPE_LIVE" | base64`)
	assertRedacted(t, r, enc)
	// Embedded in a longer string: every base64 alignment.
	for _, prefix := range []string{"a", "ab", "abc"} {
		enc := base64.StdEncoding.EncodeToString([]byte(prefix + leakVal + "\n"))
		r := sh(leakVault(t), `printf '`+prefix+`%s\n' "$STRIPE_LIVE" | base64`)
		assertRedacted(t, r, enc)
	}
}

func TestLeakHex(t *testing.T) {
	r := sh(leakVault(t), `printf %s "$STRIPE_LIVE" | od -An -tx1 | tr -d ' \n'; echo`)
	assertRedacted(t, r)
}

func TestLeakJSONErrorBody(t *testing.T) {
	r := sh(leakVault(t), `printf '{"error":"invalid key %s provided","code":401}\n' "$STRIPE_LIVE"`)
	assertRedacted(t, r)
}

func TestLeakURLEncodedLogLine(t *testing.T) {
	r := sh(leakVault(t), `printf 'GET /v1/charges?key=%s HTTP/1.1\n' "$STRIPE_LIVE"`)
	assertRedacted(t, r)
}

func TestLeakOnStderr(t *testing.T) {
	r := sh(leakVault(t), `echo "fatal: auth failed for $STRIPE_LIVE" >&2`)
	assertRedacted(t, r)
	if !strings.Contains(r.stderr, "[REDACTED:stripe/live]") {
		t.Fatalf("marker should be on stderr: %s", r)
	}
}

func TestLeakSplitAcrossWritesWithPause(t *testing.T) {
	ve := leakVault(t)
	r := ve.runEnv([]string{"HELPER_SPLIT=$STRIPE_LIVE"}, nil, "run", "--with", "stripe/live", "--", helperBin)
	assertRedacted(t, r)
}

func TestLeakValueInsideLongerToken(t *testing.T) {
	assertRedacted(t, sh(leakVault(t), `echo "Bearer ${STRIPE_LIVE}xyz"`))
}

func TestRedactionLogAndNotice(t *testing.T) {
	ve := leakVault(t)
	r := sh(ve, `echo "$STRIPE_LIVE"; echo "$STRIPE_LIVE" >&2`)
	assertRedacted(t, r)
	if !strings.Contains(r.stderr, "redacted stripe/live from output (2×)") {
		t.Fatalf("want notice: %s", r)
	}
	raw, err := os.ReadFile(filepath.Join(ve.home, "redactions.log"))
	if err != nil {
		t.Fatal(err)
	}
	log := string(raw)
	if strings.Count(log, "handle=stripe/live") != 2 || !strings.Contains(log, "stream=stderr") || !strings.Contains(log, "cmd=sh") {
		t.Fatalf("log: %s", log)
	}
	if strings.Contains(log, leakVal) {
		t.Fatal("log contains the value")
	}
}

func TestNoRedactionNoNoise(t *testing.T) {
	ve := leakVault(t)
	r := sh(ve, `echo hello`)
	if r.stdout != "hello\n" || r.stderr != "" {
		t.Fatalf("clean run should be silent: %s", r)
	}
	if _, err := os.Stat(filepath.Join(ve.home, "redactions.log")); err == nil {
		t.Fatal("log should not exist when nothing was redacted")
	}
}

func TestThroughput10MB(t *testing.T) {
	ve := leakVault(t)
	start := time.Now()
	r := ve.runEnv([]string{"HELPER_BLAST=10485760"}, nil, "run", "--with", "stripe/live", "--", helperBin)
	el := time.Since(start)
	if r.code != 0 || len(r.stdout) < 10485760 {
		t.Fatalf("blast: exit %d, %d bytes", r.code, len(r.stdout))
	}
	bound := 2 * time.Second
	if raceEnabled {
		bound = 15 * time.Second
	}
	if el > bound {
		t.Fatalf("10MB took %v, want < %v", el, bound)
	}
	t.Logf("10MB through cpass run in %v", el)
}
