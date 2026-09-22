package redact

import (
	"encoding/base32"
	"encoding/hex"
	"strings"
	"testing"
)

// TestHexUppercaseVariant covers CLA-67: an uppercase-hex encoding of a
// bound Secret (openssl fingerprints, `xxd -u`, Java's
// Hex.encodeHexString) is redacted, exactly like the lowercase form
// TestHexAndJSONAndPercent already covers.
func TestHexUppercaseVariant(t *testing.T) {
	pats := Variants("h", val)
	upper := strings.ToUpper(hex.EncodeToString([]byte(val)))
	out, evs := collect(t, pats, "fingerprint: "+upper+"\n")
	if strings.Contains(out, upper) || len(evs) == 0 || evs[0].Encoding != "hex" {
		t.Fatalf("uppercase hex leaked: got %q %+v", out, evs)
	}
}

// TestBase32PaddedWholeValue covers CLA-67: the padded, whole-value base32
// form a tool that always pads (Python's base64.b32encode, the base32(1)
// coreutil) would print is redacted with its trailing '=' padding, so no
// dangling padding survives next to the marker — the padded pattern shares
// the unpadded k=0 pattern's start and is longer, so scan's leftmost-longest
// resolution (writer.go) prefers it.
func TestBase32PaddedWholeValue(t *testing.T) {
	pats := Variants("h", val)
	enc := base32.StdEncoding.EncodeToString([]byte(val))
	if !strings.Contains(enc, "=") {
		t.Fatalf("test fixture assumption broken: %q has no padding to exercise", enc)
	}
	out, evs := collect(t, pats, "b32: "+enc+"\n")
	if out != "b32: [REDACTED:h]\n" || len(evs) != 1 || evs[0].Encoding != "base32" {
		t.Fatalf("padded base32 not fully redacted (padding left dangling?): got %q %+v", out, evs)
	}
}

// TestBase32AtAllAlignments mirrors TestBase64AtAllAlignments: a value's
// base32 encoding, embedded at every possible byte offset (0-4, since a
// base32 group is 5 bytes) inside a longer base32 stream, is still caught.
func TestBase32AtAllAlignments(t *testing.T) {
	pats := Variants("h", val)
	for _, prefix := range []string{"", "a", "ab", "abc", "abcd", "token="} {
		enc := base32.StdEncoding.EncodeToString([]byte(prefix + val + "\n"))
		out, evs := collect(t, pats, enc+"\n")
		if strings.Contains(out, enc) || len(evs) == 0 {
			t.Fatalf("prefix %q: base32 leaked: %q", prefix, out)
		}
		if evs[0].Encoding != "base32" {
			t.Fatalf("prefix %q: encoding %s", prefix, evs[0].Encoding)
		}
	}
}

// TestBase32UnpaddedAtAllAlignments is TestBase32AtAllAlignments's unpadded
// counterpart: tools that print base32 without padding (many TOTP/2FA
// secret tools) must be caught too, at every alignment.
func TestBase32UnpaddedAtAllAlignments(t *testing.T) {
	pats := Variants("h", val)
	raw := base32.StdEncoding.WithPadding(base32.NoPadding)
	for _, prefix := range []string{"", "a", "ab", "abc", "abcd", "token="} {
		enc := raw.EncodeToString([]byte(prefix + val + "\n"))
		out, evs := collect(t, pats, enc+"\n")
		if strings.Contains(out, enc) || len(evs) == 0 {
			t.Fatalf("prefix %q: unpadded base32 leaked: %q", prefix, out)
		}
		if evs[0].Encoding != "base32" {
			t.Fatalf("prefix %q: encoding %s", prefix, evs[0].Encoding)
		}
	}
}
