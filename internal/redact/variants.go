package redact

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
)

// Pattern is one byte sequence that, if it appears in output, reveals a Secret.
type Pattern struct {
	Handle   string
	Encoding string
	Bytes    []byte
}

// minPatternLen guards against variants so short they would shred ordinary
// output. Secrets are at least 8 bytes, so every variant clears this.
const minPatternLen = 6

// Variants returns every recognisable encoding of value: raw, base64 in both
// alphabets at all three alignments, hex, percent-encoded, and JSON-escaped.
func Variants(handle, value string) []Pattern {
	seen := map[string]bool{}
	var out []Pattern
	add := func(enc string, b []byte) {
		if len(b) < minPatternLen || seen[string(b)] {
			return
		}
		seen[string(b)] = true
		out = append(out, Pattern{Handle: handle, Encoding: enc, Bytes: b})
	}
	v := []byte(value)
	add("raw", v)
	for _, alpha := range []struct {
		name string
		enc  *base64.Encoding
	}{{"base64", base64.RawStdEncoding}, {"base64url", base64.RawURLEncoding}} {
		for k := 0; k < 3; k++ {
			add(alpha.name, alignedBase64(alpha.enc, v, k))
		}
	}
	add("hex", []byte(hex.EncodeToString(v)))
	if q := url.QueryEscape(value); q != value {
		add("percent", []byte(q))
	}
	if p := url.PathEscape(value); p != value {
		add("percent", []byte(p))
	}
	if j, err := json.Marshal(value); err == nil {
		s := string(j[1 : len(j)-1])
		if s != value {
			add("json", []byte(s))
		}
	}
	return out
}

// alignedBase64 returns the base64 characters fully determined by v when v
// starts k bytes into a 3-byte group, dropping the ambiguous edge characters.
// Matching all three alignments catches a value embedded anywhere inside a
// longer base64 stream (e.g. `echo "token=$X" | base64`).
func alignedBase64(enc *base64.Encoding, v []byte, k int) []byte {
	padded := append(make([]byte, k), v...)
	s := enc.EncodeToString(padded)
	drop := (8*k + 5) / 6          // ceil(8k/6): chars touched by the pad bytes
	keep := (8 * (k + len(v))) / 6 // floor: chars fully determined by pad+value
	if keep <= drop {
		return nil
	}
	return []byte(s[drop:keep])
}
