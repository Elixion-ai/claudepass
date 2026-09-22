package redact

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
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
// alphabets at all three alignments, base32 (standard alphabet) at all five
// alignments plus its own padded whole-value form, hex in both cases,
// percent-encoded, and JSON-escaped.
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
			add(alpha.name, alignedEncoding(alpha.enc, base64BitsPerChar, v, k))
		}
	}
	// base32 groups 5 bytes into 8 characters (40 bits, 5 bits/char), so a
	// value can start at any of 5 byte offsets into a group — unlike
	// base64's 3. The unpadded (Raw) encoding is used for the scan itself:
	// its aligned fragment is always a literal prefix of what the padded
	// encoding would print for the same bytes, so it matches either form as
	// a substring. The explicit whole-value padded pattern below then
	// exists to consume a real tool's trailing `=` padding too, rather than
	// leaving it dangling after the marker.
	rawBase32 := base32.StdEncoding.WithPadding(base32.NoPadding)
	for k := 0; k < 5; k++ {
		add("base32", alignedEncoding(rawBase32, base32BitsPerChar, v, k))
	}
	add("base32", []byte(base32.StdEncoding.EncodeToString(v)))
	add("hex", []byte(hex.EncodeToString(v)))
	add("hex", []byte(strings.ToUpper(hex.EncodeToString(v)))) // openssl fingerprints, `xxd -u`, Java's Hex.encodeHexString
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

// bitsPerChar for the two RFC 4648 alphabets alignedEncoding supports: 6 for
// base64 (4 characters per 3-byte group), 5 for base32 (8 characters per
// 5-byte group).
const (
	base64BitsPerChar = 6
	base32BitsPerChar = 5
)

// rawEncoding is the subset of *base64.Encoding and *base32.Encoding
// alignedEncoding needs: both types implement it, unpadded (Raw/NoPadding)
// variants only, so drop/keep below index into real content, never padding.
type rawEncoding interface {
	EncodeToString(src []byte) string
}

// alignedEncoding returns the characters fully determined by v when v starts
// k bytes into an enc-shaped group, dropping the ambiguous edge characters
// touched by the k synthetic pad bytes or left incomplete by v's own tail.
// Matching every alignment catches a value embedded anywhere inside a longer
// encoded stream (e.g. `echo "token=$X" | base64`), for whichever alphabet
// enc encodes with; bitsPerChar is that alphabet's output bits per
// character (see base64BitsPerChar/base32BitsPerChar above).
func alignedEncoding(enc rawEncoding, bitsPerChar int, v []byte, k int) []byte {
	padded := append(make([]byte, k), v...)
	s := enc.EncodeToString(padded)
	drop := (8*k + bitsPerChar - 1) / bitsPerChar // ceil(8k/bitsPerChar): chars touched by the pad bytes
	keep := (8 * (k + len(v))) / bitsPerChar      // floor: chars fully determined by pad+value
	if keep <= drop {
		return nil
	}
	return []byte(s[drop:keep])
}
