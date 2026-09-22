package redact

import "testing"

// knownFuzzValue is embedded, verbatim, somewhere inside arbitrary fuzzed
// surrounding bytes; it must always be found regardless of what those
// bytes are.
const knownFuzzValue = "cpass-fuzz-known-value-KNOWNFUZZvalue0123456789ABCDEFxyz"

// FuzzRedactAutomaton asserts that automaton.find always reports
// knownFuzzValue's occurrence, at the exact offset and length it was
// inserted at, no matter what fuzzed bytes surround it — the property the
// automaton exists for (see automaton.go's own doc comment: "finding every
// occurrence and reporting them leftmost-longest, non-overlapping"). It
// also asserts partialLen never panics or returns an out-of-range length
// on the tail after the match.
func FuzzRedactAutomaton(f *testing.F) {
	seeds := [][2][]byte{
		{[]byte(""), []byte("")},
		{[]byte("prefix-"), []byte("-suffix")},
		{[]byte("sk_live_"), []byte("")},
		{[]byte(""), []byte(knownFuzzValue[:8])},
		{[]byte{0, 1, 2, 0xff}, []byte{0xfe, 0, 1}},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}
	pattern := Pattern{Handle: "test/known", Encoding: "raw", Bytes: []byte(knownFuzzValue)}
	a := buildAutomaton([]Pattern{pattern})
	f.Fuzz(func(t *testing.T, prefix, suffix []byte) {
		buf := make([]byte, 0, len(prefix)+len(knownFuzzValue)+len(suffix))
		buf = append(buf, prefix...)
		buf = append(buf, knownFuzzValue...)
		buf = append(buf, suffix...)

		matches := a.find(buf, nil)
		found := false
		for _, m := range matches {
			if m.pidx == 0 && m.start == len(prefix) && m.length == len(knownFuzzValue) {
				found = true
			}
			if m.start < 0 || m.start+m.length > len(buf) {
				t.Fatalf("match out of bounds: %+v (buf len %d)", m, len(buf))
			}
		}
		if !found {
			t.Fatalf("known value not matched: prefix=%q suffix=%q matches=%v", prefix, suffix, matches)
		}

		// partialLen must never panic and never claim a suffix longer
		// than the tail it was given or longer than the longest Pattern.
		if n := a.partialLen(suffix); n < 0 || n > len(suffix) || n >= a.maxLen {
			t.Fatalf("partialLen(%q) = %d, out of range (maxLen=%d)", suffix, n, a.maxLen)
		}
	})
}
