package dotenv

import (
	"reflect"
	"strings"
	"testing"
)

// FuzzDotenvParse feeds arbitrary text through Parse, seeded from
// TestParseBasic and TestParseQuotesExportAndComments. It asserts no
// panic, and round-trip idempotence: re-serializing Parse's own output
// (through escapeDotenvValue, which uses only the backslash escapes
// Parse's parseDouble itself understands) and parsing that again must
// reproduce the identical entries.
func FuzzDotenvParse(f *testing.F) {
	seeds := []string{
		"FOO=bar\nBAZ=qux\n",
		"# a full-line comment\nexport STRIPE_KEY=\"sk_live_abc#not-a-comment\\nsecond\"\nSINGLE='raw $value # not a comment'\nTRAILING=value # trailing comment\nNOSPACE=value#nocomment\n\t  # indented comment\nexport\tTABBED=tabvalue\n\nEMPTY=\n",
		"A=\"line1\\nline2\\ttab\\\"quote\\\\slash\"\n",
		"KEY=value=with=equals\n",
		"",
		"not a valid line\n",
		"1BAD=x\n",
		"K='unterminated\n",
		`K="unterminated`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		entries, err := Parse(src)
		if err != nil {
			// Invalid input: nothing further to assert. Parse must not
			// panic, which f.Fuzz itself already enforces.
			return
		}
		var b strings.Builder
		for _, e := range entries {
			b.WriteString(e.Name)
			b.WriteByte('=')
			b.WriteString(escapeDotenvValue(e.Value))
			b.WriteByte('\n')
		}
		again, err := Parse(b.String())
		if err != nil {
			t.Fatalf("re-parsing Parse's own (escaped) output failed: %v\nsource: %q\nserialized: %q", err, src, b.String())
		}
		if !reflect.DeepEqual(entries, again) {
			t.Fatalf("round-trip mismatch:\nsource:     %q\nserialized: %q\nfirst:      %+v\nsecond:     %+v", src, b.String(), entries, again)
		}
	})
}

// escapeDotenvValue renders v as a double-quoted dotenv value using only
// the escapes parseDouble itself understands (\\ \" \n \t \r): every other
// byte, including one that is not valid UTF-8, passes through unchanged.
// This is the exact inverse of parseDouble for any string it could ever
// produce, which is what makes the fuzz round-trip above meaningful rather
// than an artifact of a richer serialization format Parse can't actually
// read back.
func escapeDotenvValue(v string) string {
	var b strings.Builder
	b.Grow(len(v) + 2)
	b.WriteByte('"')
	for i := 0; i < len(v); i++ {
		switch c := v[i]; c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
