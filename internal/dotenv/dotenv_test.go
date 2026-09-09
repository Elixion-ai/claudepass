package dotenv

import (
	"reflect"
	"testing"
)

func TestParseBasic(t *testing.T) {
	src := "FOO=bar\nBAZ=qux\n"
	got, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{{"FOO", "bar"}, {"BAZ", "qux"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseQuotesExportAndComments(t *testing.T) {
	src := `# a full-line comment
export STRIPE_KEY="sk_live_abc#not-a-comment\nsecond"
SINGLE='raw $value # not a comment'
TRAILING=value # trailing comment
NOSPACE=value#nocomment
	  # indented comment
export	TABBED=tabvalue

EMPTY=
`
	got, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{
		{"STRIPE_KEY", "sk_live_abc#not-a-comment\nsecond"},
		{"SINGLE", "raw $value # not a comment"},
		{"TRAILING", "value"},
		{"NOSPACE", "value#nocomment"},
		{"TABBED", "tabvalue"},
		{"EMPTY", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseLaterKeyOverridesEarlier(t *testing.T) {
	src := "A=one\nB=two\nA=three\n"
	got, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{{"A", "three"}, {"B", "two"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"no equals", "JUSTAWORD\n"},
		{"invalid key", "1BAD=x\n"},
		{"invalid key chars", "BA D=x\n"},
		{"unterminated double", `FOO="unterminated` + "\n"},
		{"unterminated single", `FOO='unterminated` + "\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(c.src); err == nil {
				t.Fatalf("want error for %q", c.src)
			}
		})
	}
}

func TestParseEmptySource(t *testing.T) {
	got, err := Parse("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want no entries, got %+v", got)
	}
}

func TestParseCRLF(t *testing.T) {
	got, err := Parse("FOO=bar\r\nBAZ=qux\r\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{{"FOO", "bar"}, {"BAZ", "qux"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
