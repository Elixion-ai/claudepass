package cli

import "testing"

// fakeEnv builds a getenv func from a map, returning "" for anything not
// listed — the same as a real, mostly-empty process environment.
func fakeEnv(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestDetectColorMode(t *testing.T) {
	cases := []struct {
		name  string
		isTTY bool
		env   map[string]string
		want  colorMode
	}{
		{"NO_COLOR wins over a TTY", true, map[string]string{"NO_COLOR": "1", "COLORTERM": "truecolor"}, colorNone},
		{"NO_COLOR wins with any non-empty value", true, map[string]string{"NO_COLOR": "x"}, colorNone},
		{"non-TTY, no env at all", false, nil, colorNone},
		{"non-TTY even with COLORTERM set", false, map[string]string{"COLORTERM": "truecolor"}, colorNone},
		{"TERM=dumb beats a TTY", true, map[string]string{"TERM": "dumb"}, colorNone},
		{"TTY, no COLORTERM: 256-colour fallback", true, nil, color256},
		{"TTY, COLORTERM=truecolor: 24-bit", true, map[string]string{"COLORTERM": "truecolor"}, colorTrue},
		{"TTY, COLORTERM=24bit: 24-bit", true, map[string]string{"COLORTERM": "24bit"}, colorTrue},
		{"TTY, COLORTERM=unknown value: 256-colour fallback", true, map[string]string{"COLORTERM": "yes"}, color256},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := detectColorMode(c.isTTY, fakeEnv(c.env))
			if got != c.want {
				t.Fatalf("detectColorMode(%v, %v) = %v, want %v", c.isTTY, c.env, got, c.want)
			}
		})
	}
}

func containsESC(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			return true
		}
	}
	return false
}

func TestNoColorProducesZeroESCBytesRegardlessOfTTY(t *testing.T) {
	getenv := fakeEnv(map[string]string{"NO_COLOR": "1", "COLORTERM": "truecolor"})
	for _, isTTY := range []bool{true, false} {
		mode := detectColorMode(isTTY, getenv)
		got := mode.paint(roleEmber, "stripe/live")
		if containsESC(got) {
			t.Fatalf("NO_COLOR set, isTTY=%v: got ESC bytes in %q", isTTY, got)
		}
		if got != "stripe/live" {
			t.Fatalf("NO_COLOR set: want plain text unchanged, got %q", got)
		}
	}
}

func TestNonTTYProducesZeroESCBytes(t *testing.T) {
	mode := detectColorMode(false, fakeEnv(map[string]string{"COLORTERM": "truecolor"}))
	got := mode.paint(roleRed, "refused")
	if containsESC(got) {
		t.Fatalf("non-TTY: got ESC bytes in %q", got)
	}
	if got != "refused" {
		t.Fatalf("non-TTY: want plain text unchanged, got %q", got)
	}
}

func TestTermDumbProducesZeroESCBytes(t *testing.T) {
	mode := detectColorMode(true, fakeEnv(map[string]string{"TERM": "dumb", "COLORTERM": "truecolor"}))
	got := mode.paint(roleCyan, "hint")
	if containsESC(got) {
		t.Fatalf("TERM=dumb: got ESC bytes in %q", got)
	}
}

func TestTTYWithTruecolorColortermProducesTruecolorEscape(t *testing.T) {
	mode := detectColorMode(true, fakeEnv(map[string]string{"COLORTERM": "truecolor"}))
	got := mode.paint(roleEmber, "stripe/live")
	want := "\x1b[38;2;255;138;31mstripe/live\x1b[0m"
	if got != want {
		t.Fatalf("truecolor ember: got %q, want %q", got, want)
	}
}

func TestTTYWithout24BitColortermProduces256ColourFallback(t *testing.T) {
	mode := detectColorMode(true, fakeEnv(nil))
	got := mode.paint(roleEmber, "stripe/live")
	want := "\x1b[38;5;208mstripe/live\x1b[0m"
	if got != want {
		t.Fatalf("256-colour ember: got %q, want %q", got, want)
	}
}

// TestEscapeCodesMatchDocumentedPalette pins every role's exact escape
// sequence to docs/CLI-STYLE.md's Colour section, so the two files cannot
// silently diverge (see ansi.go's cross-linking doc comment).
func TestEscapeCodesMatchDocumentedPalette(t *testing.T) {
	cases := []struct {
		role          brandRole
		want256       string
		wantTruecolor string
	}{
		{roleEmber, "\x1b[38;5;208m", "\x1b[38;2;255;138;31m"},
		{roleCyan, "\x1b[38;5;45m", "\x1b[38;2;77;232;255m"},
		{roleRed, "\x1b[38;5;203m", "\x1b[38;2;255;77;77m"},
		{roleDim, "\x1b[38;5;245m", "\x1b[38;2;179;168;155m"},
	}
	for _, c := range cases {
		if got := color256.escape(c.role); got != c.want256 {
			t.Errorf("role %+v 256-colour escape = %q, want %q", c.role, got, c.want256)
		}
		if got := colorTrue.escape(c.role); got != c.wantTruecolor {
			t.Errorf("role %+v truecolor escape = %q, want %q", c.role, got, c.wantTruecolor)
		}
	}
	if got := colorNone.escape(roleEmber); got != "" {
		t.Errorf("colorNone.escape = %q, want empty", got)
	}
}

func TestPaintOutUsesStdoutMode(t *testing.T) {
	e := &env{outMode: colorTrue, errMode: colorNone}
	got := e.paintOut(roleEmber, "h")
	want := "\x1b[38;2;255;138;31mh\x1b[0m"
	if got != want {
		t.Fatalf("paintOut: got %q, want %q", got, want)
	}
	if e.paintErr(roleEmber, "h") != "h" {
		t.Fatalf("paintErr should use errMode (colorNone), not outMode")
	}
}

func TestMarkerDecoratorNilWhenColorOff(t *testing.T) {
	if d := markerDecorator(colorNone); d != nil {
		t.Fatalf("markerDecorator(colorNone) should be nil, got a func")
	}
}

func TestMarkerDecoratorWrapsMarkerInRed(t *testing.T) {
	d := markerDecorator(color256)
	if d == nil {
		t.Fatal("markerDecorator(color256) should not be nil")
	}
	got := string(d("stripe/live", []byte("[REDACTED:stripe/live]")))
	want := "\x1b[38;5;203m[REDACTED:stripe/live]\x1b[0m"
	if got != want {
		t.Fatalf("decorated marker = %q, want %q", got, want)
	}
}

func TestIsTerminalWriterFalseForNonFile(t *testing.T) {
	var sb stringWriter
	if isTerminalWriter(&sb) {
		t.Fatal("a non-*os.File writer must never be treated as a terminal")
	}
}

// stringWriter is a minimal io.Writer that is not an *os.File, standing in
// for the bytes.Buffer/pipe destinations every real cpass invocation not
// run interactively actually uses.
type stringWriter struct{ s string }

func (w *stringWriter) Write(p []byte) (int, error) {
	w.s += string(p)
	return len(p), nil
}
