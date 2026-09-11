// Package site is the machine-checked parity contract between the Figma
// "ClaudePass Brand Book" design tokens (recorded in site/tokens.json,
// itself a trimmed export of the design handoff's figma-tokens.json) and
// the CSS custom properties actually shipped in site/retro.css.
//
// It exists because every token/Figma drift this repo has hit so far (the
// green marquee glow, the focus-ring-width mismatch, ...) was only found by
// a human reading two files side by side. This test replaces that with a
// parser: it resolves retro.css's `:root` (Dark) and `.inner-page main`
// (Light) custom-property blocks — following var() alias chains the same
// way a browser would — and fails if a resolved value stops matching
// site/tokens.json, or if a colour literal turns up anywhere else in the
// file.
//
// Deliberately its own package (not internal/e2e): it never builds or
// spawns the cpass binary, so it runs fast and has zero coupling with the
// binary-driving e2e harness or the packages a concurrent change might be
// touching (internal/cli, internal/redact, internal/run).
package site

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	cssPath    = "../../site/retro.css"
	tokensPath = "../../site/tokens.json"
)

// ---------- site/tokens.json shape ----------

type colorVal struct {
	Dark  string `json:"Dark"`
	Light string `json:"Light"`
}

type collection struct {
	Type string                     `json:"type"`
	Unit string                     `json:"unit"`
	Vars map[string]json.RawMessage `json:"vars"`
}

type tokensFile struct {
	Collections       map[string]collection `json:"collections"`
	DerivedNotInFigma struct {
		Vars map[string]string `json:"vars"`
	} `json:"derivedNotInFigma"`
}

func loadTokens(t *testing.T) tokensFile {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(tokensPath))
	if err != nil {
		t.Fatalf("reading %s: %v", tokensPath, err)
	}
	var tf tokensFile
	if err := json.Unmarshal(b, &tf); err != nil {
		t.Fatalf("parsing %s: %v", tokensPath, err)
	}
	return tf
}

func loadCSS(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(cssPath))
	if err != nil {
		t.Fatalf("reading %s: %v", cssPath, err)
	}
	return string(b)
}

// ---------- retro.css block extraction ----------

// blockSpan is a [start,end) byte range in the original CSS text, start at
// the selector and end just past the block's closing brace.
type blockSpan struct{ start, end int }

// extractBlock finds the first `selector {` in css at or after `from` and
// returns its body (the text strictly between the matching braces), plus
// the span of the whole `selector { ... }` rule. Brace depth is counted
// rather than assumed absent, even though none of the blocks this test
// reads today nest braces.
func extractBlock(css, selector string, from int) (body string, span blockSpan, ok bool) {
	needle := selector + " {"
	idx := strings.Index(css[from:], needle)
	if idx == -1 {
		return "", blockSpan{}, false
	}
	idx += from
	openBrace := idx + len(needle) - 1
	depth := 0
	for i := openBrace; i < len(css); i++ {
		switch css[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return css[openBrace+1 : i], blockSpan{idx, i + 1}, true
			}
		}
	}
	return "", blockSpan{}, false
}

// extractAllBlocks returns the bodies and spans of every `selector { ... }`
// rule in source order.
func extractAllBlocks(css, selector string) (bodies []string, spans []blockSpan) {
	from := 0
	for {
		body, span, ok := extractBlock(css, selector, from)
		if !ok {
			return
		}
		bodies = append(bodies, body)
		spans = append(spans, span)
		from = span.end
	}
}

var declRe = regexp.MustCompile(`(?m)^[ \t]*(--[a-zA-Z0-9-]+)[ \t]*:[ \t]*([^;]+);`)

// parseDecls pulls every `--name: value;` custom-property declaration out
// of a block body into a name (without the leading --) -> value map. A
// name declared more than once keeps its last value, matching cascade
// order within a single rule.
func parseDecls(body string) map[string]string {
	m := map[string]string{}
	for _, match := range declRe.FindAllStringSubmatch(body, -1) {
		name := strings.TrimPrefix(match[1], "--")
		m[name] = strings.TrimSpace(match[2])
	}
	return m
}

// ---------- var() resolution ----------

var singleVarRe = regexp.MustCompile(`^var\(--([a-zA-Z0-9-]+)\)$`)

// resolve follows a chain of `--name: var(--other);` aliases down to a
// literal value, checking the inner (.inner-page main) map first when
// useInner is true and falling back to root — exactly how the cascade
// resolves an unset custom property on a descendant of both scopes.
func resolve(name string, root, inner map[string]string, useInner bool) (string, error) {
	seen := map[string]bool{}
	cur := name
	for {
		if seen[cur] {
			return "", fmt.Errorf("cycle resolving --%s (at --%s)", name, cur)
		}
		seen[cur] = true

		val, ok := "", false
		if useInner {
			val, ok = inner[cur]
		}
		if !ok {
			val, ok = root[cur]
		}
		if !ok {
			return "", fmt.Errorf("--%s is not defined (resolving --%s)", cur, name)
		}
		if m := singleVarRe.FindStringSubmatch(val); m != nil {
			cur = m[1]
			continue
		}
		return val, nil
	}
}

var hexInStringRe = regexp.MustCompile(`#[0-9a-fA-F]{3,8}`)

func hexOf(t *testing.T, s string) string {
	t.Helper()
	m := hexInStringRe.FindString(s)
	if m == "" {
		t.Fatalf("tokens.json value %q has no hex literal to extract", s)
	}
	return strings.ToLower(m)
}

func asFloat(t *testing.T, raw json.RawMessage) (float64, bool) {
	t.Helper()
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return f, true
	}
	return 0, false
}

func asString(t *testing.T, raw json.RawMessage) (string, bool) {
	t.Helper()
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, true
	}
	return "", false
}

func lengthOf(t *testing.T, cssVal string) float64 {
	t.Helper()
	trimmed := strings.TrimSuffix(strings.TrimSpace(cssVal), "px")
	f, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		t.Fatalf("expected a px length, got %q: %v", cssVal, err)
	}
	return f
}

// ---------- the fixture every sub-test shares ----------

type fixture struct {
	tf   tokensFile
	css  string
	root map[string]string
	// inner merges every ".inner-page main" block's custom-property
	// declarations in source order (retro.css currently has two: the
	// Color override block this test cares about, and a later one that
	// only consumes the variables). Merging is harmless and future-proof
	// if a declaration ever moves between them.
	inner map[string]string
}

func setup(t *testing.T) fixture {
	t.Helper()
	css := loadCSS(t)

	rootBody, _, ok := extractBlock(css, ":root", 0)
	if !ok {
		t.Fatal("no :root { } block found in site/retro.css")
	}
	innerBodies, _ := extractAllBlocks(css, ".inner-page main")
	if len(innerBodies) == 0 {
		t.Fatal("no .inner-page main { } block found in site/retro.css")
	}
	inner := map[string]string{}
	for _, b := range innerBodies {
		for k, v := range parseDecls(b) {
			inner[k] = v
		}
	}

	return fixture{
		tf:    loadTokens(t),
		css:   css,
		root:  parseDecls(rootBody),
		inner: inner,
	}
}

// ---------- tests ----------

func TestColorTokens(t *testing.T) {
	fx := setup(t)
	col, ok := fx.tf.Collections["Color"]
	if !ok {
		t.Fatal(`tokens.json has no "Color" collection`)
	}
	for name, raw := range col.Vars {
		var cv colorVal
		if err := json.Unmarshal(raw, &cv); err != nil {
			t.Fatalf("Color.%s: %v", name, err)
		}
		wantDark := hexOf(t, cv.Dark)
		wantLight := hexOf(t, cv.Light)

		t.Run(name+"/Dark", func(t *testing.T) {
			got, err := resolve(name, fx.root, fx.inner, false)
			if err != nil {
				t.Fatalf(":root --%s: %v", name, err)
			}
			if strings.ToLower(strings.TrimSpace(got)) != wantDark {
				t.Errorf(":root --%s resolves to %q, tokens.json Dark wants %q", name, got, wantDark)
			}
		})
		t.Run(name+"/Light", func(t *testing.T) {
			got, err := resolve(name, fx.root, fx.inner, true)
			if err != nil {
				t.Fatalf(".inner-page main --%s: %v", name, err)
			}
			if strings.ToLower(strings.TrimSpace(got)) != wantLight {
				t.Errorf(".inner-page main --%s resolves to %q, tokens.json Light wants %q", name, got, wantLight)
			}
		})
	}
}

// TestScalarCollections covers every collection whose values are plain
// numbers or strings (Spacing, Radius, Elevation, Motion, Type Scale) plus
// Typography, checked in :root only — these have one mode, unlike Color.
func TestScalarCollections(t *testing.T) {
	fx := setup(t)
	for collName, coll := range fx.tf.Collections {
		if collName == "Color" {
			continue
		}
		coll := coll
		for name, raw := range coll.Vars {
			name, raw, coll := name, raw, coll
			t.Run(collName+"/"+name, func(t *testing.T) {
				got, err := resolve(name, fx.root, fx.inner, false)
				if err != nil {
					t.Fatalf(":root --%s: %v", name, err)
				}
				got = strings.TrimSpace(got)

				if coll.Unit == "px" {
					want, isNum := asFloat(t, raw)
					if !isNum {
						t.Fatalf("%s.%s: expected a numeric px value in tokens.json", collName, name)
					}
					if lengthOf(t, got) != want {
						t.Errorf(":root --%s is %q, tokens.json wants %gpx", name, got, want)
					}
					return
				}

				if want, isStr := asString(t, raw); isStr {
					if got != want {
						t.Errorf(":root --%s is %q, tokens.json wants %q", name, got, want)
					}
					return
				}
				if want, isNum := asFloat(t, raw); isNum {
					gotNum, err := strconv.ParseFloat(got, 64)
					if err != nil || gotNum != want {
						t.Errorf(":root --%s is %q, tokens.json wants %g", name, got, want)
					}
					return
				}
				t.Fatalf("%s.%s: tokens.json value is neither string nor number", collName, name)
			})
		}
	}
}

// TestDerivedTokensExist checks the small set of overlay/glow tokens that
// are documented as NOT coming from Figma (site/tokens.json's
// derivedNotInFigma) still exist in :root with the recorded value, so a
// future edit can't quietly drop or redefine one of them unnoticed either.
func TestDerivedTokensExist(t *testing.T) {
	fx := setup(t)
	for name, want := range fx.tf.DerivedNotInFigma.Vars {
		name, want := name, want
		t.Run(name, func(t *testing.T) {
			got, err := resolve(name, fx.root, fx.inner, false)
			if err != nil {
				t.Fatalf(":root --%s: %v", name, err)
			}
			if strings.TrimSpace(got) != want {
				t.Errorf(":root --%s is %q, tokens.json derivedNotInFigma wants %q", name, got, want)
			}
		})
	}
}

// TestNoColorLiteralOutsideTokenBlocks is the other half of the contract:
// every hex/rgb(a) color literal in retro.css must live inside :root or
// one of the .inner-page main override blocks. Anything else is a leak —
// exactly the shape of bug this whole test exists to catch (the green
// marquee glow was a leak like this).
func TestNoColorLiteralOutsideTokenBlocks(t *testing.T) {
	fx := setup(t)

	_, rootSpan, ok := extractBlock(fx.css, ":root", 0)
	if !ok {
		t.Fatal("no :root { } block found")
	}
	_, innerSpans := extractAllBlocks(fx.css, ".inner-page main")

	spans := append([]blockSpan{rootSpan}, innerSpans...)
	// Sort by start so the cut below is a single left-to-right pass.
	for i := 1; i < len(spans); i++ {
		for j := i; j > 0 && spans[j-1].start > spans[j].start; j-- {
			spans[j-1], spans[j] = spans[j], spans[j-1]
		}
	}

	var b strings.Builder
	last := 0
	for _, sp := range spans {
		b.WriteString(fx.css[last:sp.start])
		last = sp.end
	}
	b.WriteString(fx.css[last:])
	rest := b.String()

	hexRe := regexp.MustCompile(`#[0-9a-fA-F]{3,8}`)
	rgbRe := regexp.MustCompile(`(?i)rgba?\(`)

	if hits := hexRe.FindAllString(rest, -1); len(hits) > 0 {
		t.Errorf("hex color literal(s) outside the token blocks: %v", hits)
	}
	if hits := rgbRe.FindAllString(rest, -1); len(hits) > 0 {
		t.Errorf("rgb()/rgba() color literal(s) outside the token blocks: %v", hits)
	}
}
