// Package detect finds Secret-shaped values in arbitrary text: known
// provider-key prefixes with an inferred Handle, generic PEM private-key
// blocks, and a entropy check over otherwise-unrecognised long tokens. It is
// a pure core with no I/O, driving `cpass intercept`.
package detect

import (
	"math"
	"regexp"
	"strings"
)

// Match is one Secret-shaped span of text found in a document. Value is the
// exact substring that must be moved into the Vault and never shown again;
// Kind is a short human label safe to print (it never repeats any part of
// Value). Handle is the inferred Handle, or empty when the caller should
// fall back to an `inbox/` Handle.
type Match struct {
	Value  string
	Handle string
	Kind   string
}

// prefixPattern recognises one provider's key format by its literal prefix.
// Patterns are tried in order, so a more specific prefix (sk-ant-) must
// precede a shorter one it also satisfies (sk-).
type prefixPattern struct {
	prefix string
	minLen int // total token length below which the bare prefix word doesn't count
	handle string
	kind   string
}

var prefixPatterns = []prefixPattern{
	{"sk-ant-", 25, "anthropic/key", "Anthropic API key"},
	{"sk_live_", 20, "stripe/live", "Stripe live key"},
	{"sk_test_", 20, "stripe/test", "Stripe test key"},
	{"github_pat_", 30, "github/token", "GitHub token"},
	{"ghp_", 20, "github/token", "GitHub token"},
	{"gho_", 20, "github/token", "GitHub OAuth token"},
	{"AKIA", 16, "aws/access-key", "AWS access key"},
	{"AIza", 30, "google/api-key", "Google API key"},
	{"xoxb-", 20, "slack/token", "Slack token"},
	{"xoxp-", 20, "slack/token", "Slack token"},
	{"xoxa-", 20, "slack/token", "Slack token"},
	{"xoxs-", 20, "slack/token", "Slack token"},
	{"xoxr-", 20, "slack/token", "Slack token"},
	// Generic OpenAI prefix last: it is a strict prefix of sk-ant-, which
	// must be checked first.
	{"sk-", 20, "openai/key", "OpenAI API key"},
}

// tokenRe finds candidate secret-shaped runs: no whitespace or quoting, the
// character set real key formats use (base64/base64url plus separators).
// "=" is deliberately not part of the body: it is base64 padding at the end
// of a token (kept via the trailing "=*") but also the assignment operator
// in "NAME=value", which must not merge the variable name and the value
// into one token and hide the value's own prefix.
var tokenRe = regexp.MustCompile(`[A-Za-z0-9_\-/+.]{4,}=*`)

// pemRe finds a generic PEM private-key block, BEGIN to END, across lines.
var pemRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

// uuidRe recognises a standard UUID, a very common non-secret identifier
// that otherwise has enough character-class diversity to look entropic.
var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// urlRe finds an absolute URL by its scheme, so Scan can treat its host and
// path as ordinary structure rather than a candidate Secret: an ordinary
// REST endpoint's path segments (a version like "/v1/", a numeric or
// hex-ish resource id) mix character classes and run long enough to look
// entropic on their own, but are not plausible Secrets. A query string or
// fragment can still carry a genuine Secret — its own "="-delimited token,
// or a known prefix — so only the span up to the first "?" or "#" counts
// as path; urlPathRanges stops there.
var urlRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://[^\s"'<>]+`)

// Scan finds every Secret-shaped value in s. Order is not significant.
func Scan(s string) []Match {
	var out []Match

	for _, pem := range pemRe.FindAllString(s, -1) {
		out = append(out, Match{Value: pem, Handle: "pem/key", Kind: "PEM private key"})
	}
	// Neutralise matched PEM blocks so their base64 body isn't also picked
	// up, line by line, by the generic entropy pass below.
	s = pemRe.ReplaceAllStringFunc(s, func(m string) string {
		return strings.Map(func(r rune) rune {
			if r == '\n' {
				return '\n'
			}
			return '#'
		}, m)
	})

	urlPaths := urlPathRanges(s)
	for _, loc := range tokenRe.FindAllStringIndex(s, -1) {
		tok := s[loc[0]:loc[1]]
		if m, ok := matchPrefix(tok); ok {
			out = append(out, m)
			continue
		}
		// A token that is part of a URL path (not a known-prefix Secret,
		// checked above) doesn't go through the generic entropy path: a
		// REST call's path segments routinely mix character classes and
		// run long, without ever being a plausible Secret.
		if withinAnyRange(urlPaths, loc[0], loc[1]) {
			continue
		}
		if isHighEntropy(tok) {
			out = append(out, Match{Value: tok, Kind: "high-entropy value"})
		}
	}
	return out
}

// urlPathRanges returns the byte range of every URL's host+path found in
// s, stopping each range before its query string or fragment (the first
// "?" or "#"), so a Secret placed there is still visible to the generic
// entropy pass below.
func urlPathRanges(s string) [][2]int {
	var ranges [][2]int
	for _, loc := range urlRe.FindAllStringIndex(s, -1) {
		start, end := loc[0], loc[1]
		if i := strings.IndexAny(s[start:end], "?#"); i >= 0 {
			end = start + i
		}
		ranges = append(ranges, [2]int{start, end})
	}
	return ranges
}

// withinAnyRange reports whether [start, end) falls entirely inside one of
// ranges.
func withinAnyRange(ranges [][2]int, start, end int) bool {
	for _, r := range ranges {
		if start >= r[0] && end <= r[1] {
			return true
		}
	}
	return false
}

func matchPrefix(tok string) (Match, bool) {
	for _, p := range prefixPatterns {
		if strings.HasPrefix(tok, p.prefix) && len(tok) >= p.minLen {
			return Match{Value: tok, Handle: p.handle, Kind: p.kind}, true
		}
	}
	return Match{}, false
}

// Entropy-check tuning. minTokenLen/maxTokenLen bound the lengths real
// unprefixed secrets take; minClasses requires values to mix character
// classes the way random tokens do; minEntropy is a Shannon-entropy floor in
// bits/char; wordFraction rejects tokens that decompose mostly into
// dictionary words (compound identifiers), which can otherwise clear the
// entropy floor once they mix case and a version digit. isHighEntropy ANDs
// minClasses with minTokenLen rather than accepting either alone: an
// ordinary URL path segment can clear one on its own (digits+letters, or
// just length), but real unprefixed secrets clear both at once, and 24
// keeps every entropy-path entry in the positive corpus (30+ chars) well
// clear while cutting off the shorter path segments that used to pass at
// 20 (CLA-30).
const (
	minTokenLen  = 24
	maxTokenLen  = 100
	minClasses   = 3
	minEntropy   = 3.6
	wordFraction = 0.5
)

func isHighEntropy(tok string) bool {
	if len(tok) < minTokenLen || len(tok) > maxTokenLen {
		return false
	}
	if uuidRe.MatchString(tok) {
		return false
	}
	if classCount(tok) < minClasses {
		return false
	}
	if shannonEntropy(tok) < minEntropy {
		return false
	}
	if looksLikeWords(tok) {
		return false
	}
	return true
}

func classCount(tok string) int {
	var upper, lower, digit, symbol bool
	for _, r := range tok {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			symbol = true
		}
	}
	n := 0
	for _, b := range [...]bool{upper, lower, digit, symbol} {
		if b {
			n++
		}
	}
	return n
}

func shannonEntropy(s string) float64 {
	freq := map[rune]int{}
	for _, r := range s {
		freq[r]++
	}
	var entropy float64
	n := float64(len(s))
	for _, c := range freq {
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// wordRe splits a token into camelCase / snake_case / digit-delimited
// components: a capitalised run, a lowercase run, or a digit run.
var wordRe = regexp.MustCompile(`[A-Z]+[a-z]*|[a-z]+|[0-9]+`)

// looksLikeWords reports whether tok decomposes mostly into ordinary
// dictionary words, the signature of a descriptive identifier rather than a
// random Secret (e.g. "userAuthenticationHandlerV2ForOAuthTokenValidation").
func looksLikeWords(tok string) bool {
	var alpha []string
	for _, w := range wordRe.FindAllString(tok, -1) {
		if len(w) >= 3 && isAlpha(w) {
			alpha = append(alpha, strings.ToLower(w))
		}
	}
	if len(alpha) < 2 {
		return false
	}
	recognised := 0
	for _, w := range alpha {
		if commonWords[w] {
			recognised++
		}
	}
	return float64(recognised)/float64(len(alpha)) >= wordFraction
}

func isAlpha(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

// commonWords is a modest set of English and everyday-programming terms
// used only to tell a descriptive identifier from a random token; it does
// not need to be exhaustive, only to cover ordinary compound identifiers.
var commonWords = func() map[string]bool {
	words := []string{
		"the", "and", "for", "with", "from", "into", "this", "that", "when", "where",
		"user", "users", "name", "email", "address", "phone", "number", "date", "time",
		"config", "configuration", "service", "handler", "manager", "helper", "util", "utils",
		"common", "base", "core", "main", "module", "package", "import", "export",
		"function", "method", "class", "interface", "struct", "type", "variable", "field",
		"column", "table", "database", "schema", "record", "entry", "entries", "cache",
		"store", "memory", "buffer", "stream", "reader", "writer", "client", "server",
		"request", "response", "connection", "session", "context", "state", "props",
		"component", "render", "view", "controller", "route", "router", "middleware",
		"auth", "authentication", "authorization", "login", "logout", "register", "validate",
		"validation", "token", "secret", "password", "example", "sample", "value", "values",
		"data", "file", "path", "key", "access", "default", "local", "update", "create",
		"delete", "insert", "select", "list", "array", "object", "string", "number",
		"boolean", "true", "false", "null", "error", "errors", "result", "results",
		"status", "code", "index", "item", "items", "message", "content", "header",
		"headers", "body", "query", "param", "params", "option", "options", "setting",
		"settings", "build", "deploy", "release", "version", "branch", "commit", "merge",
		"pull", "push", "fetch", "clone", "install", "uninstall", "upgrade", "downgrade",
		"migrate", "rollback", "convert", "input", "output", "encode", "encoded", "decode",
		"decoded", "byte", "bytes", "flow", "oauth", "api", "http", "https", "json",
		"html", "css", "sql", "url", "uri", "candidate", "beta", "alpha", "production",
		"staging", "development", "test", "tests", "testing", "mock", "stub", "fixture",
		"limit", "offset", "page", "size", "count", "total", "start", "end", "begin",
		"complete", "success", "failure", "valid", "invalid", "enable", "disable", "active",
		"inactive", "public", "private", "protected", "static", "final", "abstract",
		"override", "extend", "implement", "generate", "load", "loader", "parse", "parser",
		"format", "formatter", "process", "processor", "worker", "queue", "job", "task",
		"schedule", "scheduler", "event", "events", "listener", "callback", "promise",
		"async", "await", "sync", "thread", "process",
	}
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}()
