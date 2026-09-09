// Package dotenv parses dotenv-syntax files (the format `cpass import`
// reads): KEY=VALUE lines, an optional "export " prefix, single- and
// double-quoted values, and comments. It has no knowledge of Secrets,
// Handles, or the Vault — a pure core with table-driven tests.
package dotenv

import (
	"fmt"
	"strings"
)

// Entry is one KEY=VALUE pair parsed from a dotenv file.
type Entry struct {
	Name  string
	Value string
}

// Parse reads dotenv syntax from src and returns its entries in the order
// their key was first seen. A key repeated later in the file overrides its
// earlier value, matching how a shell sourcing the same file would behave.
//
// Recognised syntax per line:
//
//	KEY=value                 unquoted; trimmed; # starts a comment only
//	                          where preceded by whitespace or at the start
//	KEY="value with # and \n" double-quoted; \\ \" \n \t \r are unescaped
//	KEY='value literally'     single-quoted; no escapes, no comment inside
//	export KEY=value          "export " (or a tab) prefix is stripped
//	# comment                 a line whose first non-blank byte is # is
//	                          skipped entirely, as is a blank line
//
// Multi-line values are not supported: every entry is exactly one line.
func Parse(src string) ([]Entry, error) {
	var order []string
	byName := map[string]string{}

	lines := strings.Split(src, "\n")
	for i, raw := range lines {
		lineNo := i + 1
		line := strings.TrimRight(raw, "\r")
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		t = strings.TrimPrefix(t, "export ")
		t = strings.TrimPrefix(t, "export\t")
		t = strings.TrimLeft(t, " \t")

		name, rest, ok := strings.Cut(t, "=")
		if !ok {
			return nil, fmt.Errorf("dotenv: line %d: expected KEY=VALUE", lineNo)
		}
		name = strings.TrimSpace(name)
		if !validKey(name) {
			return nil, fmt.Errorf("dotenv: line %d: invalid variable name %q", lineNo, name)
		}

		value, err := parseValue(rest)
		if err != nil {
			return nil, fmt.Errorf("dotenv: line %d: %w", lineNo, err)
		}
		if _, seen := byName[name]; !seen {
			order = append(order, name)
		}
		byName[name] = value
	}

	out := make([]Entry, 0, len(order))
	for _, name := range order {
		out = append(out, Entry{Name: name, Value: byName[name]})
	}
	return out, nil
}

// parseValue parses the part of a line after "KEY=".
func parseValue(rest string) (string, error) {
	s := strings.TrimLeft(rest, " \t")
	if s == "" {
		return "", nil
	}
	switch s[0] {
	case '"':
		return parseDouble(s[1:])
	case '\'':
		return parseSingle(s[1:])
	default:
		return parseUnquoted(s), nil
	}
}

// parseDouble parses a double-quoted value, s being the text after the
// opening quote. Escapes \\ \" \n \t \r are unescaped; # is literal inside
// the quotes.
func parseDouble(s string) (string, error) {
	var b strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '"' {
			return b.String(), nil
		}
		if c == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '"', '\\', '$':
				b.WriteByte(s[i+1])
			default:
				b.WriteByte('\\')
				b.WriteByte(s[i+1])
			}
			i += 2
			continue
		}
		b.WriteByte(c)
		i++
	}
	return "", fmt.Errorf("unterminated double-quoted value")
}

// parseSingle parses a single-quoted value: no escapes at all.
func parseSingle(s string) (string, error) {
	j := strings.IndexByte(s, '\'')
	if j < 0 {
		return "", fmt.Errorf("unterminated single-quoted value")
	}
	return s[:j], nil
}

// parseUnquoted returns the value up to an unquoted comment (a '#' at the
// start of the value or preceded by whitespace), trimmed of trailing
// whitespace.
func parseUnquoted(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			return strings.TrimRight(s[:i], " \t")
		}
	}
	return strings.TrimRight(s, " \t")
}

func validKey(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
