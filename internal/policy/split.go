package policy

import "strings"

// word is one shell word with its raw text (quotes removed, expansions kept
// as written) and any command substitutions it contained.
type word struct {
	raw  string
	subs []string
}

// splitCommands breaks a shell string into simple commands (lists of
// words), treating ; & | && || newlines ( ) { } and redirections as
// separators. It understands quotes, backslashes, $(...) and backticks.
// It is deliberately conservative: unknown syntax becomes ordinary words.
func splitCommands(s string) [][]word {
	var cmds [][]word
	var cur []word
	var buf strings.Builder
	var subs []string
	inWord := false

	flushWord := func() {
		if inWord {
			cur = append(cur, word{raw: buf.String(), subs: subs})
			buf.Reset()
			subs = nil
			inWord = false
		}
	}
	flushCmd := func() {
		flushWord()
		if len(cur) > 0 {
			cmds = append(cmds, cur)
			cur = nil
		}
	}

	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			buf.WriteByte(s[i+1])
			inWord = true
			i += 2
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				buf.WriteString(s[i+1:])
				i = len(s)
			} else {
				buf.WriteString(s[i+1 : i+1+j])
				i += j + 2
			}
			inWord = true
		case c == '"':
			i++
			inWord = true
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					buf.WriteByte(s[i+1])
					i += 2
					continue
				}
				if s[i] == '$' && i+1 < len(s) && s[i+1] == '(' {
					inner, n := matchParen(s[i+2:])
					subs = append(subs, inner)
					buf.WriteString("$(" + inner + ")")
					i += 2 + n
					continue
				}
				if s[i] == '`' {
					j := strings.IndexByte(s[i+1:], '`')
					if j >= 0 {
						subs = append(subs, s[i+1:i+1+j])
						buf.WriteString(s[i : i+j+2])
						i += j + 2
						continue
					}
				}
				buf.WriteByte(s[i])
				i++
			}
			i++ // closing quote
		case c == '$' && i+1 < len(s) && s[i+1] == '(':
			inner, n := matchParen(s[i+2:])
			subs = append(subs, inner)
			buf.WriteString("$(" + inner + ")")
			inWord = true
			i += 2 + n
		case c == '`':
			j := strings.IndexByte(s[i+1:], '`')
			if j < 0 {
				buf.WriteByte(c)
				i++
				inWord = true
				continue
			}
			subs = append(subs, s[i+1:i+1+j])
			buf.WriteString(s[i : i+j+2])
			inWord = true
			i += j + 2
		case c == ' ' || c == '\t':
			flushWord()
			i++
		case c == ';' || c == '\n' || c == '|' || c == '&' || c == '(' || c == ')' || c == '{' || c == '}':
			flushCmd()
			i++
		case c == '<' || c == '>':
			// Redirection: drop the operator, an fd prefix (2>&1), and the target.
			if isDigits(buf.String()) {
				buf.Reset()
				inWord = false
			}
			flushWord()
			for i < len(s) && (s[i] == '<' || s[i] == '>' || s[i] == '&' || (s[i] >= '0' && s[i] <= '9')) {
				i++
			}
			for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
			for i < len(s) && !strings.ContainsRune(" \t;|&\n()", rune(s[i])) {
				i++
			}
		default:
			buf.WriteByte(c)
			inWord = true
			i++
		}
	}
	flushCmd()
	return cmds
}

// matchParen returns the text up to the parenthesis matching an already
// consumed "(", and the number of bytes consumed including the closer.
func matchParen(s string) (string, int) {
	depth := 1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[:i], i + 1
			}
		}
	}
	return s, len(s)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
