package policy

import "strings"

// word is one shell word with its raw text (quotes removed, expansions kept
// as written) and any command substitutions it contained. A word that
// represents a heredoc/here-document body instead (see splitCommands) has
// raw == "" and hasHeredoc == true; every other word has hasHeredoc ==
// false.
type word struct {
	raw  string
	subs []string

	// hasHeredoc, heredoc and heredocQuoted describe a <<[-]DELIM ... DELIM
	// redirection attached to this command: heredoc is the body text
	// between the line after the operator and the terminator line, and
	// heredocQuoted records whether DELIM was quoted (single/double
	// quotes, or backslash-escaped) — see docs/THREATS.md for what a
	// caller does with the two cases. A plain redirection target (`<
	// file`, `> file`, `<< <-`'s here-string `<<< word`) is not this: it
	// flows through the ordinary word logic below as a ordinary checkable
	// word instead, exactly like a bare argument.
	hasHeredoc    bool
	heredoc       string
	heredocQuoted bool
}

// pendingHeredoc is a <<[-]DELIM seen earlier on the current line, whose
// body has not been read yet: real shell grammar reads the rest of the
// line normally first, then consumes the heredoc body starting on the
// line after the newline that ends it.
type pendingHeredoc struct {
	delim  string
	quoted bool
	strip  bool // <<- : strip leading tabs from the body and the terminator line
}

// splitCommands breaks a shell string into simple commands (lists of
// words), treating ; & | && || newlines ( ) { } and redirections as
// separators. It understands quotes, backslashes, $(...), backticks,
// line-continuations (backslash-newline, elided like a real shell), and
// heredocs/here-strings. It is deliberately conservative: unknown syntax
// becomes ordinary words.
func splitCommands(s string) [][]word {
	var cmds [][]word
	var cur []word
	var buf strings.Builder
	var subs []string
	var pending []pendingHeredoc
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
			if s[i+1] == '\n' {
				// Line continuation: elided entirely, exactly like a real
				// shell — it is not a token character and not a word
				// boundary, so `ca\<newline>t .env` still tokenizes as the
				// single word "cat", not a mangled program name that
				// matches no policy rule.
				i += 2
				continue
			}
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
					if s[i+1] == '\n' {
						i += 2
						continue
					}
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
		case c == '$' && i+1 < len(s) && s[i+1] == '{':
			// ${...} parameter expansion (${f}, ${!x} indirect expansion,
			// ${VAR:-default}, ...): its closing brace belongs to the
			// expansion, not to `{`/`}` command-grouping below, so the
			// whole span is kept as one token — the interior is never
			// scanned for separators. Without this case, an unquoted
			// `cat ${f}` mis-tokenized into two commands ("cat $" and
			// "f"), silently defeating the literal-variable and indirect-
			// expansion checks below for this extremely common spelling
			// (the quoted form "${f}" already worked, since quotes have
			// their own self-contained loop above that never reaches this
			// switch at all).
			inner, n := matchBrace(s[i+2:])
			buf.WriteString("${" + inner + "}")
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
		case c == '#' && !inWord:
			// A comment: from here to the next newline is ignored, exactly
			// like a real shell — # only starts one as the first character
			// of a word, never mid-word (echo hi#not-a-comment). This is
			// what keeps a script's shebang line (#!/bin/sh) and its
			// ordinary comments from being misread as commands — e.g.
			// #!/bin/sh, taken as a bare word, would otherwise misparse as
			// filepath.Base("#!/bin/sh") == "sh", an invocation of sh with
			// no arguments (CLA-62 now refuses that shape: nothing
			// statically visible to check).
			if j := strings.IndexByte(s[i:], '\n'); j < 0 {
				i = len(s)
			} else {
				i += j
			}
		case c == '\n':
			if len(pending) > 0 {
				// The heredoc body(ies) queued on this line start now,
				// each read in the order its << appeared.
				flushWord()
				pos := i + 1
				for _, ph := range pending {
					body, next := extractHeredocBody(s, pos, ph.delim, ph.strip)
					cur = append(cur, word{hasHeredoc: true, heredoc: body, heredocQuoted: ph.quoted})
					pos = next
				}
				pending = nil
				i = pos
				if len(cur) > 0 {
					cmds = append(cmds, cur)
					cur = nil
				}
				continue
			}
			flushCmd()
			i++
		case c == ';' || c == '|' || c == '&' || c == '(' || c == ')' || c == '{' || c == '}':
			flushCmd()
			i++
		case c == '<' && i+1 < len(s) && s[i+1] == '<':
			flushWord()
			if i+2 < len(s) && s[i+2] == '<' {
				// Here-string <<<WORD: statically visible right here on
				// this same line, so it is left to flow through the
				// ordinary word logic below (CLA-61) like a normal
				// redirection target, instead of being treated as a
				// heredoc body.
				i += 3
				for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
					i++
				}
				continue
			}
			strip := false
			j := i + 2
			if j < len(s) && s[j] == '-' {
				strip = true
				j++
			}
			for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
				j++
			}
			delim, quoted, next := readHeredocDelim(s, j)
			i = next
			if delim != "" {
				pending = append(pending, pendingHeredoc{delim: delim, quoted: quoted, strip: strip})
			}
		case c == '<' || c == '>':
			// Redirection: drop the operator and an fd prefix (2>&1), but
			// let the target itself flow through the ordinary word logic
			// below — it becomes a checkable word exactly like a bare
			// argument, so `cat < .env` refuses the same way `cat .env`
			// does (CLA-61).
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
		default:
			buf.WriteByte(c)
			inWord = true
			i++
		}
	}
	flushCmd()
	return cmds
}

// readHeredocDelim reads a heredoc's delimiter word starting at i, e.g. the
// EOF in <<EOF, 'EOF' in <<'EOF', or "EOF" in <<"EOF". It reports whether
// the delimiter was quoted (any of '...', "..." or a backslash escape) —
// see docs/THREATS.md for what that means for the body — and the index
// right after the delimiter.
func readHeredocDelim(s string, i int) (delim string, quoted bool, next int) {
	var buf strings.Builder
	for i < len(s) {
		switch {
		case s[i] == '\'':
			quoted = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				buf.WriteString(s[i+1:])
				i = len(s)
			} else {
				buf.WriteString(s[i+1 : i+1+j])
				i += j + 2
			}
		case s[i] == '"':
			quoted = true
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					buf.WriteByte(s[i+1])
					i += 2
					continue
				}
				buf.WriteByte(s[i])
				i++
			}
			i++
		case s[i] == '\\' && i+1 < len(s):
			quoted = true
			buf.WriteByte(s[i+1])
			i += 2
		case s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || strings.ContainsRune(";|&()", rune(s[i])):
			return buf.String(), quoted, i
		default:
			buf.WriteByte(s[i])
			i++
		}
	}
	return buf.String(), quoted, i
}

// extractHeredocBody reads a heredoc's body starting at index start (the
// byte right after the newline that ends the line carrying its <<[-]DELIM),
// up to and including the line consisting exactly of delim (after stripping
// leading tabs first when strip is set), returning the body text (without
// the terminator line) and the index right after the terminator line's own
// newline. An unterminated heredoc reads to end of string, matching a real
// shell reading to EOF.
func extractHeredocBody(s string, start int, delim string, strip bool) (string, int) {
	i := start
	var body strings.Builder
	for i <= len(s) {
		lineEnd := strings.IndexByte(s[i:], '\n')
		var line string
		var next int
		if lineEnd < 0 {
			line = s[i:]
			next = len(s)
		} else {
			line = s[i : i+lineEnd]
			next = i + lineEnd + 1
		}
		check := line
		if strip {
			check = strings.TrimLeft(line, "\t")
		}
		if check == delim {
			return body.String(), next
		}
		body.WriteString(line)
		body.WriteByte('\n')
		if lineEnd < 0 {
			return body.String(), len(s)
		}
		i = next
	}
	return body.String(), i
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

// matchBrace returns the text up to the curly brace matching an already
// consumed "{" (from a "${" parameter expansion), and the number of bytes
// consumed including the closer. Nested braces (${x:-${y}}) are balanced
// by depth exactly like matchParen balances nested parens; an unterminated
// expansion reads to end of string.
func matchBrace(s string) (string, int) {
	depth := 1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
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
