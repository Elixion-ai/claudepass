package policy

import (
	"strconv"
	"strings"
)

// word is one shell word with its raw text (quotes removed, expansions kept
// as written) and any command substitutions it contained. A word that
// represents a heredoc/here-document body instead (see splitCommands) has
// raw == "" and hasHeredoc == true; every other word has hasHeredoc ==
// false. A heredoc word's own subs (populated only when its delimiter was
// unquoted — see below) are walked by every consumer that already walks an
// ordinary word's subs (ev.simple's "command substitutions are commands
// too" loop, hookWalk's identical loop), so a $(...) or backtick buried in
// an unquoted heredoc body is evaluated exactly like one anywhere else,
// with no separate plumbing needed.
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
	//
	// CLA-61: a real shell expands an UNQUOTED delimiter's body — command
	// substitutions, backticks, and parameter expansions — exactly like a
	// double-quoted string, before ever handing it to the reading
	// program's stdin; only a QUOTED delimiter's body is genuine inert
	// data. That expansion happens regardless of which program the
	// heredoc is attached to (`cat <<EOF` is exactly as live a leak path
	// as `sh <<EOF`, since $(cat .env) inside the body already ran, and
	// its output already became cat's stdin, before cat ever starts) —
	// see splitCommands' extractHeredocBody call site for where subs gets
	// populated, and ev.simple's heredoc-reveal check for the parameter-
	// expansion half.
	hasHeredoc    bool
	heredoc       string
	heredocQuoted bool

	// fdBindNum is set on an ordinary word that is the TARGET of a
	// `N< target` (or bash's `{name}< target`, which allocates a free
	// descriptor into the named variable instead of a literal number)
	// redirection — the word's raw text is still the target path,
	// exactly like any other redirection target (CLA-61), but it
	// additionally names which file descriptor a same-shell-string
	// `exec N< target` bind associates with that path, so a LATER
	// command's `<&N`/`<&$name` fd-alias redirection (fdAliasNum below)
	// can be resolved back to it
	// (command-policy:read-builtin-and-fd-redirection-bypass). The key
	// is a bare digit string ("3") for the numeric form, or "$name" for
	// the brace form — the same key space a later `<&$name` alias
	// reference resolves through (readFdAliasTarget), since bash itself
	// stores the allocated number into that shell variable.
	fdBindNum string

	// fdAliasNum is set on a synthetic word (raw=="", like a heredoc
	// word) standing for a `<&N`/`<&$name`/`<&${name}` fd-duplication
	// redirection with no filename text of its own — evaluated by
	// resolving this key against a fd earlier bound by `exec N<
	// target`/`exec {name}< target` in the same shell string
	// (evaluator.fds). An unresolvable key (an ordinary, unrelated real
	// file descriptor this package never saw bound) is simply left
	// alone rather than guessed at, the same "resolve only what's
	// statically knowable" default every other dynamic reference in
	// this package already has.
	fdAliasNum string

	// redirTarget is set on an ordinary word that is the TARGET of a
	// plain INPUT redirection (`< target`, or the fd-bind forms `N<
	// target`/`{name}< target`, which also set fdBindNum) — never on a
	// positional argument, a here-string's own word (`<<<` is scanned
	// separately, above `<`/`>` in splitCommands' switch, and never
	// reaches this case), or an output redirection's target (`>
	// target`). This is what lets a consumer tell "the file this word
	// names is a genuine file OPERAND" (`cat < .env`, `read line <
	// .env`) apart from "this word merely occupies the same position a
	// filename would in an ordinary reader invocation" (`read
	// id_rsa_output`, where "id_rsa_output" is read's own destination
	// VARIABLE name, never a file — command-policy:
	// read-builtin-destination-name-not-a-filename). Every other
	// reader's non-flag positional words genuinely are file arguments
	// regardless of this bit (see readBuiltins), so only read/
	// mapfile/readarray's own checks consult it.
	redirTarget bool
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

// shellKeywords are shell reserved words that, in command-start position
// (the first word of a not-yet-begun simple command — cur is still empty
// when the word completes), begin a NEW simple-command context exactly the
// way ';'/'&&'/'||' already separate commands, instead of becoming argv[0]
// of a bogus pseudo-command literally named "if"/"then"/etc. Without this,
// `if cat .env; then true; fi` tokenized as one simple command
// ["if","cat",".env"] — prog=="if" matches no policy rule, so the real
// `cat .env` invocation was never separately evaluated at all
// (command-policy:control-flow-keyword-bypass). Elsewhere in a word list
// (an argument, not a command's own first word) these are ordinary text,
// exactly like "in" inside `for i in 1 2 3` — the loop body's own command,
// after a `do`, still gets its own fresh command-start check.
var shellKeywords = map[string]bool{
	"if": true, "then": true, "elif": true, "else": true, "fi": true,
	"while": true, "until": true, "do": true, "done": true,
	"for": true, "in": true, "case": true, "esac": true, "select": true,
}

// isWordBoundaryByte reports whether s[i] (or end of string) is a
// whitespace/operator byte that could end a bare `{`/`}` token — used to
// tell a standalone `{`/`}` command-grouping operator from one glued to
// adjacent text, e.g. a brace-expansion span like ".{env,bashrc}"
// (command-policy:brace-expansion-hides-filename).
func isWordBoundaryByte(s string, i int) bool {
	if i >= len(s) {
		return true
	}
	switch s[i] {
	case ' ', '\t', '\n', ';', '|', '&', '(', ')':
		return true
	}
	return false
}

// splitCommands breaks a shell string into simple commands (lists of
// words), treating ; & | && || newlines ( ) { } and redirections as
// separators. It understands quotes, backslashes, $(...), backticks,
// ANSI-C ($'...') and locale ($"...") quoting, line-continuations
// (backslash-newline, elided like a real shell), heredocs/here-strings,
// reserved words that begin a new command (if/then/.../done/for/.../esac),
// and single-level, non-nested brace expansion ({a,b,c}, {n..m}, {a..z}).
// It is deliberately conservative: unknown syntax becomes ordinary words.
func splitCommands(s string) [][]word {
	var cmds [][]word
	var cur []word
	var buf strings.Builder
	var subs []string
	var pending []pendingHeredoc
	inWord := false
	// pendingFDBind is the fd key (see word.fdBindNum) dropped by the most
	// recently seen `N<`/`{name}<` redirection operator, carried forward
	// so the very next word tokenized — that redirection's own target —
	// picks it up as its fdBindNum. Cleared the instant it's consumed, at
	// every command boundary, and at the start of every new redirection
	// (see the '<'/'>' case), so it can never leak onto an unrelated
	// later word (command-policy:read-builtin-and-fd-redirection-bypass).
	var pendingFDBind string
	// pendingRedirIn mirrors pendingFDBind exactly (same set/consume/clear
	// points) but for the plain, no-fd-prefix case too: set by the
	// '<'/'>' case whenever the operator was '<' (an input redirection,
	// including the fd-bind forms, which also set pendingFDBind), and
	// carried onto the very next word tokenized as that word's own
	// redirTarget bit (command-policy:read-builtin-destination-name-not-
	// a-filename). Left false for a '>' output redirection's target,
	// which is never a reader's file operand.
	var pendingRedirIn bool
	// caseDepth, inCaseHeader and wantPattern together recognize a `case
	// X in PATTERN) cmds ;; PATTERN2) cmds ;; esac` statement's own
	// PATTERN words as pattern-arm syntax, not a command to evaluate —
	// without this, `set)`/`env)`/`export)` (an entirely ordinary case
	// arm for a CLI whose own subcommands happen to share a name with
	// one of this package's zero-argument-triggers-a-refusal builtins,
	// e.g. a script with its own `set`/`env` subcommand) tokenizes as a
	// bare one-word command "set"/"env"/"export" with no arguments,
	// which several of this package's own rules refuse outright
	// (command-policy:case-statement-pattern-arm-not-a-command).
	// caseDepth counts currently-open case blocks (case/esac are
	// otherwise ordinary shellKeywords entries, discarded exactly like
	// if/while/for/etc. already are); inCaseHeader is true only between
	// a just-opened case's own keyword and its matching "in" (so a
	// selector expression, `case "$1" in`, is never mistaken for a
	// pattern); wantPattern is true only for the pattern-arm position
	// itself — right after that "in", or right after a `;;` that ends
	// one arm and starts the next — and is what flushCmd (below) and the
	// ')' case (see the '<'/'>' redirection case's sibling switch arms
	// further down) consult to discard a pattern word instead of
	// treating it as a real command. A single, non-stacked wantPattern
	// (rather than one per case-nesting level) stays correct for a
	// case-inside-a-case: discarding "esac" always clears it, which is
	// exactly the state the ENCLOSING context should be in immediately
	// after a nested case statement closes (its own arm's body, not a
	// fresh pattern position) — see the shellKeywords branch below.
	var caseDepth int
	var inCaseHeader bool
	var wantPattern bool

	flushWord := func() {
		if inWord {
			w := buf.String()
			ws := subs
			buf.Reset()
			subs = nil
			inWord = false
			if len(cur) == 0 && shellKeywords[w] {
				// A reserved word in command-start position: discard it
				// (it carries no subs of its own — no $()/backtick text
				// can equal a bare keyword) rather than let it become
				// argv[0] of a fake command; the word that follows is
				// judged as the real one.
				pendingFDBind = ""
				pendingRedirIn = false
				switch w {
				case "case":
					caseDepth++
					inCaseHeader = true
				case "esac":
					if caseDepth > 0 {
						caseDepth--
					}
					wantPattern = false
					inCaseHeader = false
				}
				return
			}
			if w == "in" && inCaseHeader {
				// The "in" that ends a case statement's own header — its
				// selector word(s), already sitting in cur, are flushed
				// as their own inert leftover "command" exactly like an
				// ordinary bareword that matches no policy rule (the
				// same harmless fallthrough `for i in 1 2 3`'s own
				// selector words already get) — never discarded as a
				// keyword itself: "in" is a keyword only in command-start
				// position, and cur is never empty here (the selector
				// word(s) already occupy it).
				pendingFDBind = ""
				pendingRedirIn = false
				inCaseHeader = false
				wantPattern = true
				return
			}
			fd := pendingFDBind
			pendingFDBind = ""
			ri := pendingRedirIn
			pendingRedirIn = false
			cur = append(cur, word{raw: w, subs: ws, fdBindNum: fd, redirTarget: ri})
		}
	}
	flushCmd := func() {
		flushWord()
		pendingFDBind = ""
		pendingRedirIn = false
		if wantPattern && caseDepth > 0 {
			// A case-pattern word (or one alternative of a `|`-separated
			// pattern list, each ended by its own flushCmd via the '|'
			// case below) — never a real command, so it is discarded
			// rather than appended to cmds, exactly like a comment or a
			// bare keyword already is above
			// (command-policy:case-statement-pattern-arm-not-a-command).
			// wantPattern itself stays true across a `|` alternative
			// (only ')' below clears it) and across this flush.
			cur = nil
			return
		}
		if len(cur) > 0 {
			cmds = append(cmds, expandBraces(cur))
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
		case c == '$' && ifsRefLen(s, i) > 0:
			// An UNQUOTED $IFS/${IFS} reference: a real shell performs
			// word-splitting on this expansion's result using IFS's
			// current value, whose DEFAULT is whitespace — so
			// `cat${IFS}.env`/`cat$IFS.env` really tokenize as the two
			// separate words "cat" and ".env", not one glued word
			// "cat${IFS}.env"/"cat$IFS.env" that matches no
			// reader/secret-file rule at all
			// (command-policy:ifs-word-splitting-bypass). Modeled
			// structurally as a word boundary right here — flushing
			// whatever was built so far and starting fresh — exactly
			// like whitespace already is, rather than guessing at IFS's
			// actual runtime value (which could in principle be
			// something other than whitespace; treating every unquoted
			// $IFS/${IFS} reference as a split point is the conservative
			// direction of that unknown, since it can only ever produce
			// MORE, smaller words to check, never fewer). A quoted
			// "$IFS"/"${IFS}" never reaches this case at all — quoting
			// suppresses word-splitting in a real shell too, and quotes
			// have their own self-contained scanning branches above that
			// never fall through to this switch.
			flushWord()
			i += ifsRefLen(s, i)
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
			text, sb, next := scanDoubleQuotedBody(s, i+1)
			buf.WriteString(text)
			subs = append(subs, sb...)
			inWord = true
			i = next
		case c == '$' && i+1 < len(s) && s[i+1] == '\'':
			// ANSI-C quoting, $'...': contributes only its unescaped text
			// to the word, consuming no literal leading '$'
			// (command-policy:quoting-ansi-c-and-locale-strings) —
			// without this case the '$' fell through to the default
			// handler as a literal byte and the following '...' was then
			// parsed as an ordinary single-quoted string, so `cat
			// $'.env'` mangled into the word "$.env", which matches no
			// secret-file glob.
			text, next := scanAnsiCString(s, i+2)
			buf.WriteString(text)
			inWord = true
			i = next
		case c == '$' && i+1 < len(s) && s[i+1] == '"':
			// Locale-translated quoting, $"...": behaves like an ordinary
			// double-quoted string — translation is a runtime-only
			// concern this checker can safely ignore — consuming no
			// literal leading '$' either, for the same reason as $'...'
			// above.
			text, sb, next := scanDoubleQuotedBody(s, i+2)
			buf.WriteString(text)
			subs = append(subs, sb...)
			inWord = true
			i = next
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
					w := word{hasHeredoc: true, heredoc: body, heredocQuoted: ph.quoted}
					if !ph.quoted {
						// CLA-61: an unquoted delimiter's body is expanded
						// by a real shell before it ever reaches the
						// reading program's stdin — the same command
						// substitutions a double-quoted string carries
						// (see scanUnquotedSubs), so every existing
						// subs-walking consumer (this package's own
						// "command substitutions are commands too" loops)
						// picks them up with no extra plumbing. A quoted
						// delimiter's body stays exactly as inert as it
						// is in a real shell: no subs, ever.
						w.subs = scanUnquotedSubs(body)
					}
					cur = append(cur, w)
					pos = next
				}
				pending = nil
				i = pos
				if len(cur) > 0 {
					cmds = append(cmds, expandBraces(cur))
					cur = nil
				}
				continue
			}
			flushCmd()
			i++
		case c == ';' && i+1 < len(s) && s[i+1] == ';':
			// `;;`: ends a case statement's own arm, exactly the boundary
			// a real shell's case grammar gives it — re-opening the
			// pattern-arm position for whatever comes next (another
			// PATTERN), or "esac", both handled by wantPattern/
			// inCaseHeader's own logic above
			// (command-policy:case-statement-pattern-arm-not-a-command).
			// A lone ';' (the generic case just below) never does this:
			// only the doubled form is bash's own arm terminator.
			flushCmd()
			if caseDepth > 0 {
				wantPattern = true
			}
			i += 2
		case c == ';' || c == '|' || c == '&' || c == '(':
			flushCmd()
			i++
		case c == ')':
			flushCmd()
			// Clears whatever pattern-arm position wantPattern was
			// tracking — the word(s) just flushed (discarded above, in
			// flushCmd) were this pattern's own text; anything from here
			// until the next ';;'/`in` is the arm's actual command body,
			// checked exactly like any other command
			// (command-policy:case-statement-pattern-arm-not-a-command).
			// Harmless when wantPattern was already false (an ordinary
			// subshell-closing or otherwise unrelated ')').
			wantPattern = false
			i++
		case (c == '{' || c == '}') && !inWord && isWordBoundaryByte(s, i+1):
			// A standalone `{`/`}` token: real bash's command-grouping
			// reserved word, exactly like ';'/'&&'/'||' above. Only
			// recognized as such when it is its own whitespace/operator-
			// delimited token (mirroring shellKeywords' command-start
			// check) — glued to adjacent text (a brace-expansion span like
			// ".{env,bashrc}", or any other glued spelling) it falls
			// through to the default case below as ordinary text instead,
			// so the word is never silently truncated
			// (command-policy:brace-expansion-hides-filename); expandBraces
			// then expands a recognized {a,b,c}/{n..m}/{a..z} span within
			// that intact word into the separate words it stands for.
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
			// Redirection: drop the operator and an fd prefix (2>&1, or
			// bash's `{name}<`/`{name}>` form, which allocates a free
			// descriptor into the named variable instead of a literal
			// number), but let the target itself flow through the
			// ordinary word logic below — it becomes a checkable word
			// exactly like a bare argument, so `cat < .env` refuses the
			// same way `cat .env` does (CLA-61). Any new redirection
			// starts with a clean slate for fd tracking — a fd key from
			// an EARLIER, already-consumed redirection must never leak
			// onto this one's target.
			pendingFDBind = ""
			pendingRedirIn = false
			var fdKey string
			var fdKeyOK bool
			if c == '<' {
				// Only an INPUT redirection's dropped fd prefix is worth
				// tracking at all — this fix is about later reading a
				// bound fd back (`<&N`), never about output.
				fdKey, fdKeyOK = fdBindPrefix(buf.String())
			}
			if isDigits(buf.String()) || fdKeyOK {
				buf.Reset()
				inWord = false
			}
			flushWord()
			if c == '<' && i+1 < len(s) && s[i+1] == '&' {
				// <&N / <&$name / <&${name}: a fd-duplication/alias
				// redirection with no filename text of its own —
				// captured as a synthetic word (mirroring a heredoc
				// word: raw=="", real content held elsewhere) carrying
				// which fd it aliases, resolved by the evaluator
				// against a same-shell-string `exec N<
				// target`/`exec {name}< target` bind
				// (command-policy:read-builtin-and-fd-redirection-
				// bypass's second half: `cat <&3` after `exec 3<
				// .env`). Anything else after `<&` this package doesn't
				// recognize (`<&-` closing a fd, a malformed reference)
				// falls through to the generic consuming loop below
				// unchanged, exactly as it did before this fix — left
				// alone rather than guessed at.
				if aliasKey, next, ok := readFdAliasTarget(s, i+2); ok {
					cur = append(cur, word{fdAliasNum: aliasKey})
					i = next
					for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
						i++
					}
					continue
				}
			}
			for i < len(s) && (s[i] == '<' || s[i] == '>' || s[i] == '&' || (s[i] >= '0' && s[i] <= '9')) {
				i++
			}
			for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
			if fdKeyOK {
				// The very next word tokenized — this redirection's own
				// target — picks this up via flushWord() above.
				pendingFDBind = fdKey
			}
			// The very next word tokenized is this redirection's own
			// target (word.redirTarget) whenever it was an INPUT
			// redirection — including the fd-bind forms just above,
			// which additionally set pendingFDBind — but never for a
			// '>' output redirection's target, which is never a
			// reader's file operand
			// (command-policy:read-builtin-destination-name-not-a-
			// filename). The `<&N` fd-alias sub-case above already
			// `continue`d before reaching here, so it never sets this.
			pendingRedirIn = c == '<'
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

// scanUnquotedSubs extracts every $(...) and backtick command substitution
// from s the same way splitCommands' own double-quote branch does (backslash
// escapes a single following byte and is otherwise inert; a $( opens a
// matchParen-balanced span; a backtick pair delimits the other backtick
// form) — for text that was never itself inside a shell word, namely an
// unquoted heredoc's body (CLA-61). A real shell performs exactly this
// expansion on such a body before handing it to the reading program's
// stdin, whatever that program is — the shell has already run $(cat .env)
// and already handed its output to cat's stdin before cat ever starts, so
// this must be found regardless of which program the heredoc is attached
// to, not only a shell (which already gets its whole body re-parsed as a
// script by ev.shell — this function exists for every *other* program a
// heredoc can be attached to). A bare, unmatched backtick or an
// unterminated $( reads to end of string, same as the double-quote branch.
func scanUnquotedSubs(s string) []string {
	var subs []string
	for i := 0; i < len(s); {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			i += 2
		case s[i] == '$' && i+1 < len(s) && s[i+1] == '(':
			inner, n := matchParen(s[i+2:])
			subs = append(subs, inner)
			i += 2 + n
		case s[i] == '`':
			j := strings.IndexByte(s[i+1:], '`')
			if j < 0 {
				i++
				continue
			}
			subs = append(subs, s[i+1:i+1+j])
			i += j + 2
		default:
			i++
		}
	}
	return subs
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

// isIdentByte reports whether b can appear in a bare shell identifier
// (variable/fd name): letters, digits, or underscore.
func isIdentByte(b byte) bool {
	return b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// ifsRefLen reports the byte length of an unquoted $IFS or ${IFS}
// reference starting at s[i] (s[i]=='$'), or 0 when s[i:] isn't one —
// including when it's glued into a longer identifier ($IFSFOO is the
// variable IFSFOO, not $IFS followed by "FOO") — see the case in
// splitCommands that calls this
// (command-policy:ifs-word-splitting-bypass).
func ifsRefLen(s string, i int) int {
	if i >= len(s) || s[i] != '$' {
		return 0
	}
	if strings.HasPrefix(s[i:], "${IFS}") {
		return len("${IFS}")
	}
	if strings.HasPrefix(s[i:], "$IFS") {
		end := i + 4
		if end < len(s) && isIdentByte(s[end]) {
			return 0 // glued into a longer name, e.g. $IFSFOO
		}
		return 4
	}
	return 0
}

// fdBindPrefix reports whether buf — text accumulated immediately before
// a `<`/`>` redirection operator — names a file-descriptor prefix for an
// fd-bind redirection: a bare number (`exec 3< target`) or bash's
// `{name}` form (`exec {fd}< target`, which allocates a free descriptor
// and stores its number in the named shell variable). When it does, key
// is what evaluator.fds should record the target under — the bare number
// itself, or "$name" for the brace form, matching the key space a later
// `<&N`/`<&$name` alias lookup uses (readFdAliasTarget) — since bash
// itself stores the allocated number into that variable, not into a
// literal "{name}" token.
func fdBindPrefix(buf string) (key string, ok bool) {
	if isDigits(buf) {
		return buf, true
	}
	if len(buf) > 2 && buf[0] == '{' && buf[len(buf)-1] == '}' {
		inner := buf[1 : len(buf)-1]
		if identRe.MatchString(inner) {
			return "$" + inner, true
		}
	}
	return "", false
}

// readFdAliasTarget reads what follows a `<&` fd-duplication operator
// starting at i: either a bare fd number (`<&3`) or a variable reference
// naming one (`<&$fd`/`<&${fd}`) — the two shapes bash's `exec {fd}<
// target; ... <&$fd` idiom for a dynamically-allocated descriptor uses,
// alongside the plain `exec N< target; ... <&N` numeric form. Returns
// the alias key normalized to the same key space fdBindPrefix populates
// (a bare digit string, or "$name"), and whether anything recognizable
// followed `<&` at all — `<&-` (closing a fd) or anything else this
// package doesn't attempt returns ok==false, leaving the redirection to
// fall through to the ordinary digit/`&`-consuming loop unchanged, the
// same "resolve only what's statically knowable, don't guess" default
// this package already applies everywhere else.
func readFdAliasTarget(s string, i int) (key string, next int, ok bool) {
	if i < len(s) && s[i] == '$' {
		j := i + 1
		braced := false
		if j < len(s) && s[j] == '{' {
			braced = true
			j++
		}
		start := j
		for j < len(s) && isIdentByte(s[j]) {
			j++
		}
		if j == start {
			return "", i, false
		}
		name := s[start:j]
		if braced {
			if j < len(s) && s[j] == '}' {
				j++
			} else {
				return "", i, false
			}
		}
		return "$" + name, j, true
	}
	j := i
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	if j == i {
		return "", i, false
	}
	return s[i:j], j, true
}

// scanDoubleQuotedBody reads the body of a double-quoted string — the
// ordinary "..." form, or its locale-translated cousin $"..." (the only
// difference between the two is the literal bytes that introduce them;
// translation itself is a runtime-only concern this checker can safely
// ignore, matching the untranslated fallback) — starting right after its
// opening quote, up to and including its closing quote. Command
// substitutions and backtick substitutions inside are recorded into subs
// exactly like the plain '"' case always has; a trailing backslash-newline
// is elided, matching real shell line-continuation semantics inside a
// double-quoted string. i pointing past end of string (an unterminated
// quote) reads to end of string, same as before this was factored out.
func scanDoubleQuotedBody(s string, i int) (text string, subs []string, next int) {
	var buf strings.Builder
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
	if i < len(s) {
		i++ // closing quote
	}
	return buf.String(), subs, i
}

// scanAnsiCString reads the body of bash's ANSI-C-quoted string, $'...' —
// i pointing right after its opening quote — up to and including its
// closing quote, applying the same backslash-escape processing a real
// shell does inside $'...': \n \t \r \a \b \f \v \e \\ \' \" \? all
// contribute the byte they name, \xHH (1-2 hex digits) and \0NNN/\NNN (1-3
// octal digits) contribute the byte they encode, and any other backslash
// sequence keeps its escaped character literally, dropping only the
// backslash — matching real bash's own fallback for a sequence it doesn't
// recognize. Command substitutions and parameter expansions are NOT
// processed inside $'...' (a real shell does not perform them there
// either — only backslash escapes). Returns the unescaped text and the
// index right after the closing quote (or end of string if unterminated).
func scanAnsiCString(s string, i int) (string, int) {
	var buf strings.Builder
	for i < len(s) && s[i] != '\'' {
		if s[i] != '\\' || i+1 >= len(s) {
			buf.WriteByte(s[i])
			i++
			continue
		}
		c := s[i+1]
		switch c {
		case 'n':
			buf.WriteByte('\n')
			i += 2
		case 't':
			buf.WriteByte('\t')
			i += 2
		case 'r':
			buf.WriteByte('\r')
			i += 2
		case 'a':
			buf.WriteByte('\a')
			i += 2
		case 'b':
			buf.WriteByte('\b')
			i += 2
		case 'f':
			buf.WriteByte('\f')
			i += 2
		case 'v':
			buf.WriteByte('\v')
			i += 2
		case 'e', 'E':
			buf.WriteByte(0x1b)
			i += 2
		case '\\', '\'', '"', '?':
			buf.WriteByte(c)
			i += 2
		case 'x':
			j, n, val := i+2, 0, 0
			for j < len(s) && n < 2 && isHexDigit(s[j]) {
				val = val*16 + hexVal(s[j])
				j++
				n++
			}
			if n > 0 {
				buf.WriteByte(byte(val))
				i = j
			} else {
				buf.WriteByte(c)
				i += 2
			}
		case '0', '1', '2', '3', '4', '5', '6', '7':
			j, n, val := i+1, 0, 0
			for j < len(s) && n < 3 && s[j] >= '0' && s[j] <= '7' {
				val = val*8 + int(s[j]-'0')
				j++
				n++
			}
			buf.WriteByte(byte(val))
			i = j
		default:
			buf.WriteByte(c)
			i += 2
		}
	}
	if i < len(s) {
		i++ // closing quote
	}
	return buf.String(), i
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func hexVal(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10
	default:
		return int(b-'A') + 10
	}
}

// maxBraceExpansion bounds how many alternatives expandBraceWord/
// numericRange/letterRange will generate for one {..} span, so a huge
// range like {0..999999999} bails out (leaving the word unexpanded,
// exactly like any other shape this function doesn't attempt) instead of
// building a huge slice.
const maxBraceExpansion = 256

// expandBraces expands each word in words that carries a single-level,
// non-nested brace-expansion span ({a,b,c}, {n..m}, {a..z}) into the
// several words it stands for — the same flattening a real shell performs
// on a command line before that command ever runs, so e.g. `cat
// .{env,bashrc}` presents ".env" and ".bashrc" as separately checkable
// arguments instead of the one intact-but-unmatchable literal
// ".{env,bashrc}" (command-policy:brace-expansion-hides-filename). A
// heredoc-body word (hasHeredoc) is never a candidate — its raw text is
// empty and its actual body is checked by other means — so it passes
// through unchanged. Likewise a fd-alias word (fdAliasNum set, raw=="",
// mirroring a heredoc word's own empty raw) is never a candidate, for
// the same reason. A fd-bind word's fdBindNum (see split.go's word doc
// comment) is carried onto every alternative a brace span inside its own
// raw text expands to, exactly like subs already is, so `exec 3<
// .{env,bashrc}` — a contrived but real shape — still ends up tracking
// fd 3 against each expanded candidate.
func expandBraces(words []word) []word {
	out := make([]word, 0, len(words))
	for _, w := range words {
		if w.hasHeredoc || w.fdAliasNum != "" {
			out = append(out, w)
			continue
		}
		for _, r := range expandBraceWord(w.raw) {
			out = append(out, word{raw: r, subs: w.subs, fdBindNum: w.fdBindNum, redirTarget: w.redirTarget})
		}
	}
	return out
}

// expandBraceWord expands the first {..} span in w that parses as a plain
// comma list or a numeric/single-letter range, replacing it with each of
// its alternatives in turn (single-level: a further {..} span nested
// inside is left unattempted, and a second, later span in the same word is
// left for a future pass to expand as its own word — still strictly safer
// than not expanding at all, since every result is still checked
// individually). A word with no {..} span, or one that doesn't parse as
// either shape (nested braces, no comma and no "..", an unparseable
// range, ...), is returned unchanged — real bash's own fallback for
// anything it can't expand is also to leave the literal text alone.
func expandBraceWord(w string) []string {
	start := strings.IndexByte(w, '{')
	if start < 0 {
		return []string{w}
	}
	depth := 0
	end := -1
	for i := start; i < len(w); i++ {
		switch w[i] {
		case '{':
			depth++
			if depth > 1 {
				return []string{w} // nested: not attempted
			}
		case '}':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return []string{w}
	}
	alts := braceAlternatives(w[start+1 : end])
	if len(alts) < 2 {
		return []string{w}
	}
	prefix, suffix := w[:start], w[end+1:]
	out := make([]string, 0, len(alts))
	for _, a := range alts {
		out = append(out, prefix+a+suffix)
	}
	return out
}

// braceAlternatives parses the interior of a single {..} span as either a
// comma-separated list (a,b,c — real bash requires at least one comma; a
// brace with neither a comma nor ".." is not an expansion at all) or a
// ".."-range (numeric, or a single a-z/A-Z letter, ascending or
// descending), returning nil when neither shape matches.
func braceAlternatives(inner string) []string {
	if inner == "" {
		return nil
	}
	if strings.Contains(inner, ",") {
		return strings.Split(inner, ",")
	}
	if idx := strings.Index(inner, ".."); idx >= 0 {
		a, b := inner[:idx], inner[idx+2:]
		if out, ok := numericRange(a, b); ok {
			return out
		}
		if out, ok := letterRange(a, b); ok {
			return out
		}
	}
	return nil
}

func numericRange(a, b string) ([]string, bool) {
	lo, errA := strconv.Atoi(a)
	hi, errB := strconv.Atoi(b)
	if errA != nil || errB != nil {
		return nil, false
	}
	step := 1
	if lo > hi {
		step = -1
	}
	var out []string
	for n := lo; ; n += step {
		out = append(out, strconv.Itoa(n))
		if n == hi {
			break
		}
		if len(out) > maxBraceExpansion {
			return nil, false
		}
	}
	return out, true
}

func letterRange(a, b string) ([]string, bool) {
	if len(a) != 1 || len(b) != 1 {
		return nil, false
	}
	lo, hi := a[0], b[0]
	isAlpha := func(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
	if !isAlpha(lo) || !isAlpha(hi) {
		return nil, false
	}
	step := 1
	if lo > hi {
		step = -1
	}
	var out []string
	for c := int(lo); ; c += step {
		out = append(out, string(rune(c)))
		if byte(c) == hi {
			break
		}
		if len(out) > maxBraceExpansion {
			return nil, false
		}
	}
	return out, true
}
