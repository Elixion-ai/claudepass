// Package integrate holds the Agent instruction text shared by every
// integration target (Codex's AGENTS.md today; the Claude Code skill and the
// MCP server's own docs later) and the logic to write it into a delimited,
// idempotent section of a text file.
package integrate

import "strings"

const (
	beginMarker = "<!-- cpass:begin -->"
	endMarker   = "<!-- cpass:end -->"
)

// Snippet is the instruction text every integration teaches an Agent: use
// `cpass run`, never read `.env`, capture generated values, check the
// Manifest. Kept to the fewest words that say it correctly.
const Snippet = `## ClaudePass

This project keeps Secrets in a ClaudePass Vault; you only ever see a Handle, never a value.

- Never read ` + "`.env`" + ` or any other secret file directly.
- Run commands that need a Secret through ` + "`cpass run -- <command>`" + `. It injects every Handle declared in ` + "`.claudepass.toml`" + `; add one ad hoc with ` + "`--with <handle>[:VAR]`" + `.
- When a command produces a new secret value, capture it instead of reading the output yourself: ` + "`cpass capture <handle> -- <command>`" + ` stores stdout as a Secret and prints only the Handle.
- Before relying on a Secret being available, run ` + "`cpass manifest check`" + `; it exits non-zero and names any missing Handle.
`

// section is the full delimited block written into a target file: a begin
// marker, the Snippet, and an end marker, each on its own line.
func section() string {
	return beginMarker + "\n" + Snippet + endMarker + "\n"
}

// findSection returns the byte range of the delimited section in content,
// including one trailing newline after the end marker if present, so the
// range can be sliced out and replaced without disturbing what follows.
func findSection(content string) (start, end int, ok bool) {
	bi := strings.Index(content, beginMarker)
	if bi < 0 {
		return 0, 0, false
	}
	rest := content[bi:]
	ei := strings.Index(rest, endMarker)
	if ei < 0 {
		return 0, 0, false
	}
	end = bi + ei + len(endMarker)
	if end < len(content) && content[end] == '\n' {
		end++
	}
	return bi, end, true
}

// Apply returns content with the ClaudePass section written in: replaced in
// place if one already exists, appended (after a blank line) otherwise. The
// second return value reports whether the result differs from content, so a
// caller can skip rewriting a file that is already up to date.
func Apply(content string) (string, bool) {
	sec := section()
	if start, end, ok := findSection(content); ok {
		if content[start:end] == sec {
			return content, false
		}
		return content[:start] + sec + content[end:], true
	}
	trimmed := strings.TrimRight(content, "\n")
	if trimmed == "" {
		return sec, true
	}
	return trimmed + "\n\n" + sec, true
}
