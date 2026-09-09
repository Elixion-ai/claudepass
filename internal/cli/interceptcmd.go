package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"claudepass/internal/broker"
	"claudepass/internal/detect"
	"claudepass/internal/vault"
)

func init() {
	register(command{"intercept", "Claude Code UserPromptSubmit hook: catch a pasted Secret before the Agent sees it", cmdIntercept})
}

// hookInput is the subset of Claude Code's UserPromptSubmit hook JSON this
// command reads from stdin. Extra fields (session_id, transcript_path, cwd,
// hook_event_name, ...) are present in real hook payloads and ignored here.
type hookInput struct {
	Prompt string `json:"prompt"`
}

// bypassPrefix lets a human force a misdetected prompt through. Per
// CONTEXT.md's definition of Exposed, any value still found is stored and
// flagged Exposed anyway: it is about to enter the Agent's Context.
const bypassPrefix = "!!"

func cmdIntercept(e *env) int {
	fs := flag.NewFlagSet("intercept", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	if _, err := parseInterspersed(fs, e.args); err != nil {
		return ExitUsage
	}

	raw, err := io.ReadAll(e.stdin)
	if err != nil {
		return e.failErr(err)
	}
	var in hookInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return e.fail(ExitUsage, "invalid hook JSON on stdin: %v", err)
	}

	bypass := strings.HasPrefix(in.Prompt, bypassPrefix)
	matches := detect.Scan(in.Prompt)
	if len(matches) == 0 {
		return ExitOK
	}

	if bypass {
		interceptBypass(e, matches)
		return ExitOK
	}

	v, code := openVault(e)
	if code != ExitOK {
		return code
	}
	used := map[string]bool{}
	for _, en := range v.List("") {
		used[en.Handle] = true
	}
	var stored []string
	for _, m := range matches {
		handle := uniqueHandle(used, inferredOrInbox(m))
		if _, err := v.Add(handle, m.Value, vault.AddOptions{}); err != nil {
			return e.failErr(err)
		}
		stored = append(stored, fmt.Sprintf("%s as %s", m.Kind, handle))
	}
	if err := v.Save(); err != nil {
		return e.failErr(err)
	}
	// Claude Code's UserPromptSubmit hook protocol: exit 2 blocks the
	// submission and shows this stderr text to the human, who resubmits.
	fmt.Fprintf(e.stderr, "cpass: stored %s; resubmit using the Handle, or prefix with !! to send anyway\n",
		joinWithAnd(stored))
	return ExitUsage
}

// interceptBypass stores every detected value as Exposed and never blocks:
// a bypassed prompt must always pass through, even if the Vault happens to
// be locked (storage is then simply skipped).
func interceptBypass(e *env, matches []detect.Match) {
	v, err := broker.OpenVault()
	if err != nil {
		return
	}
	used := map[string]bool{}
	for _, en := range v.List("") {
		used[en.Handle] = true
	}
	var stored []string
	for _, m := range matches {
		handle := uniqueHandle(used, inferredOrInbox(m))
		if _, err := v.Add(handle, m.Value, vault.AddOptions{Exposed: "bypass"}); err != nil {
			continue
		}
		stored = append(stored, handle)
	}
	if len(stored) == 0 {
		return
	}
	if err := v.Save(); err != nil {
		return
	}
	fmt.Fprintf(e.stderr, "cpass: bypass — stored and flagged Exposed: %s\n", strings.Join(stored, ", "))
}

// inferredOrInbox returns the Match's inferred Handle, or an inbox/<timestamp>
// fallback when detection could only tell that the value looks like a
// Secret, not what kind.
func inferredOrInbox(m detect.Match) string {
	if m.Handle != "" {
		return m.Handle
	}
	return "inbox/" + time.Now().UTC().Format("20060102-150405")
}

// uniqueHandle returns base, or base with a "-2", "-3", ... suffix if it
// collides with an already-used Handle (existing Vault entries, or an
// earlier value from the same call), and marks the result used.
func uniqueHandle(used map[string]bool, base string) string {
	h := base
	for n := 2; used[h]; n++ {
		h = fmt.Sprintf("%s-%d", base, n)
	}
	used[h] = true
	return h
}

// joinWithAnd renders ["a", "b", "c"] as "a, b and c".
func joinWithAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	default:
		return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
	}
}
