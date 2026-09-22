package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Elixion-ai/claudepass/internal/broker"
	"github.com/Elixion-ai/claudepass/internal/detect"
	"github.com/Elixion-ai/claudepass/internal/vault"
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
	fs.SetOutput(io.Discard)
	if _, err := parseInterspersed(fs, e.args); err != nil {
		return e.usageErr(err, "cpass intercept")
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
	matches := detect.ScanStrict(in.Prompt)
	if len(matches) == 0 {
		return ExitOK
	}

	if bypass {
		interceptBypass(e, matches)
		return ExitOK
	}

	var stored []string
	code := updateVault(e, func(v *vault.Vault) error {
		used := map[string]bool{}
		for _, en := range v.List("") {
			used[en.Handle] = true
		}
		for _, m := range matches {
			handle := uniqueHandle(used, inferredOrInbox(m))
			if _, err := v.Add(handle, m.Value, vault.AddOptions{}); err != nil {
				return err
			}
			// Always plain: this text ends up in the stderr Claude Code's
			// UserPromptSubmit hook re-displays to the human (see
			// cmdIntercept's doc comment), not a terminal cpass itself
			// controls, so it must never carry escapes regardless of this
			// process's stderr TTY-ness — the same reasoning as
			// cmdPolicy's hook branch (policycmd.go).
			stored = append(stored, storedTextForMode(colorNone, m.Kind, handle))
		}
		return nil
	})
	if code != ExitOK {
		return code
	}
	// Claude Code's UserPromptSubmit hook protocol: exit 2 blocks the
	// submission and shows this stderr text to the human, who resubmits.
	// docs/CLI-STYLE.md's Intercept row joins multiple items with a plain
	// comma, not "a, b and c".
	e.notice("stored %s; resubmit using the Handle, or prefix with !! to send anyway", strings.Join(stored, ", "))
	return ExitUsage
}

// errNothingToStore signals interceptBypass's update callback that no match
// was actually stored, so broker.UpdateVault skips the Save — Update always
// Saves on a nil return, and an empty prompt-scan result must not spend a
// write (or a lock) on a Vault that hasn't actually changed.
var errNothingToStore = errors.New("intercept: nothing to store")

// interceptBypass stores every detected value as Exposed and never blocks:
// a bypassed prompt must always pass through, even if the Vault happens to
// be locked, or the write lock is contended (storage is then simply
// skipped) — any error here is deliberately swallowed.
func interceptBypass(e *env, matches []detect.Match) {
	var stored []string
	err := broker.UpdateVault(func(v *vault.Vault) error {
		used := map[string]bool{}
		for _, en := range v.List("") {
			used[en.Handle] = true
		}
		for _, m := range matches {
			handle := uniqueHandle(used, inferredOrInbox(m))
			if _, err := v.Add(handle, m.Value, vault.AddOptions{Exposed: "bypass"}); err != nil {
				continue
			}
			stored = append(stored, handle)
		}
		if len(stored) == 0 {
			return errNothingToStore
		}
		return nil
	})
	if err != nil {
		return
	}
	e.notice("bypass — stored and flagged Exposed: %s", strings.Join(stored, ", "))
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
