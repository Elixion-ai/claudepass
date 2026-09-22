package cli

import (
	"flag"
	"io"
	"os"
	"path/filepath"

	"github.com/Elixion-ai/claudepass/internal/integrate"
)

func init() {
	registerIntegration("claude", integrateClaude)
}

// defaultClaudeSkillsDir is ~/.claude/skills, the personal, always-loaded
// skills directory Claude Code auto-discovers plugins in (see the
// "Skills-directory plugins" section of the plugins reference). It falls
// back to a relative path only if the home directory can't be found, which
// os.UserHomeDir documents as rare (an unset $HOME).
func defaultClaudeSkillsDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".claude", "skills")
	}
	return filepath.Join(".claude", "skills")
}

// integrateClaude implements `cpass integrate claude [--path DIR] [--remove]`:
// write the ClaudePass plugin (hooks + skill) into DIR/claudepass, a Claude
// Code skills-directory plugin folder. Claude Code loads any folder there
// with a .claude-plugin/plugin.json automatically, on the next session, as
// claudepass@skills-dir — no marketplace registration or `claude plugin
// install` step, and nothing here shells out to the claude binary, so this
// works even before Claude Code has been installed. --path exists mainly
// so a non-default install target (or a test) never has to touch the real
// ~/.claude/skills directory. --remove is the inverse: it deletes that same
// plugin directory (see integrate.RemoveClaudePlugin for the safety check
// that keeps it from touching a directory cpass didn't itself install).
func integrateClaude(e *env, args []string) int {
	fs := flag.NewFlagSet("integrate claude", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("path", defaultClaudeSkillsDir(), "Claude Code skills directory to install into")
	remove := fs.Bool("remove", false, "remove the ClaudePass plugin this command installed")
	if err := fs.Parse(args); err != nil {
		return e.usageErr(err, "cpass integrate claude [--path DIR] [--remove]")
	}
	if fs.NArg() != 0 {
		return e.fail(ExitUsage, "usage: cpass integrate claude [--path DIR] [--remove]")
	}

	target := filepath.Join(*dir, "claudepass")

	if *remove {
		removed, err := integrate.RemoveClaudePlugin(target)
		if err != nil {
			return e.failErr(err)
		}
		if !removed {
			fprintf(e.stdout, "%s not installed, nothing to remove\n", target)
			return ExitOK
		}
		fprintf(e.stdout, "removed %s\n", target)
		return ExitOK
	}

	changed, err := integrate.WriteClaudePlugin(target, effectiveVersion())
	if err != nil {
		return e.failErr(err)
	}
	if !changed {
		fprintf(e.stdout, "%s already up to date\n", target)
		return ExitOK
	}
	fprintf(e.stdout, "installed the ClaudePass plugin at %s\n", target)
	fprintln(e.stdout, "registered hook: UserPromptSubmit -> cpass intercept")
	fprintln(e.stdout, "registered hook: PreToolUse (Bash) -> cpass policy --hook")
	fprintln(e.stdout, "registered skill: claudepass")
	fprintln(e.stdout, "it loads as claudepass@skills-dir on the next `claude` session (or run /reload-plugins in one already open)")
	return ExitOK
}
