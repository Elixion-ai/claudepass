// Package pluginfiles embeds the Claude Code plugin's static files —
// .claude-plugin/plugin.json, hooks/hooks.json, skills/claudepass/SKILL.md
// — into the cpass binary, so `cpass integrate claude` can materialise them
// on disk regardless of how cpass itself was installed (a source checkout
// is not assumed to exist next to the binary).
package pluginfiles

import "embed"

// FS holds the plugin directory rooted at plugins/claude-code: read it back
// with FS.ReadFile("hooks/hooks.json") or walk it with fs.WalkDir(FS, ".",
// ...). all: is required on .claude-plugin because Go's embed otherwise
// skips directories whose name starts with a dot.
//
//go:embed all:.claude-plugin hooks skills
var FS embed.FS
