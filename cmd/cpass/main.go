// Command cpass is the ClaudePass CLI: a secret manager for AI coding agents.
package main

import (
	"os"

	"github.com/Elixion-ai/claudepass/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
