// Package cli implements the cpass command line.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Version is injected at build time.
var Version = "dev"

// Exit codes.
const (
	ExitOK      = 0
	ExitError   = 1
	ExitUsage   = 2
	ExitRefused = 3
)

type env struct {
	args   []string
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

type command struct {
	name    string
	summary string
	run     func(e *env) int
}

var commands = map[string]command{}

func register(c command) { commands[c.name] = c }

// Main runs cpass with the given arguments and returns the exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := &env{args: args, stdin: stdin, stdout: stdout, stderr: stderr}
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage(stdout)
		return ExitOK
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Fprintln(stdout, "cpass", Version)
		return ExitOK
	}
	c, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "cpass: unknown command %q\n", args[0])
		usage(stderr)
		return ExitUsage
	}
	e.args = args[1:]
	return c.run(e)
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "cpass — secrets for AI coding agents. Agents see Handles, never values.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage: cpass <command> [flags]")
	fmt.Fprintln(w)
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "  %-10s %s\n", n, commands[n].summary)
	}
	fmt.Fprintf(w, "  %-10s %s\n", "version", "print the version")
}

// fail prints a one-line error and returns the exit code.
func (e *env) fail(code int, format string, a ...any) int {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(e.stderr, "cpass: "+strings.TrimSuffix(msg, "\n"))
	return code
}

func (e *env) failErr(err error) int {
	var code = ExitError
	if errors.Is(err, errLocked) {
		code = ExitError
	}
	return e.fail(code, "%v", err)
}

var errLocked = errors.New("locked")

func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	return isTTY(f)
}
