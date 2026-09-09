package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// testStdin and testTTY are set only by the e2e build tag (see testhooks_on.go).
var (
	testStdin bool
	testTTY   bool
)

func isTTY(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// humanPresent reports whether a human is at the other end of stdin.
func (e *env) humanPresent() bool {
	if testTTY {
		return true
	}
	return isTerminal(e.stdin)
}

// readSecret reads a Secret value from a human. On a terminal it prompts with
// echo off. Without a terminal it refuses, unless CPASS_TEST_STDIN=1, so an
// Agent can never feed a value it already knows (use cpass capture instead).
func (e *env) readSecret(prompt string) (string, error) {
	if f, ok := e.stdin.(*os.File); ok && isTTY(f) {
		fmt.Fprint(e.stderr, prompt)
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(e.stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	if testStdin {
		line, err := bufio.NewReader(e.stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	return "", fmt.Errorf("add needs a terminal to type the value into; from an Agent, use `cpass capture <handle> -- <command>` so the value never enters its context")
}
