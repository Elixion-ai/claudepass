//go:build e2e

package cli

import "os"

// Test hooks exist only in binaries built with -tags e2e. A release binary
// has no way to bypass the terminal gates.
func init() {
	testStdin = os.Getenv("CPASS_TEST_STDIN") == "1"
	testTTY = os.Getenv("CPASS_TEST_TTY") == "1"
}
