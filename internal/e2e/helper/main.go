// Command helper is the child process e2e tests run under cpass. It writes
// its environment to the file named by HELPER_OUT (never to stdout, so a
// test can prove a value reached the process without it reaching output),
// optionally prints HELPER_ECHO, and exits with HELPER_EXIT.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	if out := os.Getenv("HELPER_OUT"); out != "" {
		_ = os.WriteFile(out, []byte(strings.Join(os.Environ(), "\n")+"\n"), 0o600)
	}
	if s := os.Getenv("HELPER_ECHO"); s != "" {
		fmt.Println(os.ExpandEnv(s))
	}
	if s := os.Getenv("HELPER_STDERR"); s != "" {
		fmt.Fprintln(os.Stderr, os.ExpandEnv(s))
	}
	code := 0
	if s := os.Getenv("HELPER_EXIT"); s != "" {
		code, _ = strconv.Atoi(s)
	}
	os.Exit(code)
}
