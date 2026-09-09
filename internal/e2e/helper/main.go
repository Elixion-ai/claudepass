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
	"syscall"
	"time"
)

func main() {
	if out := os.Getenv("HELPER_OUT"); out != "" {
		_ = os.WriteFile(out, []byte(strings.Join(os.Environ(), "\n")+"\n"), 0o600)
	}
	if s := os.Getenv("HELPER_SPLIT"); s != "" {
		// Write the expanded value in two halves with a pause between them.
		v := os.ExpandEnv(s)
		os.Stdout.WriteString(v[:len(v)/2])
		time.Sleep(60 * time.Millisecond)
		os.Stdout.WriteString(v[len(v)/2:] + "\n")
	}
	if n, _ := strconv.Atoi(os.Getenv("HELPER_BLAST")); n > 0 {
		line := []byte(strings.Repeat("x", 63) + "\n")
		for written := 0; written < n; written += len(line) {
			os.Stdout.Write(line)
		}
	}
	if s := os.Getenv("HELPER_ECHO"); s != "" {
		fmt.Println(os.ExpandEnv(s))
	}
	if s := os.Getenv("HELPER_STDERR"); s != "" {
		fmt.Fprintln(os.Stderr, os.ExpandEnv(s))
	}
	if s := os.Getenv("HELPER_KILL"); s != "" {
		n, _ := strconv.Atoi(s)
		_ = syscall.Kill(os.Getpid(), syscall.Signal(n))
	}
	code := 0
	if s := os.Getenv("HELPER_EXIT"); s != "" {
		code, _ = strconv.Atoi(s)
	}
	os.Exit(code)
}
