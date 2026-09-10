// Command helper is the child process e2e tests run under cpass. It writes
// its environment to the file named by HELPER_OUT (never to stdout, so a
// test can prove a value reached the process without it reaching output),
// optionally prints HELPER_ECHO, and exits with HELPER_EXIT.
package main

import (
	"bufio"
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
		// Best-effort like every other write to this process's own stdout
		// below: a failure here just shows up as truncated output to the
		// e2e test watching for it, which is exactly the right failure mode.
		v := os.ExpandEnv(s)
		_, _ = os.Stdout.WriteString(v[:len(v)/2])
		time.Sleep(60 * time.Millisecond)
		_, _ = os.Stdout.WriteString(v[len(v)/2:] + "\n")
	}
	if n, _ := strconv.Atoi(os.Getenv("HELPER_BLAST")); n > 0 {
		line := []byte(strings.Repeat("x", 63) + "\n")
		w := bufio.NewWriterSize(os.Stdout, 64*1024)
		for written := 0; written < n; written += len(line) {
			_, _ = w.Write(line) // best-effort, see above
		}
		_ = w.Flush() // best-effort, see above
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
