package e2e

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// runConcurrent runs cpass in its own real process (not a goroutine sharing
// this one) — CLA-55 and CLA-93 both need proof against actual concurrent
// `cpass` processes, not just concurrent Go code sharing one address space.
// It never calls ve.t from inside the goroutine that calls it (see
// TestConcurrentAddsAllSurvive): testing.T's FailNow-family methods must
// only be called from the test's own goroutine, so this returns its error
// instead of failing the test itself.
func (ve *vaultEnv) runConcurrent(stdin []byte, args ...string) (result, error) {
	cmd := exec.Command(cpassBin, args...)
	cmd.Env = append(baseEnv(), "CPASS_HOME="+ve.home, "CPASS_KEY="+ve.key)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
		cmd.Env = append(cmd.Env, "CPASS_TEST_STDIN=1")
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		return result{}, err
	}
	return result{code: code, stdout: out.String(), stderr: errb.String()}, nil
}

// TestConcurrentAddsAllSurvive is CLA-55's end-to-end regression test: N
// real, concurrently running `cpass add` processes against one Vault must
// all succeed, and every Handle they stored must survive — before the fix,
// this reliably lost several of the N (silently: every process still
// exited 0) and some processes hit an explicit rename ENOENT racing the
// old fixed "vault.cpv.tmp".
func TestConcurrentAddsAllSurvive(t *testing.T) {
	ve := newVault(t)
	const n = 20
	var wg sync.WaitGroup
	results := make([]result, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			handle := fmt.Sprintf("concurrent/h%02d", i)
			value := fmt.Sprintf("value-number-%02d-long-enough-ok", i)
			results[i], errs[i] = ve.runConcurrent([]byte(value+"\n"), "add", handle)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("add %d: process error: %v", i, err)
		}
		if results[i].code != 0 {
			t.Fatalf("add %d failed: %s", i, results[i])
		}
		if strings.Contains(results[i].stderr, "no such file or directory") {
			t.Fatalf("add %d raced another writer's rename: %s", i, results[i])
		}
	}

	r := ve.run(nil, "ls")
	if r.code != 0 {
		t.Fatalf("ls: %s", r)
	}
	got := strings.Fields(r.stdout)
	if len(got) != n {
		t.Fatalf("vault has %d handles, want %d — a concurrent add silently lost one:\n%s", len(got), n, r.stdout)
	}
	for i := 0; i < n; i++ {
		want := fmt.Sprintf("concurrent/h%02d", i)
		found := false
		for _, h := range got {
			if h == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing %s from ls output: %v", want, got)
		}
	}
}
