// Package e2e drives the built cpass binary as a subprocess: the exact
// boundary an Agent uses. Tests here assert on stdout, stderr, exit codes,
// and what a child process observes, never on internals.
package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

var (
	cpassBin  string
	helperBin string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cpass-e2e-bin")
	if err != nil {
		panic(err)
	}
	cpassBin = filepath.Join(dir, "cpass")
	helperBin = filepath.Join(dir, "helper")
	for _, b := range [][2]string{{cpassBin, "claudepass/cmd/cpass"}, {helperBin, "claudepass/internal/e2e/helper"}} {
		cmd := exec.Command("go", "build", "-tags", "e2e", "-o", b[0], b[1])
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			panic("build " + b[1] + ": " + err.Error())
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// vaultEnv is a fresh CPASS_HOME with a key, optionally initialised.
type vaultEnv struct {
	t    *testing.T
	home string
	key  string
}

func newVault(t *testing.T) *vaultEnv {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	ve := &vaultEnv{t: t, home: t.TempDir(), key: base64.StdEncoding.EncodeToString(k)}
	r := ve.run(nil, "init")
	if r.code != 0 {
		t.Fatalf("init failed: %s", r.stderr)
	}
	return ve
}

type result struct {
	code           int
	stdout, stderr string
}

func (r result) String() string {
	return "exit " + itoa(r.code) + "\nstdout: " + r.stdout + "\nstderr: " + r.stderr
}

func itoa(i int) string { return strconv.Itoa(i) }

// run executes cpass with the Vault's environment plus extra vars.
func (ve *vaultEnv) run(stdin []byte, args ...string) result {
	return ve.runEnv(nil, stdin, args...)
}

func (ve *vaultEnv) runEnv(extra []string, stdin []byte, args ...string) result {
	return ve.runBin(cpassBin, extra, stdin, args...)
}

// buildRelease builds cpass without the e2e tag, once per test binary.
func buildRelease(t *testing.T) string {
	t.Helper()
	releaseOnce.Do(func() {
		releaseBin = filepath.Join(filepath.Dir(cpassBin), "cpass-release")
		cmd := exec.Command("go", "build", "-o", releaseBin, "claudepass/cmd/cpass")
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			releaseErr = err
		}
	})
	if releaseErr != nil {
		t.Fatal(releaseErr)
	}
	return releaseBin
}

var (
	releaseOnce sync.Once
	releaseBin  string
	releaseErr  error
)

func (ve *vaultEnv) runBin(bin string, extra []string, stdin []byte, args ...string) result {
	ve.t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(baseEnv(), "CPASS_HOME="+ve.home, "CPASS_KEY="+ve.key)
	cmd.Env = append(cmd.Env, extra...)
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
		ve.t.Fatalf("run cpass %v: %v", args, err)
	}
	return result{code: code, stdout: out.String(), stderr: errb.String()}
}

// add stores a value via the test stdin path.
func (ve *vaultEnv) add(handle, value string, flags ...string) result {
	args := append([]string{"add"}, flags...)
	args = append(args, handle)
	return ve.run([]byte(value+"\n"), args...)
}

func baseEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "CPASS_") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

func (ve *vaultEnv) vaultPath() string { return filepath.Join(ve.home, "vault.cpv") }

// shortTempDirCounter makes each shortTempDir unique without embedding the
// (potentially long) test name in the path.
var shortTempDirCounter int32

// shortTempDir returns a short-path temp directory, unlike t.TempDir():
// under macOS's default TMPDIR, a t.TempDir() path can be long enough that
// appending "/cpass.sock" exceeds sizeof(sockaddr_un.sun_path) (104 bytes on
// darwin). Broker-socket tests use this for CPASS_HOME/XDG_RUNTIME_DIR
// instead.
func shortTempDir(t *testing.T) string {
	t.Helper()
	n := atomic.AddInt32(&shortTempDirCounter, 1)
	d := filepath.Join("/tmp", fmt.Sprintf("cpass-e2e-%d-%d", os.Getpid(), n))
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}
