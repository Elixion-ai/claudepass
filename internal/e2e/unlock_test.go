package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// lockedVault returns a fresh, un-initialised CPASS_HOME with no CPASS_KEY:
// unlike newVault(t), it does not run `cpass init` itself, so a test can
// drive init under whichever unlock source it wants to exercise.
func lockedVault(t *testing.T) *vaultEnv {
	t.Helper()
	return &vaultEnv{t: t, home: t.TempDir()}
}

// socketEnv is the extra environment that forces the Broker-process unlock
// source, with a short XDG_RUNTIME_DIR so the socket path stays under the
// unix sockaddr_un limit regardless of how long t.TempDir() is on this host.
func socketEnv(t *testing.T) []string {
	t.Helper()
	return []string{"CPASS_UNLOCK=socket", "XDG_RUNTIME_DIR=" + shortTempDir(t)}
}

// waitGone polls for path to stop existing, up to 5s. The Broker removes
// its socket file as one of its last acts before exiting (on LOCK or idle
// timeout), asynchronously to whatever told it to stop, so callers must
// poll rather than stat immediately after.
func waitGone(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s still present 5s after it should have been removed", path)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func socketPathFor(env []string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "XDG_RUNTIME_DIR="); ok {
			return filepath.Join(v, "cpass.sock")
		}
	}
	return ""
}

// TestSocketUnlockLockCycle is the Linux/CI acceptance path: init picks a
// key from a passphrase (never CPASS_KEY), run before unlock fails locked,
// unlock starts the Broker and run works, lock drops it and run fails
// locked again. Asserts the socket is mode 0600 while the Broker holds it.
func TestSocketUnlockLockCycle(t *testing.T) {
	ve := lockedVault(t)
	env := socketEnv(t)
	sock := socketPathFor(env)
	passphrase := "correct horse battery staple\n"

	r := ve.runEnv(env, []byte(passphrase), "init")
	if r.code != 0 {
		t.Fatalf("init: %s", r)
	}
	if !strings.Contains(r.stderr, "cpass unlock") {
		t.Fatalf("init should point at unlock: %s", r)
	}

	r = ve.runEnv(env, nil, "ls")
	if r.code == 0 || !strings.Contains(r.stderr, "locked") {
		t.Fatalf("want locked before unlock: %s", r)
	}

	r = ve.runEnv(env, []byte(passphrase), "unlock")
	if r.code != 0 {
		t.Fatalf("unlock: %s", r)
	}

	st, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if st.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a socket: %v", sock, st.Mode())
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v, want 0600", st.Mode().Perm())
	}

	r = ve.runEnv(env, []byte("value-number-one\n"), "add", "a/one")
	if r.code != 0 {
		t.Fatalf("add after unlock: %s", r)
	}
	r = ve.runEnv(env, nil, "ls")
	if r.code != 0 || !strings.Contains(r.stdout, "a/one") {
		t.Fatalf("ls after unlock: %s", r)
	}

	r = ve.runEnv(env, nil, "lock")
	if r.code != 0 {
		t.Fatalf("lock: %s", r)
	}
	// The Broker removes its socket file as it exits, just after acking
	// LOCK: poll briefly rather than racing that exit.
	waitGone(t, sock)

	r = ve.runEnv(env, nil, "ls")
	if r.code == 0 || !strings.Contains(r.stderr, "locked") {
		t.Fatalf("want locked after lock: %s", r)
	}
}

// TestSocketUnlockIdleTimeout drives --timeout 1s and confirms the Broker
// drops the key (and its socket) on its own once idle past that.
func TestSocketUnlockIdleTimeout(t *testing.T) {
	ve := lockedVault(t)
	env := socketEnv(t)
	sock := socketPathFor(env)
	passphrase := "another-strong-passphrase\n"

	if r := ve.runEnv(env, []byte(passphrase), "init"); r.code != 0 {
		t.Fatalf("init: %s", r)
	}
	if r := ve.runEnv(env, []byte(passphrase), "unlock", "--timeout", "1s"); r.code != 0 {
		t.Fatalf("unlock: %s", r)
	}
	if r := ve.runEnv(env, nil, "ls"); r.code != 0 {
		t.Fatalf("ls right after unlock: %s", r)
	}

	waitGone(t, sock)

	r := ve.runEnv(env, nil, "ls")
	if r.code == 0 || !strings.Contains(r.stderr, "locked") {
		t.Fatalf("want locked after idle timeout: %s", r)
	}
}

// TestSocketUnlockWrongPassphraseRefused checks that a wrong passphrase at
// unlock is refused (the Broker never starts) rather than silently wrapping
// the Vault with a key that cannot open it.
func TestSocketUnlockWrongPassphraseRefused(t *testing.T) {
	ve := lockedVault(t)
	env := socketEnv(t)
	sock := socketPathFor(env)

	if r := ve.runEnv(env, []byte("right-passphrase\n"), "init"); r.code != 0 {
		t.Fatalf("init: %s", r)
	}
	r := ve.runEnv(env, []byte("wrong-passphrase\n"), "unlock")
	if r.code == 0 {
		t.Fatalf("wrong passphrase should be refused: %s", r)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("Broker should not be listening after a refused unlock")
	}
	r = ve.runEnv(env, nil, "ls")
	if r.code == 0 || !strings.Contains(r.stderr, "locked") {
		t.Fatalf("want locked: %s", r)
	}
}

// TestSocketUnlockEmptyPassphraseRefused mirrors add's empty-value refusal:
// an empty master passphrase would make the derived key trivial to guess.
func TestSocketUnlockEmptyPassphraseRefused(t *testing.T) {
	ve := lockedVault(t)
	env := socketEnv(t)
	r := ve.runEnv(env, []byte("\n"), "init")
	if r.code == 0 || !strings.Contains(r.stderr, "empty") {
		t.Fatalf("want empty-passphrase refusal: %s", r)
	}
}

// TestUnlockLockRefusedInKeychainMode checks the macOS-default guard: unlock
// and lock (Broker-process commands) refuse when the Keychain is this
// Vault's unlock source, rather than pretending to start or stop something.
func TestUnlockLockRefusedInKeychainMode(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("this guard only fires on macOS, where the Keychain is the default source")
	}
	ve := newVault(t)
	if r := ve.run(nil, "unlock"); r.code == 0 || !strings.Contains(r.stderr, "Keychain") {
		t.Fatalf("want unlock refused in Keychain mode: %s", r)
	}
	if r := ve.run(nil, "lock"); r.code == 0 || !strings.Contains(r.stderr, "Keychain") {
		t.Fatalf("want lock refused in Keychain mode: %s", r)
	}
}

// TestKeychainUnlockRoundTrip is the macOS acceptance path: init with no
// CPASS_KEY stores the key in the Keychain, and add/ls/run all work
// afterwards with no CPASS_KEY set, reading it back transparently. Uses a
// unique service name so it never touches a real "cpass" Keychain item, and
// deletes its item when done.
func TestKeychainUnlockRoundTrip(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Keychain unlock is macOS-only")
	}
	service := fmt.Sprintf("cpass-e2e-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	ve := lockedVault(t)
	env := []string{"CPASS_KEYCHAIN_SERVICE=" + service}
	t.Cleanup(func() {
		exec.Command("security", "delete-generic-password", "-a", ve.vaultPath(), "-s", service).Run()
	})

	r := ve.runEnv(env, nil, "init")
	if r.code != 0 {
		t.Fatalf("init: %s", r)
	}
	if !strings.Contains(r.stderr, "Keychain") {
		t.Fatalf("init should mention the Keychain: %s", r)
	}

	out, err := exec.Command("security", "find-generic-password", "-a", ve.vaultPath(), "-s", service, "-w").Output()
	if err != nil {
		t.Fatalf("Keychain item missing after init: %v", err)
	}
	if strings.TrimSpace(string(out)) == "" {
		t.Fatalf("Keychain item has no password")
	}

	r = ve.runEnv(env, []byte("keychain-secret-val\n"), "add", "k/one")
	if r.code != 0 {
		t.Fatalf("add with no CPASS_KEY: %s", r)
	}
	r = ve.runEnv(env, nil, "ls")
	if r.code != 0 || !strings.Contains(r.stdout, "k/one") {
		t.Fatalf("ls with no CPASS_KEY: %s", r)
	}

	envOut, r := childEnv(t, ve, env, "--with", "k/one")
	if r.code != 0 {
		t.Fatalf("run with no CPASS_KEY: %s", r)
	}
	if envOut["K_ONE"] != "keychain-secret-val" {
		t.Fatalf("child did not receive the Keychain-unlocked value: %v", envOut)
	}
}
