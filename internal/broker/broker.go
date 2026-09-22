// Package broker resolves Handles into Secret values at the moment a command
// runs. This slice provides the key source and Vault location; the unlock
// model (Keychain, Broker process) and Handle resolution build on it.
package broker

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Elixion-ai/claudepass/internal/vault"
)

// EnvHome overrides the ClaudePass home directory.
const EnvHome = "CPASS_HOME"

// EnvKey supplies the unlock key directly (base64, 32 bytes). Used by CI and tests.
const EnvKey = "CPASS_KEY"

// EnvUnlock, set to "socket", forces the Broker-process unlock source even
// on macOS (used by tests to exercise that path without a real Keychain).
const EnvUnlock = "CPASS_UNLOCK"

// EnvKeychainService overrides the Keychain service name. Production code
// always uses "cpass"; tests set this to a throwaway name so they never
// touch a real login Keychain item.
const EnvKeychainService = "CPASS_KEYCHAIN_SERVICE"

// ErrLocked is returned when no unlock key is available.
var ErrLocked = errors.New("vault is locked, run cpass unlock")

// UseKeychain reports whether this invocation's unlock source is the macOS
// Keychain (darwin, unless CPASS_UNLOCK=socket forces the Broker process).
func UseKeychain() bool {
	return runtime.GOOS == "darwin" && os.Getenv(EnvUnlock) != "socket"
}

// KeychainService is the Keychain service name Keychain items are stored
// and looked up under.
func KeychainService() string {
	if s := os.Getenv(EnvKeychainService); s != "" {
		return s
	}
	return "cpass"
}

// keychainAccount is the Keychain account name: the Vault path, so distinct
// Vaults never collide, falling back to "default" if it cannot be determined.
func keychainAccount() string {
	if p, err := VaultPath(); err == nil && p != "" {
		return p
	}
	return "default"
}

// SetKeychainKey stores key in the Keychain under this Vault's account,
// creating or replacing the item. macOS only.
func SetKeychainKey(key []byte) error {
	return keychainSet(KeychainService(), keychainAccount(), key)
}

// Home returns the ClaudePass home directory, creating nothing.
func Home() (string, error) {
	if h := os.Getenv(EnvHome); h != "" {
		return h, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine config dir: %w", err)
	}
	return filepath.Join(dir, "claudepass"), nil
}

// VaultPath returns the path of the Vault file.
func VaultPath() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "vault.cpv"), nil
}

// UnlockKey returns the unlock key: CPASS_KEY first (CI), then, on macOS,
// the Keychain item for this Vault, then the Broker process on its socket.
// This is the single entry point every unlock source funnels through.
func UnlockKey() ([]byte, error) {
	if s := os.Getenv(EnvKey); s != "" {
		k, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(k) != vault.KeySize {
			return nil, fmt.Errorf("%s must be base64 of %d bytes", EnvKey, vault.KeySize)
		}
		return k, nil
	}
	if UseKeychain() {
		key, err := keychainGet(KeychainService(), keychainAccount())
		if err != nil {
			return nil, ErrLocked
		}
		return key, nil
	}
	key, err := RequestKey()
	if err != nil {
		return nil, ErrLocked
	}
	return key, nil
}

// OpenVault opens the Vault with whatever unlock key is available.
func OpenVault() (*vault.Vault, error) {
	p, err := VaultPath()
	if err != nil {
		return nil, err
	}
	key, err := UnlockKey()
	if err != nil {
		return nil, err
	}
	return vault.Open(p, key)
}

// UpdateVault is the write counterpart to OpenVault: it resolves the same
// path and unlock key, then runs fn against a freshly opened Vault under
// vault.Update's exclusive lock, saving the result if fn returns nil. Every
// `cpass` command that changes the Vault calls this (or vault.Update
// directly, when it already holds a *vault.Vault from an earlier
// broker.OpenVault and needs the lock around a slower step in between —
// see cmdCapture) rather than its own Open ... Save, so two `cpass`
// processes can never race each other's write (CLA-55).
func UpdateVault(fn func(v *vault.Vault) error) error {
	p, err := VaultPath()
	if err != nil {
		return err
	}
	key, err := UnlockKey()
	if err != nil {
		return err
	}
	return vault.Update(p, key, fn)
}

// EnvCI forces CI mode: Handles resolve from the environment, no Vault.
const EnvCI = "CPASS_CI"

// CIMode reports whether Handles resolve from the environment instead of a
// Vault: CPASS_CI=1, or CI=true with no Vault file present.
func CIMode() bool {
	if os.Getenv(EnvCI) == "1" {
		return true
	}
	if os.Getenv(EnvCI) == "0" {
		return false
	}
	if os.Getenv("CI") == "true" {
		if p, err := VaultPath(); err == nil && !vault.Exists(p) {
			return true
		}
	}
	return false
}

// Ref names a Handle to inject, with an optional Binding-name override.
type Ref struct {
	Handle   string
	Override string // environment variable name; empty keeps the Handle's default
	// Declared is the Manifest's Binding for this Handle, if any. It wins
	// over the Vault's default Binding and is the only source in CI mode.
	Declared vault.Binding
	// FromGlobal marks a Ref that reached this command through the Global
	// Manifest rather than the project's own. Such a Ref is ambient: no
	// committed file in this project asked for it, so an unresolvable one is
	// skipped rather than fatal, and a Binding-name collision involving one
	// is refused rather than silently resolved.
	FromGlobal bool
}

// ParseRef parses "handle" or "handle:BINDING".
func ParseRef(s string) (Ref, error) {
	h, name, _ := strings.Cut(s, ":")
	if err := vault.ValidateHandle(h); err != nil {
		return Ref{}, err
	}
	if name != "" && !envNameRe.MatchString(name) {
		return Ref{}, fmt.Errorf("invalid binding name %q for %s", name, h)
	}
	return Ref{Handle: h, Override: name}, nil
}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func resolveFromEnv(refs []Ref) ([]Resolved, []string, error) {
	out := make([]Resolved, 0, len(refs))
	var skipped []string
	bound := map[string]Ref{}
	for _, r := range refs {
		name := r.Override
		if name == "" {
			name = r.Declared.Name
		}
		if name == "" {
			name = vault.DefaultBindingName(r.Handle)
		}
		val, ok := os.LookupEnv(name)
		if !ok {
			if r.FromGlobal {
				skipped = append(skipped, skipNotice(r.Handle, name+" is not set in the environment"))
				continue
			}
			return nil, nil, fmt.Errorf("CI mode: %s expects %s in the environment", r.Handle, name)
		}
		// The Vault's own vault.Add enforces MinSecretLength so that every
		// value it holds clears redact.minPatternLen and gets real Redaction
		// coverage; CI mode reads straight from the environment and bypasses
		// vault.Add entirely; without this check a short CI secret (a test
		// fixture token, a four-character flag someone reused as a "secret")
		// would resolve with zero redact Patterns and print raw the moment
		// the wrapped command echoes it. Enforcing the same floor here closes
		// that gap. The message names the Handle and the minimum, never the
		// value — the value is exactly what must not appear in a diagnostic
		// this short and this likely to be pasted somewhere.
		if len(val) < vault.MinSecretLength {
			if r.FromGlobal {
				skipped = append(skipped, skipNotice(r.Handle, fmt.Sprintf("%s in the environment is shorter than the minimum %d characters", name, vault.MinSecretLength)))
				continue
			}
			return nil, nil, fmt.Errorf("CI mode: %s (%s) is shorter than the minimum %d characters", r.Handle, name, vault.MinSecretLength)
		}
		if err := checkCollision(bound, name, r); err != nil {
			return nil, nil, err
		}
		kind := r.Declared.Kind
		if kind == "" {
			kind = vault.BindEnv
		}
		out = append(out, Resolved{Handle: r.Handle, Value: val, Binding: vault.Binding{Kind: kind, Name: name}, FromGlobal: r.FromGlobal})
	}
	return out, skipped, nil
}

// skipNotice renders docs/CLI-STYLE.md's stale-Global-Handle line. A Global
// Handle that cannot be resolved is a drifted machine-wide declaration, not
// a broken project: the run continues without it and says so, rather than
// taking down every project that ever ran `cpass manifest init`.
func skipNotice(handle, why string) string {
	return fmt.Sprintf("cpass: %s is declared in your Global Manifest but %s; skipping it — run `cpass local %s` to stop declaring it", handle, why, handle)
}

// checkCollision refuses two Handles binding the same environment variable
// when either of them came from the Global Manifest, recording name for the
// Refs that follow.
//
// Only a Global-involved collision is refused. Two Handles a project itself
// declared into the same variable have always resolved last-write-wins, and
// that stays exactly as it was: a project that never opted into the Global
// Manifest must not start failing on a version bump. What is new is the
// ambient case — a Global Handle the project's author never enumerated,
// silently overwriting (or being overwritten by) one they did — which has no
// right answer and so is named instead of guessed.
func checkCollision(bound map[string]Ref, name string, r Ref) error {
	prev, ok := bound[name]
	if ok && (prev.FromGlobal || r.FromGlobal) {
		return fmt.Errorf("handle collision: %s and %s both bind %s", prev.Handle, r.Handle, name)
	}
	if !ok {
		bound[name] = r
	}
	return nil
}

// Resolved is a Secret ready to inject.
type Resolved struct {
	Handle  string
	Value   string
	Binding vault.Binding
	Exposed bool
	// FromGlobal carries Ref.FromGlobal through to the injection step.
	FromGlobal bool
	// ExposedAt is when the Secret most recently became Exposed. Zero when
	// Exposed is false or the Vault carries no exposure history for it (CI
	// mode never sets this: there is no Vault to read it from).
	ExposedAt time.Time
}

// Resolve turns Refs into Secrets. It fails on the first missing Handle a
// project asked for, naming it and nothing else; a missing Handle that came
// from the Global Manifest is returned in skipped instead, for the caller to
// report, and the rest of the run proceeds. In CI mode each Handle resolves
// from the environment variable named by its Binding; refs must then carry
// the Binding (Override, or Kind/Name via Ref.Declared).
//
// Resolve always opens the Vault fresh, through OpenVault() (and so
// UnlockKey()): the right default for every caller that makes at most a
// couple of Broker calls in its whole process lifetime, which is every
// caller except cpass mcp — see KeyCache.Resolve for the one that amortises
// this across many calls in one long-lived process (CLA-77).
func Resolve(refs []Ref) ([]Resolved, []string, error) {
	if len(refs) == 0 {
		return nil, nil, nil
	}
	if CIMode() {
		return resolveFromEnv(refs)
	}
	v, err := OpenVault()
	if err != nil {
		return nil, nil, err
	}
	defer v.Close()
	return resolveFromVault(v, refs)
}

// resolveFromVault is Resolve's vault-backed branch, factored out so
// KeyCache.Resolve (CLA-77) can reuse it against a Vault opened with a
// cached key instead of calling OpenVault() itself.
func resolveFromVault(v *vault.Vault, refs []Ref) ([]Resolved, []string, error) {
	out := make([]Resolved, 0, len(refs))
	var skipped []string
	bound := map[string]Ref{}
	for _, r := range refs {
		e, err := v.Get(r.Handle)
		if err != nil {
			if r.FromGlobal {
				skipped = append(skipped, skipNotice(r.Handle, "it is missing from the Vault"))
				continue
			}
			return nil, nil, fmt.Errorf("no such handle: %s", r.Handle)
		}
		b := e.Binding
		if r.Declared.Name != "" {
			b.Name = r.Declared.Name
		}
		if r.Declared.Kind != "" {
			b.Kind = r.Declared.Kind
		}
		if r.Override != "" {
			b.Name = r.Override
		}
		if err := checkCollision(bound, b.Name, r); err != nil {
			return nil, nil, err
		}
		res := Resolved{Handle: e.Handle, Value: e.Value, Binding: b, Exposed: e.Exposed, FromGlobal: r.FromGlobal}
		if e.Exposed && len(e.Exposures) > 0 {
			res.ExposedAt = e.Exposures[len(e.Exposures)-1].At
		}
		out = append(out, res)
	}
	return out, skipped, nil
}
