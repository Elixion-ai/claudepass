// Package vault implements the encrypted local store where Secrets live.
//
// On disk a Vault is a JSON envelope: a random data key wrapped by the unlock
// key, and the entry list encrypted under the data key. Both layers use
// XChaCha20-Poly1305, so a wrong key fails at the unwrap and a modified body
// fails at the open; the two are reported as distinct errors.
//
// Open, mutate the in-memory Entry map, Save is not by itself safe against
// another process doing the same thing at once — see Update, the one
// correct way to do that cycle (CLA-55).
package vault

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Elixion-ai/claudepass/internal/atomicfile"
	"github.com/Elixion-ai/claudepass/internal/lockfile"
)

// FormatVersion is the on-disk envelope version.
const FormatVersion = 1

// MinSecretLength is the shortest value the Vault accepts. Shorter values
// would make Redaction scrub trivially short strings from all output.
const MinSecretLength = 8

// ErrNotFound is returned when a Handle does not exist.
var ErrNotFound = errors.New("vault: no such handle")

// ErrExists is returned when adding a Handle that already exists.
var ErrExists = errors.New("vault: handle already exists")

// ErrNoVault is returned when the Vault file does not exist.
var ErrNoVault = errors.New("vault: not initialised (run cpass init)")

// BindingKind says how a Secret lands in a command's process.
type BindingKind string

const (
	// BindEnv places the value in an environment variable.
	BindEnv BindingKind = "env"
	// BindFile writes the value to a temporary file and places its path in an
	// environment variable.
	BindFile BindingKind = "file"
)

// Binding is a Handle's default Binding.
type Binding struct {
	Kind BindingKind `json:"kind"`
	Name string      `json:"name"`
}

// Exposure records that a Secret's value entered an Agent's Context.
type Exposure struct {
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
}

// Entry is one Secret and its metadata.
type Entry struct {
	Handle    string     `json:"handle"`
	Value     string     `json:"value"`
	Binding   Binding    `json:"binding"`
	Exposed   bool       `json:"exposed"`
	Exposures []Exposure `json:"exposures,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type body struct {
	Entries []Entry `json:"entries"`
}

type envelope struct {
	Version    int    `json:"version"`
	KeyNonce   string `json:"key_nonce"`
	WrappedKey string `json:"wrapped_key"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// Vault is an unlocked, in-memory view of the store. Save writes it back.
type Vault struct {
	path    string
	key     []byte // unlock key
	dataKey []byte
	entries map[string]*Entry
}

var handleRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$`)

// ValidateHandle reports whether h is a well-formed Handle.
func ValidateHandle(h string) error {
	if !handleRe.MatchString(h) {
		return fmt.Errorf("vault: invalid handle %q (use lowercase segments like stripe/live)", h)
	}
	return nil
}

// DefaultBindingName derives an environment variable name from a Handle:
// stripe/live -> STRIPE_LIVE.
func DefaultBindingName(handle string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(handle) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	name := b.String()
	if name != "" && name[0] >= '0' && name[0] <= '9' {
		name = "_" + name
	}
	return name
}

// Exists reports whether a Vault file is present at path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Create initialises a new empty Vault at path under the given unlock key.
//
// Two concurrent `cpass init` runs against a fresh path both take Update's
// own write lock (path+lockSuffix) for the whole check-then-create, and
// re-check Exists once they hold it: an unlocked Exists-then-Save let both
// runs pass the first check, create independently, and have the second
// Save silently win the data key over the first — leaving a stray Keychain
// item, on macOS, that no longer matches the Vault it started with (CLA-98
// item 1, a CLA-55 follow-up).
func Create(path string, key []byte) (*Vault, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("vault: unlock key must be %d bytes", KeySize)
	}
	if Exists(path) {
		return nil, fmt.Errorf("vault: %s already exists", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	lock, err := lockfile.Acquire(path+lockSuffix, lockfile.DefaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("vault: locking for create: %w", err)
	}
	defer func() { _ = lock.Release() }()
	if Exists(path) {
		return nil, fmt.Errorf("vault: %s already exists", path)
	}
	dataKey, err := randomBytes(KeySize)
	if err != nil {
		return nil, err
	}
	// A Vault's own copy of key, never the caller's slice: Close zeroes
	// v.key in place, and a caller (cpass unlock hands the same key on to
	// StartBroker right after opening the Vault with it, to name one) must
	// keep using its own slice safely after that.
	v := &Vault{path: path, key: append([]byte(nil), key...), dataKey: dataKey, entries: map[string]*Entry{}}
	if err := v.Save(); err != nil {
		return nil, err
	}
	return v, nil
}

// Open reads and decrypts the Vault at path with the unlock key.
func Open(path string, key []byte) (*Vault, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("vault: unlock key must be %d bytes", KeySize)
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoVault
	}
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, ErrTampered
	}
	if env.Version != FormatVersion {
		return nil, fmt.Errorf("vault: unsupported format version %d", env.Version)
	}
	keyNonce, err1 := b64d(env.KeyNonce)
	wrapped, err2 := b64d(env.WrappedKey)
	nonce, err3 := b64d(env.Nonce)
	ct, err4 := b64d(env.Ciphertext)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return nil, ErrTampered
	}
	dataKey, err := open(key, keyNonce, wrapped, []byte("cpass-data-key"))
	if err != nil {
		return nil, ErrWrongKey
	}
	plain, err := open(dataKey, nonce, ct, aadFor(env))
	if err != nil {
		return nil, ErrTampered
	}
	var b body
	if err := json.Unmarshal(plain, &b); err != nil {
		return nil, ErrTampered
	}
	// A Vault's own copy of key, never the caller's slice — see the same
	// note in Create.
	v := &Vault{path: path, key: append([]byte(nil), key...), dataKey: dataKey, entries: map[string]*Entry{}}
	for i := range b.Entries {
		e := b.Entries[i]
		v.entries[e.Handle] = &e
	}
	return v, nil
}

func aadFor(env envelope) []byte {
	return []byte(fmt.Sprintf("cpass-vault-v%d:%s:%s", env.Version, env.KeyNonce, env.WrappedKey))
}

// Save encrypts and writes the Vault to disk with mode 0600, via
// internal/atomicfile: staged in a per-invocation-unique temp file in the
// same directory (never the fixed v.path+".tmp" two Saves could otherwise
// race each other's rename on), fsynced, renamed into place, and the
// directory fsynced after — so a crash or power loss right after cpass
// reports success can no longer revert vault.cpv to its pre-write state
// with no indication anything was lost (CLA-56).
//
// Before that overwrite, Save preserves the generation it is about to
// replace as vault.cpv.bak — also via atomicfile, so the backup itself
// never lands half-written — best effort: a brand-new Vault has no prior
// generation yet, which is not an error. This is the Vault's only backup
// or recovery mechanism (CLA-59); docs/SECURITY.md documents the
// consequence that a Handle removed by this Save still exists, encrypted,
// in vault.cpv.bak until the next write.
//
// Save on its own does not make two concurrent writers safe: it guarantees
// only that the write it was given lands whole or not at all, atomically
// with respect to a concurrent reader. See Update for the actual
// read-modify-write serialization (CLA-55).
func (v *Vault) Save() error {
	entries := v.List("")
	plain, err := json.Marshal(body{Entries: entries})
	if err != nil {
		return err
	}
	keyNonce, wrapped, err := seal(v.key, v.dataKey, []byte("cpass-data-key"))
	if err != nil {
		return err
	}
	env := envelope{Version: FormatVersion, KeyNonce: b64e(keyNonce), WrappedKey: b64e(wrapped)}
	nonce, ct, err := seal(v.dataKey, plain, aadFor(env))
	if err != nil {
		return err
	}
	env.Nonce, env.Ciphertext = b64e(nonce), b64e(ct)
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(v.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// MkdirAll is a no-op on a directory that already exists, regardless of
	// its current mode, so a loosened CPASS_HOME (a stray umask, a reused
	// directory) would otherwise stay loosened forever. Chmod unconditionally
	// to make sure it ends up 0700 either way.
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if old, err := os.ReadFile(v.path); err == nil {
		if err := atomicfile.Write(v.path+".bak", old, 0o600); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicfile.Write(v.path, out, 0o600)
}

// lockSuffix names the sidecar lock file Update holds for the whole
// Open -> mutate -> Save cycle: path+".lock", next to the Vault itself.
const lockSuffix = ".lock"

// Update is the one correct way for a `cpass` process to change the Vault:
// it holds an exclusive lock (internal/lockfile) for the whole cycle,
// opens path fresh under that lock (so it always sees the latest state, not
// whatever a caller happened to Open earlier), runs fn, and Saves if fn
// returns nil. Every write command funnels through this (directly, or via
// broker.UpdateVault) so two `cpass` processes writing the same Vault at
// once can never race each other's Open -> mutate -> Save and silently
// drop one of their changes (CLA-55).
//
// A reader (Get, List, Count, and so broker.Resolve/OpenVault) never calls
// this: Save's atomic rename already keeps a concurrent read consistent on
// its own, and making every read wait on the write lock would serialize
// `cpass ls` behind an unrelated `cpass add` for no reason.
func Update(path string, key []byte, fn func(v *Vault) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lock, err := lockfile.Acquire(path+lockSuffix, lockfile.DefaultTimeout)
	if err != nil {
		return fmt.Errorf("vault: locking for write: %w", err)
	}
	defer func() { _ = lock.Release() }()
	v, err := Open(path, key)
	if err != nil {
		return err
	}
	// Update owns this Vault for exactly the length of the call, so it
	// zeroes the key material itself (CLA-60) rather than handing an open
	// Vault back for every caller to remember to Close.
	defer v.Close()
	if err := fn(v); err != nil {
		return err
	}
	return v.Save()
}

// Path is the file the Vault lives in.
func (v *Vault) Path() string { return v.path }

// Close zeroes the unlock key and data key this Vault holds in memory.
// Call it on every bounded use of an opened Vault — a CLI command, an MCP
// tool call, one broker.Resolve — once it is done with the key material,
// typically deferred right after Open/Create/OpenVault succeeds (Save, if
// any, always runs first in program order; a deferred Close only ever runs
// after it).
//
// This is best-effort hygiene, not a guarantee: by the time Close runs, Go's
// garbage collector or the runtime may already have copied these bytes
// elsewhere (a slice that grew and reallocated, a value that escaped to the
// heap, a moved goroutine stack), and none of those copies are found or
// wiped. It shortens how long the key sits at its one certain address, no
// more — see docs/SECURITY.md. Idempotent: safe to call more than once, and
// safe to call on a Vault whose key material is already zero.
func (v *Vault) Close() {
	zero(v.key)
	zero(v.dataKey)
}

// zero overwrites every byte of b in place.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Get returns a copy of the Entry for handle.
func (v *Vault) Get(handle string) (Entry, error) {
	e, ok := v.entries[handle]
	if !ok {
		return Entry{}, fmt.Errorf("%w: %s", ErrNotFound, handle)
	}
	return *e, nil
}

// List returns copies of every Entry whose Handle starts with prefix, sorted.
func (v *Vault) List(prefix string) []Entry {
	out := make([]Entry, 0, len(v.entries))
	for _, e := range v.entries {
		if strings.HasPrefix(e.Handle, prefix) {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Handle < out[j].Handle })
	return out
}

// Count is the number of Secrets in the Vault.
func (v *Vault) Count() int { return len(v.entries) }

// AddOptions configures Add.
type AddOptions struct {
	Binding Binding // zero value derives an env Binding from the Handle
	Exposed string  // non-empty marks the Secret Exposed with this reason
}

// Add stores a new Secret. The value must be at least MinSecretLength long.
func (v *Vault) Add(handle, value string, opts AddOptions) (Entry, error) {
	if err := ValidateHandle(handle); err != nil {
		return Entry{}, err
	}
	if len(value) < MinSecretLength {
		return Entry{}, fmt.Errorf("vault: value for %s is shorter than %d characters", handle, MinSecretLength)
	}
	if _, ok := v.entries[handle]; ok {
		return Entry{}, fmt.Errorf("%w: %s", ErrExists, handle)
	}
	b := opts.Binding
	if b.Kind == "" {
		b.Kind = BindEnv
	}
	if b.Name == "" {
		b.Name = DefaultBindingName(handle)
	}
	now := time.Now().UTC()
	e := &Entry{Handle: handle, Value: value, Binding: b, CreatedAt: now, UpdatedAt: now}
	if opts.Exposed != "" {
		e.Exposed = true
		e.Exposures = []Exposure{{At: now, Reason: opts.Exposed}}
	}
	v.entries[handle] = e
	return *e, nil
}

// Remove deletes a Secret.
func (v *Vault) Remove(handle string) error {
	if _, ok := v.entries[handle]; !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, handle)
	}
	delete(v.entries, handle)
	return nil
}

// Rename moves a Secret to a new Handle, keeping its metadata. The Binding
// name is re-derived only if it was the default for the old Handle.
func (v *Vault) Rename(from, to string) error {
	if err := ValidateHandle(to); err != nil {
		return err
	}
	e, ok := v.entries[from]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, from)
	}
	if _, ok := v.entries[to]; ok {
		return fmt.Errorf("%w: %s", ErrExists, to)
	}
	if e.Binding.Name == DefaultBindingName(from) {
		e.Binding.Name = DefaultBindingName(to)
	}
	e.Handle = to
	e.UpdatedAt = time.Now().UTC()
	delete(v.entries, from)
	v.entries[to] = e
	return nil
}

// MarkExposed flags a Secret as Exposed with a reason.
func (v *Vault) MarkExposed(handle, reason string) error {
	e, ok := v.entries[handle]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, handle)
	}
	e.Exposed = true
	e.Exposures = append(e.Exposures, Exposure{At: time.Now().UTC(), Reason: reason})
	e.UpdatedAt = time.Now().UTC()
	return nil
}

// ClearExposed clears the Exposed flag after rotation.
func (v *Vault) ClearExposed(handle string) error {
	e, ok := v.entries[handle]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, handle)
	}
	e.Exposed = false
	e.UpdatedAt = time.Now().UTC()
	return nil
}

func b64e(b []byte) string          { return base64.StdEncoding.EncodeToString(b) }
func b64d(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
