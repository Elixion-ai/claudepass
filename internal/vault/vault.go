// Package vault implements the encrypted local store where Secrets live.
//
// On disk a Vault is a JSON envelope: a random data key wrapped by the unlock
// key, and the entry list encrypted under the data key. Both layers use
// XChaCha20-Poly1305, so a wrong key fails at the unwrap and a modified body
// fails at the open; the two are reported as distinct errors.
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
func Create(path string, key []byte) (*Vault, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("vault: unlock key must be %d bytes", KeySize)
	}
	if Exists(path) {
		return nil, fmt.Errorf("vault: %s already exists", path)
	}
	dataKey, err := randomBytes(KeySize)
	if err != nil {
		return nil, err
	}
	v := &Vault{path: path, key: key, dataKey: dataKey, entries: map[string]*Entry{}}
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
	v := &Vault{path: path, key: key, dataKey: dataKey, entries: map[string]*Entry{}}
	for i := range b.Entries {
		e := b.Entries[i]
		v.entries[e.Handle] = &e
	}
	return v, nil
}

func aadFor(env envelope) []byte {
	return []byte(fmt.Sprintf("cpass-vault-v%d:%s:%s", env.Version, env.KeyNonce, env.WrappedKey))
}

// Save encrypts and atomically writes the Vault to disk with mode 0600.
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
	if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
		return err
	}
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, v.path)
}

// Path is the file the Vault lives in.
func (v *Vault) Path() string { return v.path }

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
