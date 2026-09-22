package cli

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Elixion-ai/claudepass/internal/broker"
	"github.com/Elixion-ai/claudepass/internal/manifest"
	"github.com/Elixion-ai/claudepass/internal/vault"
)

func init() {
	register(command{"init", "create an empty Vault", cmdInit})
	register(command{"add", "store a Secret under a Handle (typed, never pasted to an Agent)", cmdAdd})
	register(command{"ls", "list Handles (never values)", cmdLs})
	register(command{"rm", "delete a Secret", cmdRm})
	register(command{"mv", "rename a Handle", cmdMv})
}

func openVault(e *env) (*vault.Vault, int) {
	v, err := broker.OpenVault()
	if err != nil {
		if errors.Is(err, broker.ErrLocked) {
			fprintln(e.stderr, e.locked())
			return nil, ExitError
		}
		return nil, e.fail(ExitError, "%v", err)
	}
	return v, ExitOK
}

// storeKeychainKey stores key as this Vault's macOS Keychain item, plain
// (the unchanged default CLA-8 behaviour) unless touchID is set. Asking
// for touchID falls back gracefully to that same plain item when this
// cpass binary was not built with Touch ID support
// (broker.TouchIDAvailable() false, true for every CGO_ENABLED=0 build,
// which includes every release and the default `go build`): a portable
// binary must still be able to create a working Vault, so this warns
// rather than refusing to init. See docs/SECURITY.md.
func storeKeychainKey(e *env, key []byte, touchID bool) error {
	if touchID && broker.TouchIDAvailable() {
		if err := broker.SetKeychainKeyUserPresence(key); err != nil {
			return err
		}
		e.notice("stored the Vault key in the macOS Keychain (service %q), requiring Touch ID or the device passcode to read it", broker.KeychainService())
		return nil
	}
	if touchID {
		e.notice("--touch-id needs a cpass binary built with -tags touchid on macOS with cgo enabled (CGO_ENABLED=1); storing the key without Touch ID for now — see docs/SECURITY.md, or run `cpass keychain upgrade --touch-id` after rebuilding")
	}
	if err := broker.SetKeychainKey(key); err != nil {
		return err
	}
	e.notice("stored the Vault key in the macOS Keychain (service %q)", broker.KeychainService())
	return nil
}

func cmdInit(e *env) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	touchID := fs.Bool("touch-id", false,
		"require Touch ID or the device passcode to read the Vault key from the macOS Keychain (needs a cpass binary built with -tags touchid)")
	if err := fs.Parse(e.args); err != nil {
		return e.usageErr(err, "cpass init [--touch-id]")
	}
	path, err := broker.VaultPath()
	if err != nil {
		return e.failErr(err)
	}
	if vault.Exists(path) {
		return e.fail(ExitError, "vault already exists at %s", path)
	}
	key, err := broker.UnlockKey()
	if errors.Is(err, broker.ErrLocked) {
		// No CPASS_KEY: pick a key via this platform's unlock source.
		switch {
		case broker.UseKeychain():
			key = make([]byte, vault.KeySize)
			if _, err := rand.Read(key); err != nil {
				return e.failErr(err)
			}
			if err := storeKeychainKey(e, key, *touchID); err != nil {
				return e.failErr(err)
			}
		default:
			if *touchID {
				e.notice("--touch-id only applies to the macOS Keychain unlock source; ignoring it")
			}
			passphrase, err := e.readSecret("master passphrase: ",
				"cpass init needs a terminal to type a master passphrase into, or set CPASS_KEY for CI")
			if err != nil {
				return e.failErr(err)
			}
			if passphrase == "" {
				return e.fail(ExitError, "master passphrase must not be empty")
			}
			key, err = broker.DeriveKey(passphrase)
			if err != nil {
				return e.failErr(err)
			}
			e.notice("run `cpass unlock` before using the Vault from an Agent session")
		}
	} else if err != nil {
		return e.failErr(err)
	}
	if _, err := vault.Create(path, key); err != nil {
		return e.failErr(err)
	}
	fprintf(e.stdout, "initialised vault at %s\n", path)
	return ExitOK
}

func cmdAdd(e *env) int {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	binding := fs.String("binding", "", "environment variable name (default derived from the Handle)")
	file := fs.Bool("file", false, "bind as a temp file whose path is placed in the variable")
	exposed := fs.Bool("exposed", false, "the value has already been seen by an Agent; store it flagged for rotation")
	global := globalFlag(fs, "also declare the Handle in the Global Manifest, so every project that has one receives it")
	pos, err := parseInterspersed(fs, e.args)
	if err != nil {
		return e.usageErr(err, "cpass add <handle> [--binding NAME] [--file] [--exposed] [-g]")
	}
	if len(pos) != 1 {
		return e.fail(ExitUsage, "usage: cpass add <handle> [--binding NAME] [--file] [--exposed] [-g]")
	}
	handle := pos[0]
	if err := vault.ValidateHandle(handle); err != nil {
		return e.failErr(err)
	}
	v, code := openVault(e)
	if code != ExitOK {
		return code
	}
	value, err := e.readSecret(fmt.Sprintf("value for %s: ", handle),
		"add needs a terminal to type the value into; from an Agent, use `cpass capture <handle> -- <command>` so the value never enters its context")
	if err != nil {
		return e.failErr(err)
	}
	opts := vault.AddOptions{}
	if *file {
		opts.Binding.Kind = vault.BindFile
	}
	opts.Binding.Name = *binding
	if *exposed {
		opts.Exposed = "added-exposed"
	}
	entry, err := v.Add(handle, value, opts)
	if err != nil {
		return e.failErr(err)
	}
	if err := v.Save(); err != nil {
		return e.failErr(err)
	}
	// docs/CLI-STYLE.md "Stored a Secret (cpass add)": ember Handle, dim
	// Binding detail, coloured by outMode since this confirmation is
	// written to stdout — never errMode, which belongs to stderr
	// diagnostics (refuse/notice/exposed/locked). Plain-mode bytes are
	// unchanged from before colour existed here.
	fprintf(e.stdout, "stored %s %s\n",
		e.paintOut(roleEmber, entry.Handle),
		e.paintOut(roleDim, fmt.Sprintf("(%s %s)", entry.Binding.Kind, entry.Binding.Name)))
	if *global {
		// Declared only once the Secret is safely in the Vault, and printed
		// as its own existing "declared ... in ..." line rather than
		// crowding the frozen "stored" grammar: two facts, two rows.
		return declareGlobal(e, manifest.Entry{Handle: entry.Handle, Binding: entry.Binding})
	}
	return ExitOK
}

func cmdLs(e *env) int {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	long := fs.Bool("l", false, "show Binding, Exposed state and Global declaration")
	onlyExposed := fs.Bool("exposed", false, "only Exposed Secrets")
	onlyGlobal := fs.Bool("global", false, "only Handles declared in the Global Manifest")
	if err := fs.Parse(e.args); err != nil {
		return e.usageErr(err, "cpass ls [prefix] [-l] [--exposed] [--global]")
	}
	prefix := ""
	if fs.NArg() > 0 {
		prefix = fs.Arg(0)
	}
	v, code := openVault(e)
	if code != ExitOK {
		return code
	}
	// Only read once, and only when the listing actually mentions the Global
	// Manifest: a plain `cpass ls` never touched that file before this
	// feature existed and must not start depending on it being readable.
	gm := &manifest.Manifest{}
	if *long || *onlyGlobal {
		var err error
		if gm, err = manifest.LoadGlobal(); err != nil {
			return e.failErr(err)
		}
	}
	for _, en := range v.List(prefix) {
		if *onlyExposed && !en.Exposed {
			continue
		}
		if *onlyGlobal && !gm.Has(en.Handle) {
			continue
		}
		if *long {
			flags := ""
			if en.Exposed {
				flags += "  EXPOSED"
			}
			if gm.Has(en.Handle) {
				flags += "  GLOBAL"
			}
			fprintf(e.stdout, "%-40s %s %s%s\n", en.Handle, en.Binding.Kind, en.Binding.Name, flags)
		} else {
			fprintln(e.stdout, en.Handle)
		}
	}
	return ExitOK
}

func cmdRm(e *env) int {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(e.args); err != nil {
		return e.usageErr(err, "cpass rm <handle>...")
	}
	if fs.NArg() < 1 {
		return e.fail(ExitUsage, "usage: cpass rm <handle>...")
	}
	v, code := openVault(e)
	if code != ExitOK {
		return code
	}
	for _, h := range fs.Args() {
		if err := v.Remove(h); err != nil {
			return e.failErr(err)
		}
	}
	if err := v.Save(); err != nil {
		return e.failErr(err)
	}
	fprintf(e.stdout, "removed %s\n", strings.Join(fs.Args(), " "))
	return ExitOK
}

func cmdMv(e *env) int {
	fs := flag.NewFlagSet("mv", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(e.args); err != nil {
		return e.usageErr(err, "cpass mv <from> <to>")
	}
	if fs.NArg() != 2 {
		return e.fail(ExitUsage, "usage: cpass mv <from> <to>")
	}
	v, code := openVault(e)
	if code != ExitOK {
		return code
	}
	if err := v.Rename(fs.Arg(0), fs.Arg(1)); err != nil {
		return e.failErr(err)
	}
	if err := v.Save(); err != nil {
		return e.failErr(err)
	}
	fprintf(e.stdout, "renamed %s -> %s\n", fs.Arg(0), fs.Arg(1))
	return ExitOK
}
