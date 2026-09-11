package cli

import (
	"errors"
	"flag"
	"io"
	"runtime"

	"claudepass/internal/broker"
)

func init() {
	register(command{"keychain", "manage the macOS Keychain unlock item: upgrade --touch-id", cmdKeychain})
}

func cmdKeychain(e *env) int {
	if len(e.args) == 0 {
		return e.fail(ExitUsage, "usage: cpass keychain upgrade --touch-id")
	}
	sub := e.args[0]
	e.args = e.args[1:]
	switch sub {
	case "upgrade":
		return cmdKeychainUpgrade(e)
	}
	return e.fail(ExitUsage, "unknown keychain subcommand %q", sub)
}

// cmdKeychainUpgrade is CLA-23's opt-in: it re-stores the current Vault's
// key under this Vault's existing Keychain (service, account) identity,
// this time with a SecAccessControl requiring Touch ID or the device
// passcode — replacing whatever item (plain or already access-controlled)
// was there. Unlike `cpass init --touch-id`, it does not fall back to a
// plain item when Touch ID support is unavailable: there is no new Vault
// to create here, only an existing Keychain item to leave alone or
// deliberately upgrade, so an unmet --touch-id request is refused rather
// than silently doing nothing while claiming success.
func cmdKeychainUpgrade(e *env) int {
	fs := flag.NewFlagSet("keychain upgrade", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	touchID := fs.Bool("touch-id", false,
		"require Touch ID or the device passcode to read the Vault key from the macOS Keychain")
	if err := fs.Parse(e.args); err != nil {
		return e.usageErr(err, "cpass keychain upgrade --touch-id")
	}
	if !*touchID {
		return e.fail(ExitUsage, "usage: cpass keychain upgrade --touch-id")
	}
	if runtime.GOOS != "darwin" {
		return e.fail(ExitError, "cpass keychain upgrade is macOS-only")
	}
	if !broker.TouchIDAvailable() {
		return e.fail(ExitError, "%v", broker.ErrTouchIDUnsupported)
	}
	key, err := broker.UnlockKey()
	if err != nil {
		if errors.Is(err, broker.ErrLocked) {
			fprintln(e.stderr, e.locked())
			return ExitError
		}
		return e.failErr(err)
	}
	if err := broker.SetKeychainKeyUserPresence(key); err != nil {
		return e.failErr(err)
	}
	fprintf(e.stdout, "upgraded the Keychain item (service %q) to require Touch ID or the device passcode\n", broker.KeychainService())
	return ExitOK
}
