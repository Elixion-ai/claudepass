package cli

import (
	"bufio"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"strings"

	"claudepass/internal/broker"
	"claudepass/internal/vault"
)

func init() {
	register(command{"unlock", "start the Broker holding the Vault key (Linux/CI, or macOS with CPASS_UNLOCK=socket)", cmdUnlock})
	register(command{"lock", "stop the Broker and drop the held key", cmdLock})
	register(command{"broker-serve", "(internal) run as the Broker process in the foreground; started by cpass unlock", cmdBrokerServe})
}

func cmdUnlock(e *env) int {
	fs := flag.NewFlagSet("unlock", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	timeout := fs.Duration("timeout", broker.DefaultIdleTimeout, "idle timeout before the Broker drops the key")
	if err := fs.Parse(e.args); err != nil {
		return ExitUsage
	}
	if broker.UseKeychain() {
		return e.fail(ExitError, "this Vault unlocks via the macOS Keychain automatically; there is no Broker to start (set CPASS_UNLOCK=socket to use one anyway)")
	}
	passphrase, err := e.readSecret("master passphrase: ",
		"cpass unlock needs a terminal to type the master passphrase into: run it from your own terminal, not from an Agent session")
	if err != nil {
		return e.failErr(err)
	}
	key, err := broker.DeriveKey(passphrase)
	if err != nil {
		return e.failErr(err)
	}
	path, err := broker.VaultPath()
	if err != nil {
		return e.failErr(err)
	}
	if _, err := vault.Open(path, key); err != nil {
		return e.failErr(err)
	}
	if err := broker.StartBroker(key, *timeout); err != nil {
		return e.failErr(err)
	}
	fprintf(e.stdout, "unlocked (idle timeout %s)\n", timeout.String())
	return ExitOK
}

func cmdLock(e *env) int {
	fs := flag.NewFlagSet("lock", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	if err := fs.Parse(e.args); err != nil {
		return ExitUsage
	}
	if broker.UseKeychain() {
		return e.fail(ExitError, "this Vault unlocks via the macOS Keychain automatically; there is no Broker to stop (set CPASS_UNLOCK=socket to use one anyway)")
	}
	if err := broker.StopBroker(); err != nil {
		return e.failErr(err)
	}
	fprintln(e.stdout, "locked")
	return ExitOK
}

// cmdBrokerServe runs the Broker process itself in the foreground. cpass
// unlock spawns it detached; it is not meant to be run by hand. The key is
// read from stdin (never a command-line argument) so it never appears in a
// process listing.
func cmdBrokerServe(e *env) int {
	fs := flag.NewFlagSet("broker-serve", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	socketPath := fs.String("socket", "", "unix socket path to listen on")
	timeout := fs.Duration("timeout", broker.DefaultIdleTimeout, "idle timeout before exiting")
	if err := fs.Parse(e.args); err != nil {
		return ExitUsage
	}
	if *socketPath == "" {
		return e.fail(ExitUsage, "broker-serve requires -socket")
	}
	line, err := bufio.NewReader(e.stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return e.failErr(err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil || len(key) != vault.KeySize {
		return e.fail(ExitError, "broker-serve: bad key on stdin")
	}
	if err := broker.Serve(*socketPath, key, *timeout); err != nil {
		return e.failErr(err)
	}
	return ExitOK
}
