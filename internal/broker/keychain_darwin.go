//go:build darwin

package broker

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
)

// The Keychain is accessed only through the `security` CLI as a subprocess:
// no cgo, so cpass links no Security framework and an invocation can never
// trigger the Keychain's access-control GUI (Touch ID / password prompt).
// That also means we cannot set a user-presence ACL on the item — see
// CLA-9 for a cgo-based Touch ID follow-up.

// keychainGet reads the password of the generic-password item (service,
// account), decoding it from base64.
func keychainGet(service, account string) ([]byte, error) {
	cmd := exec.Command("security", "find-generic-password", "-a", account, "-s", service, "-w")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("broker: security find-generic-password: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out.String()))
	if err != nil {
		return nil, fmt.Errorf("broker: Keychain item %s/%s is not a valid key: %w", service, account, err)
	}
	return key, nil
}

// keychainSet creates or replaces the generic-password item (service,
// account) with key, base64-encoded. The creating process (`security`) is
// trusted by default to read its own items back without a prompt, so no
// -T/-A access-control flag is needed or set.
func keychainSet(service, account string, key []byte) error {
	enc := base64.StdEncoding.EncodeToString(key)
	cmd := exec.Command("security", "add-generic-password", "-a", account, "-s", service, "-w", enc, "-U")
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("broker: security add-generic-password: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return nil
}
