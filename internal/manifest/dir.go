package manifest

import "os"

// ensurePrivateDir creates dir (and any missing parents) and makes sure it
// ends up mode 0700 either way: os.MkdirAll is a no-op on a directory that
// already exists, regardless of its current mode, so a loosened directory
// (a stray umask, a reused $CPASS_HOME) would otherwise stay loosened
// forever without an explicit chmod after it — the same fix already
// applied to the Vault's own directory in vault.Save (CLA-58). Every place
// in this package that ensures $CPASS_HOME or one of its own subdirectories
// exists (SaveGlobal and UpdateGlobal in global.go, shouldWarnBroadRoot in
// broadroot.go) shares this one helper instead of repeating the
// MkdirAll-then-chmod pair at each call site (CLA-98 item 7).
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}
