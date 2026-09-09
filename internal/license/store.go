package license

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileName is the license token's file name under $CPASS_HOME.
const FileName = "license"

// Path returns the license file's path under home.
func Path(home string) string { return filepath.Join(home, FileName) }

// Status is the resolved state of the license: which plan the CLI should
// grant right now, and a warning to surface when that state is a degrade
// rather than the token's face value.
type Status struct {
	// Plan is PlanFree or PlanPro: what the caller should actually enforce.
	Plan string
	// Payload is the stored token's payload, or nil when no token is
	// stored. It is set even when Plan has been degraded to free (an
	// expired token still reports its original payload for `status`).
	Payload *Payload
	// Warning explains a degrade to free plan: non-empty when a token is
	// stored but expired, or unreadable. Empty on the happy paths (no
	// token at all, or an active unexpired one).
	Warning string
}

// Activate verifies raw's signature and, only if it verifies, stores it
// under home. It does not check expiry: a token that is already expired at
// activation time is still authentically signed, so it is stored, and Load
// reports it as an expired degrade rather than Activate refusing it
// outright — the same rule an already-active token follows when it expires
// later. Callers refuse the command on a non-nil error; nothing is written
// in that case.
func Activate(home, raw string) (Payload, error) {
	p, err := Verify(raw)
	if err != nil {
		return Payload{}, err
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return Payload{}, err
	}
	tmp := Path(home) + ".tmp"
	if err := os.WriteFile(tmp, []byte(raw), 0o600); err != nil {
		return Payload{}, err
	}
	if err := os.Rename(tmp, Path(home)); err != nil {
		return Payload{}, err
	}
	return p, nil
}

// Deactivate removes the stored license token. Removing an already-absent
// one is not an error: deactivate is idempotent.
func Deactivate(home string) error {
	err := os.Remove(Path(home))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Load reports the license Status under home. It never fails: any problem
// reading or verifying a stored token (missing, corrupt, tampered, or
// simply expired) degrades to the free plan with an explanatory Warning
// rather than an error, because a license problem must never block reading
// or running Secrets that already exist — only the free-plan Secret limit,
// enforced separately, does that.
func Load(home string) Status {
	raw, err := os.ReadFile(Path(home))
	if err != nil {
		return Status{Plan: PlanFree}
	}
	p, err := Verify(string(raw))
	if err != nil {
		return Status{Plan: PlanFree, Warning: fmt.Sprintf("stored license is invalid (%v); degraded to free plan", err)}
	}
	if p.Exp != 0 && time.Now().Unix() >= p.Exp {
		return Status{
			Plan:    PlanFree,
			Payload: &p,
			Warning: fmt.Sprintf("license for %s expired %s; degraded to free plan (upgrade at https://claudepass.dev/pricing)", p.Sub, time.Unix(p.Exp, 0).UTC().Format("2006-01-02")),
		}
	}
	return Status{Plan: p.Plan, Payload: &p}
}

// NeedsUpgrade reports whether count existing Secrets already meets or
// exceeds the free plan's limit under this Status — the one decision add,
// import, capture and intercept all gate a new Secret on. A Pro (or any
// non-free) plan never needs an upgrade.
func (s Status) NeedsUpgrade(count int) bool {
	return s.Plan == PlanFree && count >= FreeSecretLimit
}
