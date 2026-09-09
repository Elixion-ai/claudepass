package cli

import (
	"flag"
	"fmt"
	"time"

	"claudepass/internal/broker"
	"claudepass/internal/license"
	"claudepass/internal/vault"
)

func init() {
	register(command{"license", "manage the license: activate <token> | status | deactivate", cmdLicense})
}

func cmdLicense(e *env) int {
	if len(e.args) == 0 {
		return e.fail(ExitUsage, "usage: cpass license activate <token> | status | deactivate")
	}
	sub, rest := e.args[0], e.args[1:]
	switch sub {
	case "activate":
		return licenseActivate(e, rest)
	case "status":
		return licenseStatus(e, rest)
	case "deactivate":
		return licenseDeactivate(e, rest)
	}
	return e.fail(ExitUsage, "unknown license subcommand %q", sub)
}

func licenseActivate(e *env, args []string) int {
	fs := flag.NewFlagSet("license activate", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		return e.fail(ExitUsage, "usage: cpass license activate <token>")
	}
	home, err := broker.Home()
	if err != nil {
		return e.failErr(err)
	}
	p, err := license.Activate(home, fs.Arg(0))
	if err != nil {
		return e.fail(ExitError, "license token refused: %v", err)
	}
	fmt.Fprintf(e.stdout, "activated license for %s: plan %s, expires %s\n",
		p.Sub, p.Plan, time.Unix(p.Exp, 0).UTC().Format(time.RFC3339))
	warnIfDegraded(e, license.Load(home))
	return ExitOK
}

func licenseStatus(e *env, args []string) int {
	fs := flag.NewFlagSet("license status", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	home, err := broker.Home()
	if err != nil {
		return e.failErr(err)
	}
	st := license.Load(home)
	fmt.Fprintf(e.stdout, "plan: %s\n", st.Plan)
	if st.Payload != nil {
		fmt.Fprintf(e.stdout, "account: %s\n", st.Payload.Sub)
		fmt.Fprintf(e.stdout, "expires: %s\n", time.Unix(st.Payload.Exp, 0).UTC().Format(time.RFC3339))
	}
	if st.Plan == license.PlanFree {
		fmt.Fprintf(e.stdout, "limit: %d Secrets\n", license.FreeSecretLimit)
	} else {
		fmt.Fprintln(e.stdout, "limit: unlimited")
	}
	warnIfDegraded(e, st)
	return ExitOK
}

func licenseDeactivate(e *env, args []string) int {
	fs := flag.NewFlagSet("license deactivate", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	home, err := broker.Home()
	if err != nil {
		return e.failErr(err)
	}
	if err := license.Deactivate(home); err != nil {
		return e.failErr(err)
	}
	fmt.Fprintln(e.stdout, "deactivated license; back to the free plan")
	return ExitOK
}

func warnIfDegraded(e *env, st license.Status) {
	if st.Warning != "" {
		fmt.Fprintln(e.stderr, "cpass: "+st.Warning)
	}
}

// freeLimitMessage is the exact refusal shown when the free plan's Secret
// limit blocks a new Secret, per CLA-14.
const freeLimitMessage = "free plan holds %d Secrets; upgrade at https://claudepass.dev/pricing ($9.99/month)"

// CheckFreeLimit refuses to create another Secret when the free plan's
// limit is reached and no valid, unexpired license lifts it. add and the
// future import and capture commands must call this before creating a new
// Entry, and the future intercept command calls it too: storing what it
// caught is exactly a Capture, so on refusal intercept must still block the
// prompt from reaching the Agent while telling the human it could not
// store the value (the returned error carries that message).
//
// It also surfaces a stored-but-expired license's warning to e.stderr as a
// side effect, on every call, not only on refusal: that is the one point
// every gated command passes through, and the expired-license notice must
// reach the human even on the calls that still succeed.
func CheckFreeLimit(e *env, v *vault.Vault) error {
	home, err := broker.Home()
	if err != nil {
		return err
	}
	st := license.Load(home)
	warnIfDegraded(e, st)
	if st.NeedsUpgrade(v.Count()) {
		return fmt.Errorf(freeLimitMessage, license.FreeSecretLimit)
	}
	return nil
}
