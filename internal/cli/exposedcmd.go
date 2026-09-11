package cli

import (
	"flag"
	"io"
	"time"
)

func init() {
	register(command{"exposed", "list Exposed Secrets with when and how they were exposed", cmdExposed})
	register(command{"rotate-done", "clear the Exposed flag after replacing a value: cpass rotate-done <handle>", cmdRotateDone})
	register(command{"mark-exposed", "flag a Secret Exposed from another surface: cpass mark-exposed <handle> --reason R", cmdMarkExposed})
}

func cmdExposed(e *env) int {
	fs := flag.NewFlagSet("exposed", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(e.args); err != nil {
		return e.usageErr(err, "cpass exposed")
	}
	v, code := openVault(e)
	if code != ExitOK {
		return code
	}
	any := false
	for _, en := range v.List("") {
		if !en.Exposed {
			continue
		}
		any = true
		reason, at := "unknown", "unknown"
		if n := len(en.Exposures); n > 0 {
			last := en.Exposures[n-1]
			reason = last.Reason
			at = last.At.Format(time.RFC3339)
		}
		fprintf(e.stdout, "%-30s %-20s reason=%s\n", en.Handle, at, reason)
	}
	if !any {
		fprintln(e.stdout, "no Exposed Secrets")
	}
	return ExitOK
}

func cmdRotateDone(e *env) int {
	fs := flag.NewFlagSet("rotate-done", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(e.args); err != nil {
		return e.usageErr(err, "cpass rotate-done <handle>")
	}
	if fs.NArg() != 1 {
		return e.fail(ExitUsage, "usage: cpass rotate-done <handle>")
	}
	v, code := openVault(e)
	if code != ExitOK {
		return code
	}
	handle := fs.Arg(0)
	if err := v.ClearExposed(handle); err != nil {
		return e.failErr(err)
	}
	if err := v.Save(); err != nil {
		return e.failErr(err)
	}
	fprintf(e.stdout, "%s is no longer Exposed\n", handle)
	return ExitOK
}

func cmdMarkExposed(e *env) int {
	fs := flag.NewFlagSet("mark-exposed", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reason := fs.String("reason", "manual", "why the Secret is considered Exposed")
	pos, err := parseInterspersed(fs, e.args)
	if err != nil {
		return e.usageErr(err, "cpass mark-exposed <handle> [--reason REASON]")
	}
	if len(pos) != 1 {
		return e.fail(ExitUsage, "usage: cpass mark-exposed <handle> [--reason REASON]")
	}
	v, code := openVault(e)
	if code != ExitOK {
		return code
	}
	handle := pos[0]
	if err := v.MarkExposed(handle, *reason); err != nil {
		return e.failErr(err)
	}
	if err := v.Save(); err != nil {
		return e.failErr(err)
	}
	fprintf(e.stdout, "%s marked Exposed (%s)\n", handle, *reason)
	return ExitOK
}
