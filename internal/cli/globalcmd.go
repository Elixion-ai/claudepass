package cli

import (
	"flag"
	"io"

	"github.com/Elixion-ai/claudepass/internal/broker"
	"github.com/Elixion-ai/claudepass/internal/manifest"
	"github.com/Elixion-ai/claudepass/internal/vault"
)

// globalFlag registers -g and --global on fs as one destination — Go's flag
// package treats one dash and two alike, so each spelling is its own
// registration. Every command that can target the Global Manifest shares
// this one function, so the spellings can never drift apart: -g is what a
// human types while setting a machine up, --global is what a script reads
// back. (`cpass ls -l` is the other single-letter flag in this CLI.)
func globalFlag(fs *flag.FlagSet, usage string) *bool {
	var b bool
	fs.BoolVar(&b, "g", false, usage)
	fs.BoolVar(&b, "global", false, usage)
	return &b
}

func init() {
	register(command{"global", "declare an existing Handle in the Global Manifest", cmdGlobal})
	register(command{"local", "stop declaring a Handle in the Global Manifest", cmdLocal})
}

// cmdGlobal promotes a Handle already in the Vault to the Global Manifest,
// the same declaration `cpass add -g` writes at the moment a Secret is
// stored — so a Handle can become machine-wide later without retyping its
// value (which `cpass add` would refuse to accept inline anyway).
func cmdGlobal(e *env) int {
	fs := flag.NewFlagSet("global", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	binding := fs.String("binding", "", "environment variable name (default derived from the Handle)")
	file := fs.Bool("file", false, "file Binding: the variable holds a path to a temp file")
	pos, err := parseInterspersed(fs, e.args)
	if err != nil {
		return e.usageErr(err, "cpass global <handle> [--binding NAME] [--file]")
	}
	if len(pos) != 1 {
		return e.fail(ExitUsage, "usage: cpass global <handle> [--binding NAME] [--file]")
	}
	handle := pos[0]
	if err := vault.ValidateHandle(handle); err != nil {
		return e.failErr(err)
	}
	entry := manifest.Entry{Handle: handle, Binding: vault.Binding{Name: *binding}}
	if *file {
		entry.Binding.Kind = vault.BindFile
	}
	return declareGlobal(e, entry)
}

// declareGlobal writes one Entry to the Global Manifest and reports it in
// the same "declared <handle> in <path>" grammar `cpass manifest add` uses,
// so the two doors into a declaration read identically.
func declareGlobal(e *env, entry manifest.Entry) int {
	warnUnknownGlobal(e, entry.Handle)
	gm, err := manifest.LoadGlobal()
	if err != nil {
		return e.failErr(err)
	}
	gm.Add(entry)
	if err := gm.SaveGlobal(); err != nil {
		return e.failErr(err)
	}
	fprintf(e.stdout, "declared %s in %s\n", e.paintOut(roleEmber, entry.Handle), e.paintOut(roleDim, gm.Path))
	return ExitOK
}

// cmdLocal undeclares a Handle globally. The Secret itself is untouched:
// this is the inverse of the declaration, not of `cpass add`.
func cmdLocal(e *env) int {
	fs := flag.NewFlagSet("local", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(e.args); err != nil {
		return e.usageErr(err, "cpass local <handle>")
	}
	if fs.NArg() != 1 {
		return e.fail(ExitUsage, "usage: cpass local <handle>")
	}
	handle := fs.Arg(0)
	gm, err := manifest.LoadGlobal()
	if err != nil {
		return e.failErr(err)
	}
	if !gm.Remove(handle) {
		return e.fail(ExitError, "%s is not declared in %s", handle, gm.Path)
	}
	if err := gm.SaveGlobal(); err != nil {
		return e.failErr(err)
	}
	fprintf(e.stdout, "removed %s from %s\n", e.paintOut(roleEmber, handle), e.paintOut(roleDim, gm.Path))
	return ExitOK
}

// warnUnknownGlobal says so when a Handle being declared machine-wide is not
// in the Vault. Declaring ahead of storing stays legal — that is how a
// project Manifest works, and `cpass manifest check -g` is the report for it
// — but a Global declaration is different in degree: a typo here becomes a
// skip notice on every run in every project until someone notices, so it is
// worth one line at the moment it is made. Never fatal, and silent when
// there is no Vault to consult (CI, or a locked one).
func warnUnknownGlobal(e *env, handle string) {
	if broker.CIMode() {
		return
	}
	v, err := broker.OpenVault()
	if err != nil {
		return
	}
	defer v.Close()
	if _, err := v.Get(handle); err != nil {
		e.notice("%s is not in the Vault yet; every run will skip it until you `cpass add %s`", handle, handle)
	}
}
