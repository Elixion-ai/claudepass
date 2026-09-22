package cli

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"

	"github.com/Elixion-ai/claudepass/internal/broker"
	"github.com/Elixion-ai/claudepass/internal/manifest"
	"github.com/Elixion-ai/claudepass/internal/vault"
)

func init() {
	register(command{"manifest", "declare the Handles a project needs: manifest init|add|check|global", cmdManifest})
}

const manifestUsage = "usage: cpass manifest init | add <handle> [--binding NAME] [--file] [-g] | check [-g|--effective] | global <on|off>"

func cmdManifest(e *env) int {
	if len(e.args) == 0 {
		return e.fail(ExitUsage, manifestUsage)
	}
	if isHelpFlag(e.args[0]) {
		fprintln(e.stdout, manifestUsage)
		return ExitOK
	}
	sub, rest := e.args[0], e.args[1:]
	switch sub {
	case "init":
		return manifestInit(e, rest)
	case "add":
		return manifestAdd(e, rest)
	case "check":
		return manifestCheck(e, rest)
	case "global":
		return manifestGlobalToggle(e, rest)
	}
	return e.fail(ExitUsage, "unknown manifest subcommand %q", sub)
}

func manifestInit(e *env, args []string) int {
	fs := flag.NewFlagSet("manifest init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	noGlobal := fs.Bool("no-global", false, "opt this project out of the Global Manifest's Handles")
	if err := fs.Parse(args); err != nil {
		return e.usageErr(err, "cpass manifest init [--no-global]")
	}
	p := filepath.Join(".", manifest.FileName)
	if _, err := os.Stat(p); err == nil {
		return e.fail(ExitError, "%s already exists", p)
	}
	// Warn before writing: a Manifest planted at the filesystem root or the
	// caller's own home directory turns every Global Handle this machine
	// ever declares into an ambient default for every subdirectory beneath
	// it — scratch checkouts and downloads included, none of them reviewed
	// or introduced to ClaudePass on their own. Never fatal, and silent for
	// an ordinary project root (BroadRoot's own withhold-rather-than-guess
	// error handling keeps a broken os.UserHomeDir() from blocking init).
	if broad, _ := manifest.BroadRoot("."); broad {
		if wd, err := os.Getwd(); err == nil {
			e.notice("%s is a broad ancestor (your home directory, or /) — every Global Handle you ever declare will reach every directory beneath it, not just this project; consider running cpass manifest init somewhere narrower", wd)
		}
	}
	m := &manifest.Manifest{Path: p, GlobalDisabled: *noGlobal}
	if err := m.Save(); err != nil {
		return e.failErr(err)
	}
	fprintf(e.stdout, "created %s\n", p)
	return ExitOK
}

func manifestAdd(e *env, args []string) int {
	fs := flag.NewFlagSet("manifest add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	binding := fs.String("binding", "", "environment variable name (default derived from the Handle)")
	file := fs.Bool("file", false, "file Binding: the variable holds a path to a temp file")
	global := globalFlag(fs, "declare in the Global Manifest instead of this project's")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return e.usageErr(err, "cpass manifest add <handle> [--binding NAME] [--file] [-g]")
	}
	if len(pos) != 1 {
		return e.fail(ExitUsage, "usage: cpass manifest add <handle> [--binding NAME] [--file] [-g]")
	}
	handle := pos[0]
	if err := vault.ValidateHandle(handle); err != nil {
		return e.failErr(err)
	}
	entry := manifest.Entry{Handle: handle, Binding: vault.Binding{Name: *binding}}
	if *file {
		entry.Binding.Kind = vault.BindFile
	}
	if *global {
		// The Global Manifest needs no project to live in, so this door is
		// open from any directory — unlike every other manifest subcommand.
		return declareGlobal(e, entry)
	}
	m, code := loadManifest(e)
	if code != ExitOK {
		return code
	}
	m.Add(entry)
	if err := m.Save(); err != nil {
		return e.failErr(err)
	}
	fprintf(e.stdout, "declared %s in %s\n", handle, m.Path)
	return ExitOK
}

func manifestCheck(e *env, args []string) int {
	fs := flag.NewFlagSet("manifest check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	global := globalFlag(fs, "check the Global Manifest instead of this project's")
	effective := fs.Bool("effective", false,
		"report every Handle this project actually receives — its own Entries plus any reachable Global Handles")
	if err := fs.Parse(args); err != nil {
		return e.usageErr(err, "cpass manifest check [-g|--effective]")
	}
	if *effective {
		if *global {
			return e.fail(ExitUsage, "-g and --effective are mutually exclusive; --effective already includes reachable Global Handles")
		}
		return manifestCheckEffective(e)
	}
	var m *manifest.Manifest
	if *global {
		var err error
		if m, err = manifest.LoadGlobal(); err != nil {
			return e.failErr(err)
		}
	} else {
		var code int
		if m, code = loadManifest(e); code != ExitOK {
			return code
		}
	}
	if broker.CIMode() {
		var missing []string
		for _, en := range m.Entries {
			if _, ok := os.LookupEnv(en.Binding.Name); !ok {
				missing = append(missing, en.Handle+" ("+en.Binding.Name+")")
			}
		}
		return reportMissing(e, m, missing)
	}
	v, code := openVault(e)
	if code != ExitOK {
		return code
	}
	defer v.Close()
	var missing []string
	for _, en := range m.Entries {
		if _, err := v.Get(en.Handle); err != nil {
			missing = append(missing, en.Handle)
		}
	}
	return reportMissing(e, m, missing)
}

func reportMissing(e *env, m *manifest.Manifest, missing []string) int {
	if len(missing) == 0 {
		fprintf(e.stdout, "ok: all %d handles in %s are available\n", len(m.Entries), m.Path)
		return ExitOK
	}
	e.notice("%d missing handle(s):", len(missing))
	for _, h := range missing {
		fprintf(e.stderr, "  %s\n", h)
	}
	return ExitError
}

// manifestCheckEffective reports on the union manifest.Refs actually
// computes for this directory at run time — the project's own Entries
// layered over any reachable Global Handles — rather than auditing one
// file's Entries in isolation the way a plain `cpass manifest check` (with
// or without -g) does. It is the single command that answers "what does
// this project actually receive?", including Handles it never declared
// itself.
func manifestCheckEffective(e *env) int {
	m, code := loadManifest(e)
	if code != ExitOK {
		return code
	}
	refs, notices, err := manifest.Refs(".", true)
	if err != nil {
		return e.failErr(err)
	}
	for _, n := range notices {
		fprintln(e.stderr, n)
	}
	// A project Entry that shares a Handle with the Global Manifest is only
	// an override when the Global Manifest was actually going to reach this
	// directory at all — GlobalReachable applies the same gate Refs uses
	// internally, so a Handle name that merely coincides with an unreachable
	// Global Manifest (opted out, or across a nested-repository boundary)
	// is reported as an ordinary project Entry, not a false "OVERRIDES".
	globalHandles := map[string]bool{}
	if reachable, err := manifest.GlobalReachable("."); err != nil {
		return e.failErr(err)
	} else if reachable {
		if gm, err := manifest.LoadGlobal(); err == nil {
			for _, en := range gm.Entries {
				globalHandles[en.Handle] = true
			}
		}
	}

	ciMode := broker.CIMode()
	var v *vault.Vault
	if !ciMode {
		var vcode int
		if v, vcode = openVault(e); vcode != ExitOK {
			return vcode
		}
	}

	var missing []string
	for _, r := range refs {
		name := r.Declared.Name
		if name == "" {
			name = vault.DefaultBindingName(r.Handle)
		}
		kind := r.Declared.Kind
		if kind == "" {
			kind = vault.BindEnv
		}
		var available bool
		if ciMode {
			_, available = os.LookupEnv(name)
		} else {
			_, getErr := v.Get(r.Handle)
			available = getErr == nil
		}
		flags := ""
		switch {
		case r.FromGlobal:
			flags += "  GLOBAL"
		case globalHandles[r.Handle]:
			flags += "  OVERRIDES-GLOBAL"
		}
		if !available {
			flags += "  MISSING"
			missing = append(missing, r.Handle)
		}
		fprintf(e.stdout, "%-40s %s %s%s\n", r.Handle, kind, name, flags)
	}
	if len(missing) > 0 {
		e.notice("%d of %d effective handle(s) missing in %s", len(missing), len(refs), m.Path)
		return ExitError
	}
	fprintf(e.stdout, "ok: all %d effective handle(s) for %s are available\n", len(refs), m.Path)
	return ExitOK
}

// manifestGlobalToggle writes the project's durable opt-out of the Global
// Manifest. It is deliberately a property of the committed .claudepass.toml
// rather than of the machine: a repo that must never see ambient Secrets
// says so once, in the file its collaborators review, not in a setting one
// developer happens to have set locally.
func manifestGlobalToggle(e *env, args []string) int {
	fs := flag.NewFlagSet("manifest global", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return e.usageErr(err, "cpass manifest global <on|off>")
	}
	if fs.NArg() != 1 || (fs.Arg(0) != "on" && fs.Arg(0) != "off") {
		return e.fail(ExitUsage, "usage: cpass manifest global <on|off>")
	}
	m, code := loadManifest(e)
	if code != ExitOK {
		return code
	}
	m.GlobalDisabled = fs.Arg(0) == "off"
	if err := m.Save(); err != nil {
		return e.failErr(err)
	}
	verb := "enabled"
	if m.GlobalDisabled {
		verb = "disabled"
	}
	fprintf(e.stdout, "%s Global Manifest Handles for %s\n", verb, m.Path)
	return ExitOK
}

func loadManifest(e *env) (*manifest.Manifest, int) {
	p, err := manifest.Find(".")
	if err != nil {
		if errors.Is(err, manifest.ErrNotFound) {
			return nil, e.fail(ExitError, "%v", err)
		}
		return nil, e.failErr(err)
	}
	m, err := manifest.Load(p)
	if err != nil {
		return nil, e.failErr(err)
	}
	return m, ExitOK
}
