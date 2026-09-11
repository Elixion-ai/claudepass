package cli

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"

	"claudepass/internal/broker"
	"claudepass/internal/manifest"
	"claudepass/internal/vault"
)

func init() {
	register(command{"manifest", "declare the Handles a project needs: manifest init|add|check", cmdManifest})
}

func cmdManifest(e *env) int {
	if len(e.args) == 0 {
		return e.fail(ExitUsage, "usage: cpass manifest init | add <handle> [--binding NAME] [--file] | check")
	}
	sub, rest := e.args[0], e.args[1:]
	switch sub {
	case "init":
		return manifestInit(e, rest)
	case "add":
		return manifestAdd(e, rest)
	case "check":
		return manifestCheck(e, rest)
	}
	return e.fail(ExitUsage, "unknown manifest subcommand %q", sub)
}

func manifestInit(e *env, args []string) int {
	fs := flag.NewFlagSet("manifest init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return e.usageErr(err, "cpass manifest init")
	}
	p := filepath.Join(".", manifest.FileName)
	if _, err := os.Stat(p); err == nil {
		return e.fail(ExitError, "%s already exists", p)
	}
	m := &manifest.Manifest{Path: p}
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
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return e.usageErr(err, "cpass manifest add <handle> [--binding NAME] [--file]")
	}
	if len(pos) != 1 {
		return e.fail(ExitUsage, "usage: cpass manifest add <handle> [--binding NAME] [--file]")
	}
	handle := pos[0]
	if err := vault.ValidateHandle(handle); err != nil {
		return e.failErr(err)
	}
	m, code := loadManifest(e)
	if code != ExitOK {
		return code
	}
	entry := manifest.Entry{Handle: handle, Binding: vault.Binding{Name: *binding}}
	if *file {
		entry.Binding.Kind = vault.BindFile
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
	if err := fs.Parse(args); err != nil {
		return e.usageErr(err, "cpass manifest check")
	}
	m, code := loadManifest(e)
	if code != ExitOK {
		return code
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
