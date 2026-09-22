package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

// TestInterceptBypassClosesVault is a regression test for CLA-60:
// interceptBypass opens a Vault via broker.OpenVault() on the `!!` bypass
// path but, unlike every other Vault-opening call site in this codebase
// (cmdIntercept's own normal path, cmdAdd/Ls/Rm/Mv, cmdCapture/Exposed/
// RotateDone/MarkExposed, cmdImport, manifestCheck, warnUnknownGlobal, both
// MCP tool call sites, cmdInit/cmdUnlock's one-off opens, and
// broker.Resolve), never deferred v.Close() -- leaving the unlock key and
// data key resident and un-zeroed in this process's memory for the rest of
// its life instead of zeroed as soon as the bypass write is done.
//
// Vault.Close only zeroes vault.Vault's unexported key/dataKey fields, and
// interceptBypass does not return or otherwise expose the *vault.Vault it
// opens, so there is no black-box way for a test in this package (or any
// package other than vault itself) to observe whether Close ran. This test
// instead parses interceptcmd.go's own source and confirms interceptBypass
// still opens and closes the Vault in the same function, so a future edit
// that drops the defer (or renames the call so it stops matching) fails
// loudly here rather than silently reintroducing CLA-60.
func TestInterceptBypassClosesVault(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "interceptcmd.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var fn *ast.FuncDecl
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "interceptBypass" {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("interceptBypass not found in interceptcmd.go; update this test if it was renamed")
	}

	// Find the identifier a `broker.OpenVault()` call result is assigned
	// to, e.g. `v, err := broker.OpenVault()`.
	var vaultVar string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "OpenVault" {
			return true
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok {
			vaultVar = id.Name
		}
		return true
	})
	if vaultVar == "" {
		t.Fatal("interceptBypass no longer calls broker.OpenVault() in a way this test recognises; update it")
	}

	closesVault := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		defr, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		sel, ok := defr.Call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == vaultVar && sel.Sel.Name == "Close" {
			closesVault = true
		}
		return true
	})
	if !closesVault {
		t.Fatalf("interceptBypass opens a Vault (%s) via broker.OpenVault() but never defers %s.Close(); "+
			"the unlock key and data key stay resident in memory for the rest of this process's life instead "+
			"of being zeroed as soon as the bypass write is done (CLA-60)", vaultVar, vaultVar)
	}
}
