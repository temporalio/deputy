// Package surface audits Deputy's internal API surface with go/types, so
// claims about what is reachable are derived from the type checker instead of
// from text matching.
//
// The audit answers four questions:
//
//  1. Which packages under internal/ does no other package import? Their code
//     can still be exercised by their own in-package tests, which makes them
//     invisible to dead-code analysis: the code genuinely is used, by its own
//     test, so an unused-symbol check is right not to flag it.
//  2. Which exported symbols does nothing outside the declaring package
//     reference? Those are unexport candidates, and unexporting is
//     compiler-verified.
//  3. Which exported interfaces is nothing ever declared to accept as a
//     parameter or hold as a field? An interface no signature mentions is not
//     an abstraction anyone depends on.
//  4. Which findings might be reached dynamically (reflection, encoding,
//     interface dispatch, registration by name)? Those look unused to static
//     analysis and are not, so every finding carries the evidence for and
//     against acting on it rather than a bare assertion.
//
// [Analyze] loads a module and returns a [Report]. Command
// internal/surface/cmd renders one.
package surface

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/packages"
)

// loadMode is the narrowest package-loading mode that still yields full type
// information, per-file syntax, and the transitive import graph. Syntax and
// type info are both required: uses are read from the type checker, and the
// interface audit walks declaration syntax to tell a parameter from a field.
const loadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedSyntax |
	packages.NeedTypes |
	packages.NeedTypesInfo |
	packages.NeedImports |
	packages.NeedDeps |
	packages.NeedModule

// Analyze audits the module rooted at dir. It loads every package in the
// module along with its test variants, because a symbol referenced only by
// another package's test file is still referenced, and a package reached only
// by its own test is the case check 1 exists to find.
//
// Analyze returns an error if the module does not load or fails to type-check;
// a partial type graph would make every finding suspect.
func Analyze(ctx context.Context, dir string) (*Report, error) {
	cfg := &packages.Config{
		Context: ctx,
		Mode:    loadMode,
		Dir:     dir,
		Tests:   true,
	}
	loaded, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("load packages in %s: %w", dir, err)
	}
	if len(loaded) == 0 {
		return nil, fmt.Errorf("no packages found in %s", dir)
	}
	if err := loadErrors(loaded); err != nil {
		return nil, err
	}

	prog, err := newProgram(dir, loaded)
	if err != nil {
		return nil, err
	}

	report := &Report{
		Module:   prog.module,
		Audited:  prog.auditedPaths(),
		Packages: prog.unreachablePackages(),
	}
	report.Symbols, report.SymbolTotals = prog.unusedSymbols()
	report.Interfaces, report.InterfaceTotal = prog.unusedInterfaces()
	return report, nil
}

// loadErrors collects the type-checking errors of the loaded graph. It reports
// at most a few, since a broken load usually breaks everything downstream of
// one package.
func loadErrors(roots []*packages.Package) error {
	var msgs []string
	packages.Visit(roots, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			if len(msgs) < 5 {
				msgs = append(msgs, fmt.Sprintf("%s: %s", p.ID, e))
			}
		}
	})
	if len(msgs) == 0 {
		return nil
	}
	return fmt.Errorf("packages failed to load:\n\t%s", strings.Join(msgs, "\n\t"))
}

// program is the type-checked module under audit: the packages that belong to
// it, keyed by the canonical import path that unifies a package with its test
// variants.
type program struct {
	module string

	// pkgs holds every variant of every package in the module under audit,
	// keyed by canonical path. Reference scanning walks all variants; a
	// package's own tests must not count as external use of its exports.
	pkgs map[string][]*variant

	// order is the sorted canonical path list, so output is deterministic.
	order []string

	// dyn is the check 4 evidence: the ways a declaration can be reached
	// without a package naming it. Every check consults it before asserting a
	// finding.
	dyn *dynamic

	fset *token.FileSet
}

// variant is one compilation of a package: the plain package, the same package
// recompiled with its in-package test files, or its external test package.
type variant struct {
	pkg *packages.Package

	// canonical is the import path the variant contributes uses to and
	// declares symbols in. For an external test package (path "…/p_test") it
	// is the tested package's path, so a black-box test is not mistaken for
	// an unrelated package.
	canonical string

	// test reports whether this variant is compiled only for tests, meaning
	// every reference it contributes is a test-only reference.
	test bool

	// externalTest distinguishes the "…_test" black-box package, whose
	// references are test-only and also belong to the tested package itself.
	externalTest bool
}

// newProgram indexes the loaded packages by canonical path, dropping the
// synthetic test-main packages and everything outside the module under audit.
func newProgram(dir string, loaded []*packages.Package) (*program, error) {
	p := &program{pkgs: map[string][]*variant{}, fset: loaded[0].Fset}

	for _, pkg := range loaded {
		if pkg.Module == nil || pkg.Module.Path == "" {
			continue
		}
		if p.module == "" && pkg.Module.Main {
			p.module = pkg.Module.Path
		}
	}
	if p.module == "" {
		return nil, fmt.Errorf("no main module found in %s", dir)
	}

	for _, pkg := range loaded {
		v, ok := classify(pkg, p.module)
		if !ok {
			continue
		}
		p.pkgs[v.canonical] = append(p.pkgs[v.canonical], v)
	}
	if len(p.pkgs) == 0 {
		return nil, fmt.Errorf("no packages of module %s found in %s", p.module, dir)
	}

	p.order = sortedKeys(p.pkgs)
	p.dyn = newDynamic(p)
	return p, nil
}

// classify decides whether a loaded package belongs to the module under audit
// and, if so, which compilation variant it is. The generated "p.test" main
// package is skipped: it is not source anyone maintains.
func classify(pkg *packages.Package, module string) (*variant, bool) {
	if pkg.Types == nil || len(pkg.Syntax) == 0 {
		return nil, false
	}
	path := pkg.PkgPath
	if path != module && !strings.HasPrefix(path, module+"/") {
		return nil, false
	}
	if strings.HasSuffix(path, ".test") {
		return nil, false
	}

	// go/packages labels a test variant's ID with the test binary in
	// brackets; the plain package has no bracket.
	isTestVariant := strings.Contains(pkg.ID, ".test]")
	switch {
	case isTestVariant && strings.HasSuffix(path, "_test"):
		return &variant{
			pkg:          pkg,
			canonical:    strings.TrimSuffix(path, "_test"),
			test:         true,
			externalTest: true,
		}, true
	case isTestVariant:
		return &variant{pkg: pkg, canonical: path, test: true}, true
	default:
		return &variant{pkg: pkg, canonical: path}, true
	}
}

// auditedPaths returns the canonical paths the audit reports findings for:
// packages under internal/, excluding generated code, examples, and the public
// sdk/ (whose exports serve consumers outside this module).
func (p *program) auditedPaths() []string {
	var out []string
	for _, path := range p.order {
		if p.audited(path) {
			out = append(out, path)
		}
	}
	return out
}

// audited reports whether findings in path should be reported. Excluded trees
// still contribute references: a symbol used by sdk/ is used.
func (p *program) audited(path string) bool {
	rel := strings.TrimPrefix(strings.TrimPrefix(path, p.module), "/")
	if rel == "" {
		return false
	}
	if !strings.HasPrefix(rel, "internal/") {
		return false
	}
	for _, skip := range []string{"gen/", "examples/", "sdk/"} {
		if strings.HasPrefix(rel, skip) || strings.Contains(rel, "/"+skip) {
			return false
		}
	}
	return true
}

// plain returns the non-test compilation of a canonical path, which is the
// variant whose declarations form the package's real API. A package whose only
// files are test files has none.
func (p *program) plain(path string) *packages.Package {
	for _, v := range p.pkgs[path] {
		if !v.test {
			return v.pkg
		}
	}
	return nil
}

// variants returns every compilation of every package in the module, in
// deterministic order.
func (p *program) variants() []*variant {
	var out []*variant
	for _, path := range p.order {
		out = append(out, p.pkgs[path]...)
	}
	return out
}

// files yields every syntax tree in the module along with the type info and
// variant it belongs to.
func (p *program) files(yield func(v *variant, file *ast.File) bool) {
	for _, v := range p.variants() {
		for _, f := range v.pkg.Syntax {
			if !yield(v, f) {
				return
			}
		}
	}
}

// position renders a source position for a finding, relative to the module
// root so output is stable across checkouts.
func (p *program) position(pos token.Pos) string {
	if !pos.IsValid() {
		return ""
	}
	at := p.fset.Position(pos)
	return fmt.Sprintf("%s:%d", trimRoot(at.Filename, p.rootHint()), at.Line)
}

// rootHint returns the directory prefix to strip from finding positions. The
// module directory is not recorded on every package, so the shortest module
// root among loaded packages is used.
func (p *program) rootHint() string {
	for _, v := range p.variants() {
		if v.pkg.Module != nil && v.pkg.Module.Dir != "" {
			return v.pkg.Module.Dir
		}
	}
	return ""
}

// origin normalizes a generic instantiation back to the declaration it came
// from, so a reference to Foo[int] counts as a reference to Foo.
func origin(obj types.Object) types.Object {
	switch o := obj.(type) {
	case *types.Func:
		if orig := o.Origin(); orig != nil {
			return orig
		}
	case *types.Var:
		if orig := o.Origin(); orig != nil {
			return orig
		}
	}
	return obj
}
