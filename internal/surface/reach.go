package surface

import (
	"bufio"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

// unreachablePackages implements check 1: packages under audit that no other
// package in the module imports.
//
// Import edges are collected from every compilation variant, so a package
// imported only by another package's test file counts as reachable (and is
// reported as such by the symbol check, not here). What remains is a package
// nothing reaches: its code can still be exercised by its own in-package
// tests, which is exactly why an unused-symbol analyzer will not flag it.
func (p *program) unreachablePackages() []PackageFinding {
	importers := map[string]map[string]bool{}
	add := func(target, importer string) {
		if target == importer {
			return
		}
		if importers[target] == nil {
			importers[target] = map[string]bool{}
		}
		importers[target][importer] = true
	}
	for _, v := range p.variants() {
		for _, imp := range sortedKeys(v.pkg.Imports) {
			// A test variant importing its own package is not an outside
			// importer; neither is a package importing itself.
			add(v.pkg.Imports[imp].PkgPath, v.canonical)
		}
		// Files this platform's build constraints exclude are never
		// type-checked, so their imports are missing from the graph above. A
		// package imported only from a linux-only file is reachable; auditing
		// on another platform must not call it dead.
		for _, path := range constrainedImports(v.pkg) {
			add(path, v.canonical)
		}
	}

	var out []PackageFinding
	for _, path := range p.auditedPaths() {
		if len(importers[path]) > 0 {
			continue
		}
		plain := p.plain(path)
		if plain == nil {
			continue
		}
		// A main package is reached by being built, not by being imported.
		if plain.Name == "main" {
			continue
		}
		// A documentation-only package (a doc.go introducing a subtree, with no
		// declarations at all) has nothing to import. Reporting it as
		// unreachable would be true and useless.
		if plain.Types.Scope().Len() == 0 {
			continue
		}

		f := PackageFinding{
			Path:      path,
			Dir:       p.packageDir(path),
			Lines:     countCode(plain.GoFiles),
			TestFiles: p.testFileCount(path),
		}
		f.Doubts = p.dyn.packageDoubts(path)
		out = append(out, f)
	}
	return out
}

// constrainedImports returns the import paths named by files the build
// constraints excluded from this package on the current platform. Only the
// import block is parsed: the rest of such a file cannot be type-checked here
// anyway, and the import edge is all reachability needs.
func constrainedImports(pkg *packages.Package) []string {
	if len(pkg.IgnoredFiles) == 0 {
		return nil
	}
	var out []string
	for _, name := range pkg.IgnoredFiles {
		if filepath.Ext(name) != ".go" {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			continue
		}
		for _, imp := range file.Imports {
			if path, err := strconv.Unquote(imp.Path.Value); err == nil {
				out = append(out, path)
			}
		}
	}
	return out
}

// packageDir returns the package directory relative to the module root, taken
// from a real file path rather than inferred from the import path.
func (p *program) packageDir(path string) string {
	plain := p.plain(path)
	if plain == nil || len(plain.GoFiles) == 0 {
		return ""
	}
	return filepath.ToSlash(trimRoot(filepath.Dir(plain.GoFiles[0]), p.root))
}

// testFileCount counts the package's test files across its test variants.
func (p *program) testFileCount(path string) int {
	seen := map[string]bool{}
	for _, v := range p.pkgs[path] {
		if !v.test {
			continue
		}
		for _, f := range v.pkg.GoFiles {
			if strings.HasSuffix(f, "_test.go") {
				seen[f] = true
			}
		}
	}
	return len(seen)
}

// trimRoot makes an absolute path relative to root, leaving it alone if it is
// not under root.
func trimRoot(path, root string) string {
	if root == "" {
		return path
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return path
	}
	return rel
}

// countCode counts lines that are neither blank nor comment-only across the
// given files, which approximates the code a package would take with it. Files
// that cannot be read are skipped rather than failing the audit.
func countCode(files []string) int {
	var n int
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			continue
		}
		var inBlock bool
		scan := bufio.NewScanner(f)
		scan.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scan.Scan() {
			line := strings.TrimSpace(scan.Text())
			switch {
			case inBlock:
				if i := strings.Index(line, "*/"); i >= 0 {
					inBlock = false
					line = strings.TrimSpace(line[i+2:])
					if line != "" {
						n++
					}
				}
			case line == "":
			case strings.HasPrefix(line, "//"):
			case strings.HasPrefix(line, "/*"):
				if !strings.Contains(line, "*/") {
					inBlock = true
				}
			default:
				n++
			}
		}
		f.Close()
	}
	return n
}
