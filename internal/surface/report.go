package surface

import (
	"maps"
	"slices"
	"strconv"
)

// Report is the result of one audit. Its zero value is an empty report: no
// module, no findings.
type Report struct {
	// Module is the import path of the audited module.
	Module string

	// Audited lists the canonical import paths findings are reported for.
	// Packages outside this list still contribute references.
	Audited []string

	// Packages holds check 1: packages no other package imports.
	Packages []PackageFinding

	// Symbols holds check 2: exported symbols nothing outside the declaring
	// package references.
	Symbols []SymbolFinding

	// SymbolTotals counts the exported symbols examined, per kind, so a
	// finding count can be read as a fraction of the surface.
	SymbolTotals map[SymbolKind]int

	// Interfaces holds check 3: exported interfaces no signature accepts as a
	// parameter and no struct holds as a field.
	Interfaces []InterfaceFinding

	// InterfaceTotal counts the exported interfaces examined.
	InterfaceTotal int

	// Constrained lists the Go files this platform's build constraints excluded
	// from the load, relative to the module root. Nothing in them is
	// type-checked, so a reference made only from one of them is invisible to
	// every check and any finding could in principle be wrong because of it.
	// Auditing on another platform, or with the relevant tags, closes the gap.
	Constrained []string
}

// Reach describes how far a declaration's references travel. It is the axis
// every finding is graded on: the further a reference travels, the less
// actionable the finding.
type Reach int

const (
	// ReachNone means nothing outside the declaring package references the
	// declaration, in test files or otherwise.
	ReachNone Reach = iota

	// ReachOwnTest means the only outside references come from the declaring
	// package's own black-box test package ("…_test"). Unexporting requires
	// moving those tests in-package first.
	ReachOwnTest

	// ReachForeignTest means the only outside references come from test files
	// of other packages. The export exists for tests alone.
	ReachForeignTest

	// ReachProduction means non-test code outside the declaring package
	// references the declaration. Not reported as a finding.
	ReachProduction
)

// MarshalJSON writes the reach label rather than its ordinal, so a JSON report
// is readable without the constant table.
func (r Reach) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(r.String())), nil
}

// String implements [fmt.Stringer] with the label used in rendered reports.
func (r Reach) String() string {
	switch r {
	case ReachNone:
		return "unreferenced"
	case ReachOwnTest:
		return "own-test-only"
	case ReachForeignTest:
		return "foreign-test-only"
	case ReachProduction:
		return "referenced"
	default:
		return "unknown"
	}
}

// SymbolKind is the sort of declaration a symbol finding describes.
type SymbolKind string

// The symbol kinds the audit distinguishes. Methods are counted apart from
// package-level declarations because interface dispatch can reach a method
// without naming it.
const (
	KindFunc   SymbolKind = "func"
	KindType   SymbolKind = "type"
	KindVar    SymbolKind = "var"
	KindConst  SymbolKind = "const"
	KindMethod SymbolKind = "method"
)

// PackageFinding is a package under audit that no other package imports.
type PackageFinding struct {
	// Path is the canonical import path.
	Path string

	// Dir is the package directory, relative to the module root.
	Dir string

	// Lines counts non-blank, non-comment lines in the package's non-test
	// files: what would be removed if the package went away.
	Lines int

	// TestFiles counts the package's test files. A package with tests and no
	// importers is the case dead-code analysis cannot see: its code is used,
	// by its own test.
	TestFiles int

	// Doubts explains why the finding may be wrong. Empty means the tool found
	// no reason to doubt it.
	Doubts []string
}

// SymbolFinding is an exported symbol whose references never leave its
// declaring package, or leave it only through test files.
type SymbolFinding struct {
	// Package is the canonical import path that declares the symbol.
	Package string

	// Name is the symbol name, qualified by receiver type for a method.
	Name string

	// Kind is the sort of declaration.
	Kind SymbolKind

	// Position is the declaration site, as "path/to/file.go:line".
	Position string

	// Reach is how far the symbol's references travel.
	Reach Reach

	// Doubts explains why the finding may be wrong.
	Doubts []string
}

// InterfaceFinding is an exported interface that no signature accepts as a
// parameter and no struct holds as a field.
type InterfaceFinding struct {
	// Package is the canonical import path that declares the interface.
	Package string

	// Name is the interface name.
	Name string

	// Position is the declaration site, as "path/to/file.go:line".
	Position string

	// Methods counts the interface's method set, including embedded methods.
	Methods int

	// Roles lists the type positions the interface does appear in, such as a
	// function result or a type assertion. An interface with no roles at all
	// is named nowhere but its own declaration.
	Roles []string

	// Reach is how far references to the interface name travel, which
	// separates "unused abstraction" from "used, but never as a dependency".
	Reach Reach

	// Doubts explains why the finding may be wrong.
	Doubts []string
}

// sortedKeys returns a map's keys in ascending order, for deterministic output.
func sortedKeys[K ~string, V any](m map[K]V) []K {
	return slices.Sorted(maps.Keys(m))
}
