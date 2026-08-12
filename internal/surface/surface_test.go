package surface

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// analyzeFixture audits testdata/fixture, a self-contained module whose every
// package exists to pin one behavior of the audit. Asserting against a fixture
// rather than against Deputy itself means the expectations are exact: a wrong
// answer is a failing diff, not a number nobody can check.
func analyzeFixture(t *testing.T) *Report {
	t.Helper()
	report, err := Analyze(t.Context(), filepath.Join("testdata", "fixture"))
	if err != nil {
		t.Fatalf("Analyze(testdata/fixture) error: %v", err)
	}
	if report.Module != "fixture" {
		t.Fatalf("Module = %q, want %q", report.Module, "fixture")
	}
	return report
}

// TestAuditedPackagesExcludeGeneratedAndPublicTrees pins the exclusions: only
// packages under internal/ are candidates, generated code under internal/ is
// skipped even so, and the module-root sdk/ and examples/ trees are excluded
// while still counting as usage (see TestSymbolReachGrading, where a symbol
// referenced only from sdk/ is not reported).
func TestAuditedPackagesExcludeGeneratedAndPublicTrees(t *testing.T) {
	report := analyzeFixture(t)

	want := []string{
		"fixture/internal/blackbox",
		"fixture/internal/doconly",
		"fixture/internal/ifaces",
		"fixture/internal/orphan",
		"fixture/internal/testonly",
		"fixture/internal/used",
	}
	if diff := cmp.Diff(want, report.Audited); diff != "" {
		t.Errorf("Audited mismatch (-want +got):\n%s", diff)
	}
}

// TestUnreachablePackagesFindTestOnlyReachability covers check 1 and the three
// cases that make it worth having: a package reached only by its own in-package
// test counts as unreachable, so does one reached only by its own black-box test
// package, and a package that declares nothing does not count at all.
func TestUnreachablePackagesFindTestOnlyReachability(t *testing.T) {
	report := analyzeFixture(t)

	want := []string{
		filepath.Join("internal", "blackbox"),
		filepath.Join("internal", "orphan"),
	}
	if diff := cmp.Diff(want, report.UnreachableDirs()); diff != "" {
		t.Fatalf("unreachable packages mismatch (-want +got):\n%s", diff)
	}
	for _, got := range report.Packages {
		if got.TestFiles != 1 {
			t.Errorf("%s TestFiles = %d, want 1: the finding's whole point is that a test reaches the code", got.Dir, got.TestFiles)
		}
		if got.Lines != 2 {
			t.Errorf("%s Lines = %d, want 2 (the package clause and the func)", got.Dir, got.Lines)
		}
		if !certain(got.Doubts) {
			t.Errorf("%s Doubts = %v, want none", got.Dir, got.Doubts)
		}
	}
}

// TestSymbolReachGrading covers check 2: which references count as leaving the
// declaring package, and which do not.
func TestSymbolReachGrading(t *testing.T) {
	report := analyzeFixture(t)

	tests := []struct {
		name string
		pkg  string
		sym  string
		want Reach // ReachProduction means "must not be reported at all"
	}{
		{"referenced by main", "fixture/internal/used", "Used", ReachProduction},
		{"referenced only from an excluded tree still counts", "fixture/internal/used", "Used", ReachProduction},
		{"in-package test does not count as outside use", "fixture/internal/used", "Local", ReachNone},
		{"unreferenced type", "fixture/internal/used", "Never", ReachNone},
		{"unreferenced method", "fixture/internal/used", "Never.Method", ReachNone},
		{"another package's test file counts as a reference", "fixture/internal/testonly", "ForForeignTests", ReachForeignTest},
		{"own black-box test package", "fixture/internal/blackbox", "ForOwnBlackBoxTest", ReachOwnTest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := findSymbol(report, tt.pkg, tt.sym)
			if tt.want == ReachProduction {
				if ok {
					t.Fatalf("%s.%s was reported with reach %s, want no finding", tt.pkg, tt.sym, got.Reach)
				}
				return
			}
			if !ok {
				t.Fatalf("%s.%s was not reported, want reach %s", tt.pkg, tt.sym, tt.want)
			}
			if got.Reach != tt.want {
				t.Errorf("%s.%s reach = %s, want %s", tt.pkg, tt.sym, got.Reach, tt.want)
			}
			if got.Position == "" {
				t.Error("Position is empty, so the finding cannot be acted on")
			}
		})
	}
}

// TestSymbolTotalsCountTheWholeSurface guards the denominator: a findings count
// is only meaningful against the surface it was drawn from.
func TestSymbolTotalsCountTheWholeSurface(t *testing.T) {
	report := analyzeFixture(t)

	// Every exported declaration under internal/, and nothing from the excluded
	// trees: 8 funcs (Used, Local, NamedInString, Orphaned, ForForeignTests,
	// ForOwnBlackBoxTest, Run, Make), 10 types (Never, Stringish, Decoy, Tagged
	// plus 6 interfaces), and 9 methods (Never.Method, Stringish.String,
	// Decoy.Read plus one per interface). Vars and consts are zero, which also
	// pins that struct fields such as Tagged.Name are not counted as symbols.
	want := map[SymbolKind]int{
		KindFunc:   8,
		KindType:   10,
		KindMethod: 9,
		KindVar:    0,
		KindConst:  0,
	}
	for kind, n := range want {
		if got := report.SymbolTotals[kind]; got != n {
			t.Errorf("SymbolTotals[%s] = %d, want %d", kind, got, n)
		}
	}
	for _, f := range report.Symbols {
		for _, excluded := range []string{"/internal/gen/", "/sdk", "/examples/"} {
			if strings.Contains(f.Package, excluded) {
				t.Errorf("reported %s.%s from the excluded %s tree", f.Package, f.Name, excluded)
			}
		}
	}
}

// TestDynamicDoubtOnNameInStringLiteral covers check 4: a symbol whose name
// appears as a string is reported with the reason it might be reached by name,
// instead of being asserted dead.
func TestDynamicDoubtOnNameInStringLiteral(t *testing.T) {
	report := analyzeFixture(t)

	named, ok := findSymbol(report, "fixture/internal/used", "NamedInString")
	if !ok {
		t.Fatal("NamedInString was not reported")
	}
	if certain(named.Doubts) {
		t.Error("NamedInString has no doubts, want the string-literal reason")
	}
	if !slices.ContainsFunc(named.Doubts, func(d string) bool { return strings.Contains(d, "string literal") }) {
		t.Errorf("Doubts = %v, want one naming the string literal", named.Doubts)
	}

	// The doubt must be specific: a symbol whose name appears nowhere must come
	// back clean, or every finding would carry it.
	never, ok := findSymbol(report, "fixture/internal/used", "Never")
	if !ok {
		t.Fatal("Never was not reported")
	}
	if !certain(never.Doubts) {
		t.Errorf("Never.Doubts = %v, want none", never.Doubts)
	}
}

// TestUnusedInterfacesDistinguishDependencyFromMention covers check 3: only a
// parameter or a field makes an interface something callers depend on.
func TestUnusedInterfacesDistinguishDependencyFromMention(t *testing.T) {
	report := analyzeFixture(t)

	if report.InterfaceTotal != 6 {
		t.Errorf("InterfaceTotal = %d, want 6", report.InterfaceTotal)
	}

	var got []string
	roles := map[string][]string{}
	for _, f := range report.Interfaces {
		got = append(got, f.Name)
		roles[f.Name] = f.Roles
	}
	want := []string{"Bare", "Returned", "SelfAccepting"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("interface findings mismatch (-want +got):\n%s", diff)
	}

	// The roles explain each finding, so they have to be right too.
	wantRoles := map[string][]string{
		"Bare":          {roleAssertion},
		"Returned":      {roleResult},
		"SelfAccepting": {roleMethodParam},
	}
	if diff := cmp.Diff(wantRoles, roles); diff != "" {
		t.Errorf("interface roles mismatch (-want +got):\n%s", diff)
	}
}

// TestDispatchDoubtRequiresImplementingTheInterface covers the part of check 4
// that decides whether a method can be reached without being named. The doubt is
// earned by satisfying an interface, not by sharing a method name with one:
// otherwise every String, Read, or Close would carry it and the signal would be
// worthless.
func TestDispatchDoubtRequiresImplementingTheInterface(t *testing.T) {
	report := analyzeFixture(t)

	tests := []struct {
		name       string
		symbol     string
		wantDoubt  string
		wantDoubts bool
	}{
		{
			name:       "satisfying fmt.Stringer earns the doubt",
			symbol:     "Stringish.String",
			wantDoubt:  "fmt.Stringer",
			wantDoubts: true,
		},
		{
			name:       "sharing a name without the signature does not",
			symbol:     "Decoy.Read",
			wantDoubts: false,
		},
		{
			name:       "a method no interface declares does not",
			symbol:     "Never.Method",
			wantDoubts: false,
		},
		{
			name:       "an encoding tag makes the type decoder-reachable",
			symbol:     "Tagged",
			wantDoubt:  "encoding-tagged",
			wantDoubts: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := findSymbol(report, "fixture/internal/used", tt.symbol)
			if !ok {
				t.Fatalf("%s was not reported", tt.symbol)
			}
			if hasDoubts := !certain(got.Doubts); hasDoubts != tt.wantDoubts {
				t.Fatalf("%s doubts = %v, want any = %v", tt.symbol, got.Doubts, tt.wantDoubts)
			}
			if tt.wantDoubt == "" {
				return
			}
			if !slices.ContainsFunc(got.Doubts, func(d string) bool { return strings.Contains(d, tt.wantDoubt) }) {
				t.Errorf("%s doubts = %v, want one mentioning %q", tt.symbol, got.Doubts, tt.wantDoubt)
			}
		})
	}
}

// findSymbol looks up a reported symbol by package and name.
func findSymbol(r *Report, pkg, name string) (SymbolFinding, bool) {
	for _, f := range r.Symbols {
		if f.Package == pkg && f.Name == name {
			return f, true
		}
	}
	return SymbolFinding{}, false
}
