package surface

import (
	"bytes"
	"context"
	"errors"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages"
)

// fixtureReport audits testdata/fixture once for the whole package. Every test
// below asks the same question of the same immutable module, so loading and
// type-checking it once per test paid for the type checker eight times over and
// bought no coverage.
//
// The context is deliberately not a test's. A value computed once outlives
// whichever test happened to trigger it, so wiring it to that test's
// cancellation would make the shared result depend on run order. The load is
// bounded by the fixture, which is a handful of files, so there is nothing here
// worth interrupting.
var fixtureReport = sync.OnceValues(func() (*Report, error) {
	return Analyze(context.Background(), filepath.Join("testdata", "fixture"))
})

// analyzeFixture returns the shared audit of testdata/fixture, a self-contained
// module whose every package exists to pin one behavior of the audit. Asserting
// against a fixture rather than against Deputy itself means the expectations are
// exact: a wrong answer is a failing diff, not a number nobody can check.
//
// The returned report is shared, so callers must only read it. Sorting a slice
// of it or editing a finding in place would make the suite order-dependent, and
// the failure would land in whichever test ran second.
func analyzeFixture(t *testing.T) *Report {
	t.Helper()
	report, err := fixtureReport()
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
// while still counting as usage (see TestSymbolReachGrading, where the symbol
// each of those trees is the sole referencer of is not reported).
func TestAuditedPackagesExcludeGeneratedAndPublicTrees(t *testing.T) {
	report := analyzeFixture(t)

	want := []string{
		"fixture/internal/aggregator",
		"fixture/internal/awkward_test",
		"fixture/internal/blackbox",
		"fixture/internal/doconly",
		"fixture/internal/ifaces",
		"fixture/internal/initonly",
		"fixture/internal/orphan",
		"fixture/internal/registered",
		"fixture/internal/testonly",
		"fixture/internal/used",
	}
	if diff := cmp.Diff(want, report.Audited); diff != "" {
		t.Errorf("Audited mismatch (-want +got):\n%s", diff)
	}
}

// TestUnreachablePackagesFindTestOnlyReachability covers check 1 and the five
// cases that make it worth having: a package reached only by its own in-package
// test counts as unreachable, so does one reached only by its own black-box test
// package, a package that declares nothing at all does not count, a package whose
// only declaration is func init() or a blank import does count even though its
// package scope is just as empty, and a package whose own import path ends in
// "_test" is one of these packages rather than somebody's external test package.
//
// The want list is the assertion for the awkward ones. internal/doconly must stay
// out of it while internal/initonly and internal/aggregator stay in, which is the
// whole difference between "declares nothing" and "declares nothing the type
// checker files in package scope". The aggregator is the sharper case: its blank
// import is its entire purpose, so nothing importing it means the registrations it
// exists to trigger never run. The TestFiles assertion is where the "_test" path
// case bites: misreading the path moves those test files onto a package that does
// not exist, and the real package's count drops to zero.
func TestUnreachablePackagesFindTestOnlyReachability(t *testing.T) {
	report := analyzeFixture(t)

	want := []string{
		filepath.Join("internal", "aggregator"),
		filepath.Join("internal", "awkward_test"),
		filepath.Join("internal", "blackbox"),
		filepath.Join("internal", "initonly"),
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
		// These two are the only symbols their tree names, which is what makes
		// them a test of the exclusion. Asserting on a symbol main also uses
		// would pass even if the excluded trees were never scanned.
		{"referenced only from sdk/ still counts", "fixture/internal/used", "ForSDKOnly", ReachProduction},
		{"referenced only from examples/ still counts", "fixture/internal/used", "ForExampleOnly", ReachProduction},
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
	// trees: 14 funcs (Used, Local, ForSDKOnly, ForExampleOnly, NamedInString,
	// Orphaned, ForForeignTests, ForOwnBlackBoxTest, Run, Make, RunAnon,
	// RunStringish, RunConstrained, Awkward), 20 types (Never, Stringish, Decoy,
	// Scannable, Tagged, Handled, AnonReached, ConstraintReached, NotAProto,
	// registered.BlankImportedOnly, testonly.Shared, testonly.Decoyed, testonly.Holder,
	// ifaces.Shared plus 6
	// interfaces), and 18 methods (Never.Method, Stringish.String, Decoy.Read,
	// Scannable.Scan, Holder.Shared, AnonReached.Anon,
	// ConstraintReached.Constrained, NotAProto.ProtoReflect, the four Handled
	// methods, plus one per interface). Vars and consts are zero, which also pins that
	// struct fields such as Tagged.Name are not counted as symbols, and that the
	// type declared inside used.localTagged is not one either.
	want := map[SymbolKind]int{
		KindFunc:   14,
		KindType:   20,
		KindMethod: 18,
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

// TestBlankImportIsNotASymbolDoubt pins which question a blank import answers.
// It answers check 1: the package is reached, so it is not an unreachable-package
// finding. It says nothing about the package's exports, because the registration
// a blank import triggers runs inside the package, and nobody who blank-imports it
// can name an export at all. Treating it as a symbol doubt marked the safest
// unexport candidates in the repository as the ones to leave alone.
func TestBlankImportIsNotASymbolDoubt(t *testing.T) {
	report := analyzeFixture(t)

	// main blank-imports this package, so its export is reachable by nobody and
	// carries no other signal: the finding has to come back clean.
	provider, ok := findSymbol(report, "fixture/internal/registered", "BlankImportedOnly")
	if !ok {
		t.Fatal("registered.BlankImportedOnly was not reported")
	}
	if !certain(provider.Doubts) {
		t.Errorf("registered.BlankImportedOnly doubts = %v, want none", provider.Doubts)
	}

	// The other half: being blank-imported still keeps the package itself out of
	// the unreachable-package findings, which is the one thing it does prove.
	for _, got := range report.Packages {
		if strings.HasSuffix(filepath.ToSlash(got.Dir), "internal/registered") {
			t.Errorf("registered was reported unreachable, but main imports it for its side effects")
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
		wantAbsent string
		wantDoubts bool
	}{
		{
			name:      "satisfying fmt.Stringer earns the doubt",
			symbol:    "Stringish.String",
			wantDoubt: "fmt.Stringer",
			// ifaces.RunStringish spells the same contract anonymously, and naming
			// both would restate one fact in every Stringer doubt in the report.
			wantAbsent: "interface{String() string}",
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
		{
			name:       "a standard-library contract no file names still earns the doubt",
			symbol:     "Scannable.Scan",
			wantDoubt:  "database/sql.Scanner",
			wantDoubts: true,
		},
		{
			name:       "a contract the supplemental list omits is derived from the type graph",
			symbol:     "Handled.Handle",
			wantDoubt:  "log/slog.Handler",
			wantDoubts: true,
		},
		{
			// An anonymous interface has no name for any list to hold, so this is
			// the contract that can only ever be derived.
			name:       "an anonymous interface in a signature is a contract too",
			symbol:     "AnonReached.Anon",
			wantDoubt:  "interface{Anon()}",
			wantDoubts: true,
		},
		{
			// A constraint is not a parameter type, so a walk over parameters and
			// results alone never sees it.
			name:       "a generic type constraint is a contract too",
			symbol:     "ConstraintReached.Constrained",
			wantDoubt:  "interface{Constrained()}",
			wantDoubts: true,
		},
		{
			// ProtoReflect() string is not protobuf's contract, and calling the type
			// a registered message would be evidence the audit does not have.
			name:       "protobuf's method name without its signature is not a message",
			symbol:     "NotAProto",
			wantAbsent: "protobuf message",
			wantDoubts: false,
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
			if tt.wantAbsent != "" && slices.ContainsFunc(got.Doubts, func(d string) bool { return strings.Contains(d, tt.wantAbsent) }) {
				t.Errorf("%s doubts = %v, want none mentioning %q", tt.symbol, got.Doubts, tt.wantAbsent)
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

// TestEncodingDoubtBelongsToOneType covers the other half of the encoding
// signal: which object the doubt is about. Only the type whose fields carry the
// tag can be built by a decoder. Matching the doubt on a bare name spreads it to
// every object of that name in any package and of any kind, which fabricates
// dynamic-reachability evidence and keeps the findings it lands on from ever
// being read as certain.
func TestEncodingDoubtBelongsToOneType(t *testing.T) {
	report := analyzeFixture(t)

	const doubt = "encoding-tagged"
	tests := []struct {
		name   string
		pkg    string
		symbol string
		want   bool
	}{
		{
			name:   "the tagged type earns it",
			pkg:    "fixture/internal/testonly",
			symbol: "Shared",
			want:   true,
		},
		{
			name:   "a same-named type in another package does not",
			pkg:    "fixture/internal/ifaces",
			symbol: "Shared",
			want:   false,
		},
		{
			name:   "a method of that name in that same package does not",
			pkg:    "fixture/internal/testonly",
			symbol: "Holder.Shared",
			want:   false,
		},
		{
			name:   "a tagged type declared inside a function lends nothing to the name it shadows",
			pkg:    "fixture/internal/used",
			symbol: "Never",
			want:   false,
		},
		{
			// `notjson:"name"` contains `json:"`. Only a real tag key counts, or the
			// doubt attaches to types no codec can reach.
			name:   "a tag key that merely ends in a codec name does not earn it",
			pkg:    "fixture/internal/testonly",
			symbol: "Decoyed",
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := findSymbol(report, tt.pkg, tt.symbol)
			if !ok {
				t.Fatalf("%s.%s was not reported", tt.pkg, tt.symbol)
			}
			has := slices.ContainsFunc(got.Doubts, func(d string) bool { return strings.Contains(d, doubt) })
			if has != tt.want {
				t.Errorf("%s.%s doubts = %v, want the %q reason present = %v", tt.pkg, tt.symbol, got.Doubts, doubt, tt.want)
			}
		})
	}
}

// TestDispatchContractsResolveToInterfaces checks the audit's one
// hand-maintained list against the packages it names. A name filed under the
// wrong package resolves to nothing, the contract is never registered, and every
// method reached only through it is then reported as certainly unused: the tool
// invents evidence of deadness. Nothing about that failure is visible in the
// output, which is why the list is verified directly instead of trusted.
func TestDispatchContractsResolveToInterfaces(t *testing.T) {
	paths := slices.Sorted(maps.Keys(dispatchContracts))
	loaded, err := packages.Load(&packages.Config{
		Context: t.Context(),
		Mode:    packages.NeedName | packages.NeedTypes,
	}, paths...)
	if err != nil {
		t.Fatalf("load dispatch contract packages: %v", err)
	}

	seen := map[string]bool{}
	for _, pkg := range loaded {
		names, ok := dispatchContracts[pkg.PkgPath]
		if !ok {
			t.Errorf("loaded %s, which dispatchContracts does not name", pkg.PkgPath)
			continue
		}
		seen[pkg.PkgPath] = true
		if pkg.Types == nil {
			t.Errorf("%s did not type-check, so its contracts cannot be verified", pkg.PkgPath)
			continue
		}
		for _, name := range names {
			obj := pkg.Types.Scope().Lookup(name)
			if obj == nil {
				t.Errorf("%s.%s does not exist, so that contract is never registered", pkg.PkgPath, name)
				continue
			}
			if _, ok := obj.Type().Underlying().(*types.Interface); !ok {
				t.Errorf("%s.%s underlying type is %s, want an interface", pkg.PkgPath, name, obj.Type().Underlying())
			}
		}
	}
	for _, path := range paths {
		if !seen[path] {
			t.Errorf("%s did not load, so its contracts were not verified", path)
		}
	}
}

// TestForeignContractLookupIsLoud pins the behavior that makes the list above
// worth verifying at all: a lookup that fails is an error, not a skip. It also
// pins the case that must stay quiet, since a module is not required to depend
// on every package the list names.
func TestForeignContractLookupIsLoud(t *testing.T) {
	loaded, err := packages.Load(&packages.Config{
		Context: t.Context(),
		Mode:    packages.NeedName | packages.NeedTypes | packages.NeedImports | packages.NeedDeps,
	}, "fmt")
	if err != nil {
		t.Fatalf("load fmt: %v", err)
	}

	d := &dynamic{byMethod: map[string][]contract{}}
	err = d.addForeignContracts(loaded, map[string][]string{"fmt": {"Stringer", "Sprintf", "Absent"}})
	if err == nil {
		t.Fatal("addForeignContracts with a misfiled contract returned nil, so a wrong list stays invisible")
	}
	for _, want := range []string{"fmt.Absent", "fmt.Sprintf"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to name %s", err, want)
		}
	}
	if _, ok := d.byMethod["String"]; !ok {
		t.Error("the contracts that did resolve were dropped, so one bad entry costs the rest")
	}

	// A package outside the load graph is the ordinary case, not a defect.
	quiet := &dynamic{byMethod: map[string][]contract{}}
	if err := quiet.addForeignContracts(loaded, map[string][]string{"database/sql": {"Absent"}}); err != nil {
		t.Errorf("addForeignContracts for a package the graph lacks = %v, want nil", err)
	}
}

// TestOversizedAssetIsReportedNotSilentlyDropped pins the audit's account of its
// own coverage. The asset scan is bounded, which is fine; dropping a file without
// saying so is not, because that file is exactly where the only mention of a
// reflectively consumed symbol could be, and the report would then present a live
// symbol as safe to unexport with the evidence knowingly unread.
//
// The whole chain is exercised rather than addAssets alone. The recording is
// worthless if it does not reach the report, and losing the one line that carries
// it there would leave every unit-level assertion passing.
func TestOversizedAssetIsReportedNotSilentlyDropped(t *testing.T) {
	dir := t.TempDir()
	mustWrite := func(name string, data []byte) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	mustWrite("go.mod", []byte("module gap\n\ngo 1.26\n"))
	mustWrite(filepath.Join("internal", "thing", "thing.go"), []byte("package thing\n\n// Thing is here to give the module a surface.\nfunc Thing() {}\n"))
	mustWrite("small.cel", []byte("NamedInASmallAsset"))
	// One byte past the cap, and the name is at the front so a partial read would
	// still have found it. Only the limit can explain its absence.
	oversized := bytes.Repeat([]byte("x"), maxAssetBytes+1)
	copy(oversized, []byte("NamedInAnOversizedAsset "))
	mustWrite("big.json", oversized)

	report, err := Analyze(t.Context(), dir)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	var found *Unexamined
	for i, gap := range report.Unexamined {
		if gap.Path == "big.json" {
			found = &report.Unexamined[i]
		}
	}
	if found == nil {
		t.Fatalf("Unexamined = %v, want an entry for big.json: the run skipped it and said nothing", report.Unexamined)
	}
	if !strings.Contains(found.Reason, "asset limit") {
		t.Errorf("Unexamined reason = %q, want it to name the limit that applied", found.Reason)
	}

	// The other half: the limit must not be an excuse to skip ordinary assets, or
	// every finding would carry a caveat and the channel would mean nothing.
	for _, gap := range report.Unexamined {
		if gap.Path == "small.cel" {
			t.Errorf("small.cel was reported unexamined (%s), but it is well under the limit", gap.Reason)
		}
	}
}

// TestUnwalkableDirectoryIsReportedNotSilentlySkipped covers the largest way the
// asset scan can miss evidence. A directory it cannot enter costs every file
// underneath it, not one, and WalkDir reports that as an error the callback is
// free to swallow. Swallowing it leaves the report asserting a coverage it does
// not have, which is the same defect as the size limit and worth more.
func TestUnwalkableDirectoryIsReportedNotSilentlySkipped(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "unreadable")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "hidden.cel"), []byte("NamedOnlyInAnUnreadableTree"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "visible.cel"), []byte("NamedInAReadableTree"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Skipf("cannot make a directory unreadable here: %v", err)
	}
	// Restore before t.TempDir's own cleanup, which is registered earlier and so
	// runs after this one.
	t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })
	if _, err := os.ReadDir(sub); err == nil {
		t.Skip("directory permissions are not enforced for this user, so the walk cannot fail")
	}

	d := &dynamic{tokens: map[string]string{}}
	if err := d.addAssets(t.Context(), dir); err != nil {
		t.Fatalf("addAssets error = %v, want nil: one unreadable tree must not end the scan", err)
	}

	if _, ok := d.tokens["NamedOnlyInAnUnreadableTree"]; ok {
		t.Fatal("the unreadable tree was somehow read, so this test proves nothing")
	}
	var found *Unexamined
	for i, gap := range d.unexamined {
		if gap.Path == "unreadable" {
			found = &d.unexamined[i]
		}
	}
	if found == nil {
		t.Fatalf("unexamined = %v, want an entry for the unreadable directory", d.unexamined)
	}
	if !strings.Contains(found.Reason, "nothing under it was scanned") {
		t.Errorf("reason = %q, want it to say the whole subtree went unread", found.Reason)
	}

	// The rest of the tree still has to be scanned, or one bad directory would
	// quietly cost the entire run's evidence.
	if _, ok := d.tokens["NamedInAReadableTree"]; !ok {
		t.Errorf("tokens = %v, want the readable sibling still scanned", d.tokens)
	}
}

// TestAssetScanHonorsCancellation pins the one phase that can run long after
// the package load has finished. A signal-backed context has to be able to stop
// the asset walk, or an audit interrupted on a large repository keeps reading
// files and then prints a report for a run the user asked to end.
//
// The live case is half the test: a scan that stops for a context nobody
// canceled would satisfy the assertion above while destroying the evidence
// every "named as a string" doubt rests on.
func TestAssetScanHonorsCancellation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.cel"), []byte("NamedOnlyInAnAsset"), 0o600); err != nil {
		t.Fatalf("write asset: %v", err)
	}

	tests := []struct {
		name     string
		cancel   bool
		wantErr  error
		wantToks int
	}{
		{name: "canceled before the walk", cancel: true, wantErr: context.Canceled, wantToks: 0},
		{name: "live context scans the tree", cancel: false, wantErr: nil, wantToks: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.cancel {
				cancel()
			}

			d := &dynamic{tokens: map[string]string{}}
			err := d.addAssets(ctx, dir)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("addAssets error = %v, want %v", err, tt.wantErr)
			}
			if got := len(d.tokens); got != tt.wantToks {
				t.Errorf("tokens = %d, want %d: %v", got, tt.wantToks, d.tokens)
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
