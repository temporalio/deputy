package surface

import (
	"fmt"
	"io"
	"strings"
)

// Text writes a human-readable report to w. Findings the audit has reason to
// doubt are printed with those reasons attached, so the reader can tell a
// mechanical unexport from a judgment call.
func (r *Report) Text(w io.Writer) error {
	b := &strings.Builder{}

	fmt.Fprintf(b, "module %s: audited %d packages\n\n", r.Module, len(r.Audited))

	certainPkgs, doubtedPkgs := splitPackages(r.Packages)
	lines := totalLines(r.Packages)
	fmt.Fprintf(b, "1. packages no other package imports: %d of %d (%d lines, %d certain, %d doubted)\n",
		len(r.Packages), len(r.Audited), lines, len(certainPkgs), len(doubtedPkgs))
	for _, f := range r.Packages {
		fmt.Fprintf(b, "   %s (%d lines, %d test files)\n", f.Dir, f.Lines, f.TestFiles)
		if f.TestFiles > 0 {
			fmt.Fprintf(b, "      reached only by its own tests, so unused-symbol analysis cannot see it\n")
		}
		writeDoubts(b, f.Doubts)
	}

	total := 0
	for _, n := range r.SymbolTotals {
		total += n
	}
	byReach := map[Reach]int{}
	byKind := map[SymbolKind]int{}
	certainSymbols := 0
	for _, f := range r.Symbols {
		byReach[f.Reach]++
		byKind[f.Kind]++
		if certain(f.Doubts) {
			certainSymbols++
		}
	}
	fmt.Fprintf(b, "\n2. exported symbols never referenced outside their package: %d of %d\n", len(r.Symbols), total)
	fmt.Fprintf(b, "   surface by kind:  %s\n", countsByKind(r.SymbolTotals))
	fmt.Fprintf(b, "   findings by kind: %s\n", countsByKind(byKind))
	fmt.Fprintf(b, "   %s: %d, %s: %d, %s: %d\n",
		ReachNone, byReach[ReachNone], ReachOwnTest, byReach[ReachOwnTest], ReachForeignTest, byReach[ReachForeignTest])
	fmt.Fprintf(b, "   no reason to doubt: %d; some reason to doubt: %d\n", certainSymbols, len(r.Symbols)-certainSymbols)

	fmt.Fprintf(b, "\n3. exported interfaces never a parameter and never a field: %d of %d\n",
		len(r.Interfaces), r.InterfaceTotal)
	for _, f := range r.Interfaces {
		roles := "named nowhere else"
		if len(f.Roles) > 0 {
			roles = "appears as " + strings.Join(f.Roles, ", ")
		}
		fmt.Fprintf(b, "   %s.%s (%d methods, %s, %s)\n", short(f.Package), f.Name, f.Methods, f.Reach, roles)
		writeDoubts(b, f.Doubts)
	}

	fmt.Fprintf(b, "\n4. dynamic reachability: %d of %d symbol findings and %d of %d interface findings carry a doubt\n",
		len(r.Symbols)-certainSymbols, len(r.Symbols), doubted(r.Interfaces), len(r.Interfaces))

	if len(r.Constrained) > 0 {
		fmt.Fprintf(b, "\ncaveat: %d file(s) excluded by this platform's build constraints were not\n", len(r.Constrained))
		fmt.Fprintf(b, "type-checked, so references they make are invisible to every check above:\n")
		for _, name := range r.Constrained {
			fmt.Fprintf(b, "   %s\n", name)
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// Detail writes the per-symbol findings for one package, which is what a
// contributor reads before unexporting anything. The package is matched on whole
// path elements: a bare suffix match would silently interleave the findings of
// "internal/vmimage" and "internal/container/image" under one query.
func (r *Report) Detail(w io.Writer, pkg string) error {
	b := &strings.Builder{}
	var found bool
	pkg = strings.Trim(pkg, "/")
	for _, f := range r.Symbols {
		if f.Package != pkg && !strings.HasSuffix(f.Package, "/"+pkg) {
			continue
		}
		found = true
		fmt.Fprintf(b, "%s\t%s\t%s\t%s\n", f.Position, f.Kind, f.Name, f.Reach)
		writeDoubts(b, f.Doubts)
	}
	if !found {
		fmt.Fprintf(b, "no findings for packages matching %q\n", pkg)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// certain reports whether a finding carries no doubts.
func certain(doubts []string) bool { return len(doubts) == 0 }

// writeDoubts prints a finding's doubts, indented under it.
func writeDoubts(b *strings.Builder, doubts []string) {
	for _, d := range doubts {
		fmt.Fprintf(b, "      doubt: %s\n", d)
	}
}

// splitPackages partitions package findings by whether the audit found reason to
// doubt them.
func splitPackages(findings []PackageFinding) (sure, unsure []PackageFinding) {
	for _, f := range findings {
		if certain(f.Doubts) {
			sure = append(sure, f)
		} else {
			unsure = append(unsure, f)
		}
	}
	return sure, unsure
}

// totalLines sums the code lines of the given package findings.
func totalLines(findings []PackageFinding) int {
	var n int
	for _, f := range findings {
		n += f.Lines
	}
	return n
}

// doubted counts interface findings carrying at least one doubt.
func doubted(findings []InterfaceFinding) int {
	var n int
	for _, f := range findings {
		if !certain(f.Doubts) {
			n++
		}
	}
	return n
}

// countsByKind renders the per-kind surface totals in a stable order.
func countsByKind(totals map[SymbolKind]int) string {
	order := []SymbolKind{KindFunc, KindType, KindMethod, KindVar, KindConst}
	parts := make([]string, 0, len(order))
	for _, k := range order {
		parts = append(parts, fmt.Sprintf("%s %d", k, totals[k]))
	}
	return strings.Join(parts, ", ")
}

// short trims the module prefix from an import path for readability.
func short(path string) string {
	if i := strings.Index(path, "/internal/"); i >= 0 {
		return path[i+1:]
	}
	return path
}
