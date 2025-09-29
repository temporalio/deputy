package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestGoDialectPipeline(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main

func main() {
	helper()
}

func helper() {}
`), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	target := &Target{
		Descriptor: TargetDescriptor{Kind: TargetKindRepository, Name: "fixture", Root: dir},
		FS:         os.DirFS(dir),
	}

	dialect := NewGoDialect()
	if !dialect.Supports(target) {
		t.Fatal("expected dialect to support target")
	}

	ctx := context.Background()
	units, err := dialect.DiscoverUnits(ctx, target)
	if err != nil {
		t.Fatalf("discover units: %v", err)
	}
	if len(units) != 1 {
		t.Fatalf("expected 1 unit, got %d", len(units))
	}
	unit := units[0]
	if err := dialect.Prepare(ctx, unit); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if len(unit.Tokens) == 0 {
		t.Fatal("expected tokens to be produced")
	}
	pkg, err := dialect.LowerToIR(ctx, unit)
	if err != nil {
		t.Fatalf("lower to IR: %v", err)
	}
	if len(pkg.Symbols) < 2 {
		t.Fatalf("expected at least 2 symbols, got %d", len(pkg.Symbols))
	}
	if len(pkg.Entrypoints) == 0 {
		t.Fatalf("expected entrypoints for main package")
	}

	symIDs := map[string]struct{}{}
	for _, sym := range pkg.Symbols {
		symIDs[sym.ID.String()] = struct{}{}
	}
	if _, ok := symIDs[SymbolID{Dialect: "go", Package: unit.Path, Name: "helper"}.String()]; !ok {
		t.Fatalf("expected helper symbol present")
	}
}

func TestEngineReachability(t *testing.T) {
	dir := t.TempDir()
	const source = `package main

func main() {
	helper()
}

func helper() {
	vulnerable()
}

func vulnerable() {}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	target := &Target{
		Descriptor: TargetDescriptor{Kind: TargetKindRepository, Name: "fixture", Root: dir},
		FS:         os.DirFS(dir),
	}

	dialect := NewGoDialect()
	symbols := NewSymbolRegistry()
	symbols.Register(SymbolHint{
		Vulnerability: "GO-TEST",
		Dialect:       "go",
		Package:       ".",
		Name:          "vulnerable",
		Kind:          SymbolKindFunction,
	})

	engine := NewEngine(WithDialect(dialect), WithSymbolRegistry(symbols))
	report, err := engine.AnalyzeReachability(context.Background(), target, []string{"GO-TEST"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected single finding, got %d", len(report.Findings))
	}
	finding := report.Findings[0]
	if !finding.Reachable {
		t.Fatalf("expected vulnerability reachable")
	}
	if len(finding.Path) < 2 {
		t.Fatalf("expected path to include at least entrypoint and target")
	}

	symbols.Register(SymbolHint{
		Vulnerability: "GO-TEST-UNREACHABLE",
		Dialect:       "go",
		Package:       ".",
		Name:          "ghost",
	})
	report, err = engine.AnalyzeReachability(context.Background(), target, []string{"GO-TEST-UNREACHABLE"})
	if err != nil {
		t.Fatalf("analyze second: %v", err)
	}
	if report.Findings[0].Reachable {
		t.Fatalf("expected ghost to be unreachable")
	}
}
