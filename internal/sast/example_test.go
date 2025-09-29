package sast

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// ExampleEngine_AnalyzeReachability demonstrates how to wire the engine with the
// Go dialect and evaluate a synthetic vulnerability symbol.
func ExampleEngine_AnalyzeReachability() {
	dir, _ := os.MkdirTemp("", "sast-example-*")
	defer os.RemoveAll(dir)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main

func main() {
	execute()
}

func execute() {
	sink()
}

func sink() {}
`), 0o644)

	target := &Target{
		Descriptor: TargetDescriptor{Kind: TargetKindRepository, Name: "example", Root: dir},
		FS:         os.DirFS(dir),
	}

	registry := NewSymbolRegistry()
	registry.Register(SymbolHint{
		Vulnerability: "GO-EXAMPLE",
		Dialect:       "go",
		Package:       ".",
		Name:          "sink",
	})

	engine := NewEngine(WithDialect(NewGoDialect()), WithSymbolRegistry(registry))
	report, _ := engine.AnalyzeReachability(context.Background(), target, []string{"GO-EXAMPLE"})
	fmt.Println(report.Findings[0].Reachable)
	// Output:
	// true
}
